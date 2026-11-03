//! `docspring submit` and `docspring submissions download`: filling in a template and saving its files.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use docspring::models::{GeneratedFile, GeneratedFileState, OutputFormat, Submission, SubmissionFiles, SubmissionState};
use docspring::Api;
use sha2::Digest;

use crate::errors::{describe, CliError};
use crate::runner::{read_json, CommandResult, Runner};
use crate::session::{self, Auth};

/// Fill in a template and save its PDF or Word document
///
/// Creates a submission, waits until its file has been made (up to --timeout), and saves it: the PDF, or the Word document of a Word
/// template that makes one (--format picks the file). --data is the same as for `submissions create`: the
/// submission's data and settings, such as {"data": {"name": "Jane"}}. Prints the saved file's path (with --json, the
/// submission). For signature requests, use `submissions create`: their PDF is made once everyone has signed.
#[derive(Debug, Args)]
pub struct SubmitArgs {
    /// The template's ID
    template_id: String,
    /// The submission's data and settings, as JSON: the JSON itself, @ and a file name to read a file (@data.json),
    /// or - to read standard input
    #[arg(long, value_name = "JSON")]
    data: String,
    /// Make a test submission (free, with a watermark)
    #[arg(long)]
    test: bool,
    /// The template version to use: a published version (1.2.0, or 1 for the latest 1.x.x), latest or draft
    #[arg(long)]
    version: Option<String>,
    /// The file to save: pdf, or a Word template's docx (Word document) or odt (OpenDocument file). The submission
    /// makes it. Default: the PDF, or what a Word template makes instead
    #[arg(long, value_enum, value_name = "FORMAT")]
    format: Option<Document>,
    /// Where to save the file: a file, a directory (one ending in / is made if it doesn't exist), or - for standard
    /// output. Default: the file's name (such as sub_123.pdf) in the current directory.
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// How long to wait for the file, in seconds
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    timeout: u64,
    /// A key of your own, such as a UUID, sent as the submission's Idempotency-Key: for 24 hours, submit with the same
    /// key and the same template and --data saves the first submission's file instead of making another. Default: a
    /// new key each time submit runs
    #[arg(long, value_name = "KEY")]
    idempotency_key: Option<String>,
}

/// A document a submission makes: a PDF, or a Word template's Word document or OpenDocument file
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Document {
    Pdf,
    Docx,
    Odt,
}

impl Document {
    fn output_format(self) -> OutputFormat {
        match self {
            Document::Pdf => OutputFormat::Pdf,
            Document::Docx => OutputFormat::Docx,
            Document::Odt => OutputFormat::Odt,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Document::Pdf => "PDF",
            Document::Docx => "Word document",
            Document::Odt => "OpenDocument file",
        }
    }

    fn file(self, files: &SubmissionFiles) -> Option<&GeneratedFile> {
        match self {
            Document::Pdf => files.pdf.as_ref(),
            Document::Docx => files.docx.as_ref(),
            Document::Odt => files.odt.as_ref(),
        }
    }

    /// The document `submit` saves without --format: the PDF when the submission makes one (png pages make it too),
    /// otherwise the Word document or OpenDocument file a Word template makes
    fn default_for(output_formats: &[OutputFormat]) -> Document {
        [Document::Pdf, Document::Docx, Document::Odt]
            .into_iter()
            .find(|document| output_formats.contains(&document.output_format()))
            .unwrap_or(Document::Pdf)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum FileKind {
    Pdf,
    Docx,
    Odt,
    AuditTrail,
    Preview,
}

/// Save a submission's PDF, Word document, audit trail or preview
///
/// Prints the saved file's path (with --json, the file's details from the API).
#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// The submission's ID
    submission_id: String,
    /// Which file to save
    #[arg(long, value_enum, default_value_t = FileKind::Pdf)]
    file: FileKind,
    /// Where to save it: a file, a directory (one ending in / is made if it doesn't exist), or - for standard output.
    /// Default: the file's name (such as sub_123.pdf) in the current directory.
    #[arg(long, short)]
    output: Option<PathBuf>,
}

pub async fn submit(runner: &Runner, args: SubmitArgs) -> CommandResult {
    let mut value = read_json(&args.data)?;
    // A submission with signature requests makes its PDF only once everyone has signed, so submit would create it,
    // email the signers and then fail, and a script that ran it again would email them again
    if value
        .get("signature_requests")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|requests| !requests.is_empty())
    {
        return Err(CliError::usage(
            "submit saves the PDF, which a submission with signature requests makes only once everyone has signed. \
             Create it with `docspring submissions create`, then save the PDF with `docspring submissions download` \
             once the signature requests are completed.",
        ));
    }
    if args.test || args.format.is_some() {
        let Some(body) = value.as_object_mut() else {
            return Err(CliError::usage("--data must be a JSON object, such as {\"data\": {...}}"));
        };
        if args.test {
            body.insert("test".to_owned(), serde_json::Value::Bool(true));
        }
        if let Some(format) = args.format {
            request_format(body, format)?;
        }
    }
    let body = runner.body_from_value("createSubmission", value)?;
    let session = runner.session().await?;
    let params = docspring::CreateSubmissionParams {
        template_id: args.template_id,
        body,
        version: args.version,
        // Polled below instead, so --timeout bounds the wait: the sync host would hold the request for up to 5 minutes
        wait: Some(false),
        idempotency_key: Some(args.idempotency_key.unwrap_or_else(|| process_idempotency_key().to_owned())),
    };
    let submission = session.client.create_submission(params).await.map_err(CliError::from_sdk)?;
    let document = args.format.unwrap_or_else(|| Document::default_for(&submission.output_formats));
    let submission = wait_for_file(runner, submission, document, Duration::from_secs(args.timeout)).await?;
    let file = document.file(&submission.files).cloned().ok_or_else(|| {
        CliError::api(format!(
            "Submission {} has no {}: its output_formats leave it out",
            submission.id,
            document.name()
        ))
    })?;
    let path = save(session, &file, args.output.as_deref()).await?;
    finish(runner, &serde_json::to_value(&submission).expect("submissions serialize"), &file, path)
}

/// The Idempotency-Key submit sends without --idempotency-key, the same for the whole process: when another command
/// refreshes the login while this one runs, main runs the command again, and its create gets the first submission back
fn process_idempotency_key() -> &'static str {
    static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("the OS has a random number generator");
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    })
}

/// Makes sure the submission makes the document --format asks for: it's the submission's only output format unless
/// --data lists them, and then it must be one of them
fn request_format(body: &mut serde_json::Map<String, serde_json::Value>, format: Document) -> Result<(), CliError> {
    let name = format.output_format().as_str().to_owned();
    match body.get("output_formats") {
        None => {
            body.insert("output_formats".to_owned(), serde_json::json!([name]));
            Ok(())
        }
        Some(serde_json::Value::Array(formats)) if formats.iter().any(|value| value.as_str() == Some(&name)) => Ok(()),
        Some(_) => Err(CliError::usage(format!(
            "--format {name} isn't one of --data's output_formats: add it, or leave out --format"
        ))),
    }
}

pub async fn download(runner: &Runner, args: DownloadArgs) -> CommandResult {
    let session = runner.session().await?;
    let params = docspring::GetSubmissionParams {
        submission_id: args.submission_id,
    };
    let submission = session.client.get_submission(params).await.map_err(CliError::from_sdk)?;
    let (file, name) = match args.file {
        FileKind::Pdf => (submission.files.pdf.clone(), "PDF"),
        FileKind::Docx => (submission.files.docx.clone(), "Word document"),
        FileKind::Odt => (submission.files.odt.clone(), "OpenDocument file"),
        FileKind::AuditTrail => (submission.files.audit_trail.clone(), "audit trail"),
        FileKind::Preview => (submission.files.preview.clone(), "preview"),
    };
    // A file the API lists can be saved whatever state the submission is in: the preview, for one, is made before the
    // signature requests are completed. Without it, the submission's state says why.
    let file = match file {
        Some(file) if !submission.expired => file,
        _ => {
            if let Some(error) = no_files(&submission, name) {
                return Err(error);
            }
            if submission.state == SubmissionState::Pending {
                return Err(CliError::api(format!(
                    "Submission {}'s files aren't ready yet: run this again in a few seconds",
                    submission.id
                )));
            }
            return Err(CliError::api(format!("Submission {} has no {name}", submission.id)));
        }
    };
    let path = save(session, &file, args.output.as_deref()).await?;
    finish(runner, &serde_json::to_value(&file).expect("files serialize"), &file, path)
}

/// Prints the saved file's path, or the JSON, and says what was saved on stderr
fn finish(runner: &Runner, json: &serde_json::Value, file: &GeneratedFile, path: Option<PathBuf>) -> CommandResult {
    let Some(path) = path else {
        // Written to standard output: nothing else can go there
        return Ok(());
    };
    let size = file.size.map(|size| format!(" ({})", human_size(size as u64))).unwrap_or_default();
    runner.notice(&format!("Saved {}{size}", path.display()));
    if runner.global.json {
        runner.print(json, None);
    } else if !runner.global.quiet {
        crate::output::line(&path.display().to_string());
    }
    Ok(())
}

/// Waits until the submission's document has been made. The sync API usually responds once it has; one that takes
/// longer comes back pending, and this polls for it.
async fn wait_for_file(runner: &Runner, mut submission: Submission, document: Document, timeout: Duration) -> Result<Submission, CliError> {
    let started = Instant::now();
    let mut delay = Duration::from_millis(500);
    loop {
        if submission.state != SubmissionState::Pending {
            if let Some(error) = no_files(&submission, document.name()) {
                return Err(error);
            }
            let ready = document
                .file(&submission.files)
                .is_none_or(|file| file.state != GeneratedFileState::Pending);
            if ready {
                return Ok(submission);
            }
        }
        if started.elapsed() + delay > timeout {
            return Err(not_ready(&submission.id, document, timeout));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(3));
        let params = docspring::GetSubmissionParams {
            submission_id: submission.id.clone(),
        };
        // The check gets only the time that's left: the HTTP client limits how long a connection takes, not a response
        let check = async { runner.client().await?.get_submission(params).await.map_err(CliError::from_sdk) };
        submission = match tokio::time::timeout(timeout.saturating_sub(started.elapsed()), check).await {
            Ok(checked) => checked?,
            Err(_) => return Err(not_ready(&submission.id, document, timeout)),
        };
    }
}

fn not_ready(id: &str, document: Document, timeout: Duration) -> CliError {
    let file_option = match document {
        Document::Pdf => String::new(),
        _ => format!(" --file {}", document.output_format().as_str()),
    };
    CliError::api(format!(
        "Submission {id}'s {} wasn't ready after {} seconds. `docspring submissions download {id}{file_option}` saves it \
         once it is.",
        document.name(),
        timeout.as_secs(),
    ))
}

/// Why a submission has no files to save, from its state and error_message: None while it's pending or once it's
/// processed. Only a processed submission has files.
fn no_files(submission: &Submission, name: &str) -> Option<CliError> {
    let id = &submission.id;
    let because = |text: String| match submission.error_message.as_deref().map(str::trim).filter(|message| !message.is_empty()) {
        Some(message) => format!("{text}: {message}"),
        None => text,
    };
    let message = match &submission.state {
        _ if submission.expired => format!("Submission {id} has expired, so its files were deleted"),
        SubmissionState::Pending | SubmissionState::Processed => return None,
        SubmissionState::WaitingForSignatureRequests => format!(
            "Submission {id} is waiting for its signature requests. `docspring submissions download {id}` saves its {name} \
             once they're all completed."
        ),
        SubmissionState::InsufficientCredits => because(format!("Submission {id} is waiting for credits")),
        SubmissionState::AccountSuspended => because(format!("Submission {id} is waiting for the account to be reactivated")),
        SubmissionState::InvalidData => {
            let errors: Vec<&str> = submission.data_errors.iter().map(|error| error.message.as_str()).collect();
            let text = format!("Submission {id}'s data doesn't match the template's fields");
            if errors.is_empty() {
                text
            } else {
                format!("{text}: {}", errors.join("; "))
            }
        }
        SubmissionState::Declined => format!("Submission {id} has no {name}: a signature request was declined"),
        SubmissionState::Error | SubmissionState::SyntaxError | SubmissionState::ImageDownloadFailed | SubmissionState::ImageProcessingFailed => {
            let message = submission.error_message.as_deref().filter(|message| !message.trim().is_empty());
            format!(
                "Submission {id} failed ({}): {}",
                submission.state.as_str(),
                message.unwrap_or("DocSpring couldn't make its files")
            )
        }
        state => because(format!("Submission {id} is {} and has no {name}", state.as_str())),
    };
    Some(CliError::api(message))
}

/// Saves a generated file and returns where (None for standard output). The temporary download link is signed, so it
/// gets no credentials; without one (an account can turn them off), the permanent link takes the API token or login.
async fn save(session: &session::Session, file: &GeneratedFile, output: Option<&Path>) -> Result<Option<PathBuf>, CliError> {
    match &file.state {
        GeneratedFileState::Processed => {}
        GeneratedFileState::Error => {
            return Err(CliError::api(format!(
                "{} couldn't be made: {}",
                file.filename,
                file.error_message.as_deref().unwrap_or("no reason given")
            )))
        }
        state => return Err(CliError::api(format!("{} isn't ready yet ({})", file.filename, state.as_str()))),
    }
    let http = session::http_client()?;
    let (request, with_credentials) = match (&file.download_url, &file.permanent_url) {
        (Some(url), _) => (http.get(url), false),
        (None, Some(url)) => match &session.auth {
            Auth::Basic { token_id, token_secret } => (http.get(url).basic_auth(token_id, Some(token_secret)), true),
            Auth::Bearer(token) => (http.get(url).bearer_auth(token), true),
        },
        (None, None) => return Err(CliError::api(format!("{} has no download link", file.filename))),
    };
    let response = request
        .send()
        .await
        .map_err(|error| CliError::api(format!("Couldn't download {}: {}", file.filename, describe(&error))))?;
    let status = response.status();
    // The permanent link refused the credentials: an authentication error, like the API's, so the command runs again
    // when another command has refreshed the login (main), and exits with the authentication status otherwise
    if with_credentials && matches!(status.as_u16(), 401 | 403) {
        let mut message = format!("Downloading {} failed: {status}", file.filename);
        if status.as_u16() == 401 {
            message.push_str(
                "\nCheck the API token, or run `docspring login` again (`docspring auth status` shows which credentials \
                 commands use).",
            );
        }
        return Err(CliError::auth(message));
    }
    if !status.is_success() {
        return Err(CliError::api(format!("Downloading {} failed: {status}", file.filename)));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| CliError::api(format!("Couldn't download {}: {}", file.filename, describe(&error))))?;
    check_download(file, &bytes)?;
    if output == Some(Path::new("-")) {
        crate::output::text(&bytes);
        return Ok(None);
    }
    let path = output_path(output, &file.filename);
    crate::config::write_file(&path, &bytes, false)?;
    Ok(Some(path))
}

/// Checks a download against the size and SHA-256 hash the API lists for the file. The API has no hash for a few older
/// files (audit trails made before September 2024), which are checked by size.
fn check_download(file: &GeneratedFile, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(expected) = file.size {
        if bytes.len() as u64 != expected as u64 {
            return Err(CliError::api(format!(
                "The downloaded {} is {} bytes, not {expected}: try again",
                file.filename,
                bytes.len()
            )));
        }
    }
    if let Some(expected) = &file.sha256 {
        let actual = format!("{:x}", sha2::Sha256::digest(bytes));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(CliError::api(format!(
                "The downloaded {} doesn't match its SHA-256 hash ({actual}, not {expected}): try again",
                file.filename
            )));
        }
    }
    Ok(())
}

/// The output path for a file: the one given, inside it when it's a directory, or the file's own name
fn output_path(output: Option<&Path>, filename: &str) -> PathBuf {
    // The API's file names are plain names, but a path in one mustn't write outside the directory
    let name = Path::new(filename)
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("download.pdf"));
    match output {
        // A path that ends in a separator is a directory, made when it doesn't exist yet
        Some(path) if path.is_dir() || ends_with_separator(path) => path.join(name),
        Some(path) => path.to_owned(),
        None => name,
    }
}

fn ends_with_separator(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path.ends_with('/') || path.ends_with(std::path::MAIN_SEPARATOR)
}

fn human_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} bytes"),
        1024..1_048_576 => format!("{:.0} KB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_saved_by_name_or_where_you_say() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(output_path(None, "sub_1.pdf"), PathBuf::from("sub_1.pdf"));
        assert_eq!(output_path(Some(dir.path()), "sub_1.pdf"), dir.path().join("sub_1.pdf"));
        assert_eq!(output_path(Some(Path::new("out/x.pdf")), "sub_1.pdf"), PathBuf::from("out/x.pdf"));
        assert_eq!(output_path(None, "../../etc/sub_1.pdf"), PathBuf::from("sub_1.pdf"));
        assert_eq!(
            output_path(Some(Path::new("not_made_yet/")), "sub_1.pdf"),
            PathBuf::from("not_made_yet/sub_1.pdf")
        );
    }

    #[test]
    fn submit_saves_the_pdf_or_what_a_word_template_makes() {
        assert_eq!(Document::default_for(&[OutputFormat::Pdf]), Document::Pdf);
        assert_eq!(Document::default_for(&[OutputFormat::Png]), Document::Pdf);
        assert_eq!(Document::default_for(&[OutputFormat::Docx]), Document::Docx);
        assert_eq!(Document::default_for(&[OutputFormat::Odt]), Document::Odt);
        assert_eq!(Document::default_for(&[OutputFormat::Docx, OutputFormat::Pdf]), Document::Pdf);
    }

    #[test]
    fn format_is_requested_unless_output_formats_leave_it_out() {
        let body = |value: serde_json::Value| value.as_object().unwrap().clone();

        let mut data = body(serde_json::json!({ "data": {} }));
        request_format(&mut data, Document::Docx).unwrap();
        assert_eq!(data["output_formats"], serde_json::json!(["docx"]));

        let mut data = body(serde_json::json!({ "output_formats": ["docx", "pdf"] }));
        request_format(&mut data, Document::Pdf).unwrap();
        assert_eq!(data["output_formats"], serde_json::json!(["docx", "pdf"]));

        let mut data = body(serde_json::json!({ "output_formats": ["pdf"] }));
        let error = request_format(&mut data, Document::Odt).unwrap_err();
        assert_eq!(
            error.message,
            "--format odt isn't one of --data's output_formats: add it, or leave out --format"
        );
    }

    #[test]
    fn each_submission_state_says_why_there_are_no_files() {
        let submission = |state: SubmissionState, error_message: Option<&str>| Submission {
            id: "sub_1".to_owned(),
            state,
            error_message: error_message.map(str::to_owned),
            ..Default::default()
        };
        let message = |submission: Submission| no_files(&submission, "PDF").map(|error| error.message);

        assert_eq!(message(submission(SubmissionState::Pending, None)), None);
        assert_eq!(message(submission(SubmissionState::Processed, None)), None);
        assert_eq!(
            message(submission(SubmissionState::SyntaxError, Some("Liquid syntax error: line 3"))).unwrap(),
            "Submission sub_1 failed (syntax_error): Liquid syntax error: line 3"
        );
        assert_eq!(
            message(submission(SubmissionState::Error, None)).unwrap(),
            "Submission sub_1 failed (error): DocSpring couldn't make its files"
        );
        assert_eq!(
            message(submission(SubmissionState::WaitingForSignatureRequests, None)).unwrap(),
            "Submission sub_1 is waiting for its signature requests. `docspring submissions download sub_1` saves its PDF \
             once they're all completed."
        );
        assert_eq!(
            message(submission(SubmissionState::InsufficientCredits, Some("Add credits to generate it."))).unwrap(),
            "Submission sub_1 is waiting for credits: Add credits to generate it."
        );
        assert_eq!(
            message(submission(SubmissionState::Declined, None)).unwrap(),
            "Submission sub_1 has no PDF: a signature request was declined"
        );
        let mut invalid = submission(SubmissionState::InvalidData, None);
        invalid.data_errors = vec![docspring::models::ErrorDetail {
            code: "required".to_owned(),
            message: "name is required".to_owned(),
            ..Default::default()
        }];
        assert_eq!(
            message(invalid).unwrap(),
            "Submission sub_1's data doesn't match the template's fields: name is required"
        );
        assert_eq!(
            message(submission(SubmissionState::Unknown("on_hold".to_owned()), Some("Waiting for review"))).unwrap(),
            "Submission sub_1 is on_hold and has no PDF: Waiting for review"
        );
        let mut expired = submission(SubmissionState::Processed, None);
        expired.expired = true;
        assert_eq!(message(expired).unwrap(), "Submission sub_1 has expired, so its files were deleted");
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(52_000), "51 KB");
        assert_eq!(human_size(3_500_000), "3.3 MB");
    }
}
