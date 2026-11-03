//! `docspring exports download`: saves an account export. When a customer asks for a copy of their account's data,
//! DocSpring support exports it (an account migration) and sends an index file, account_migration_index_mig_....json.gz,
//! that links to the export's archives. This downloads and extracts each archive, as DocSpring/migration-fetcher's
//! migfetch.sh did (the format: app/models/account_migration.rb's index_data in the DocSpring app).

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use clap::Args;
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::errors::{describe, CliError};
use crate::output;
use crate::runner::{CommandResult, Runner};
use crate::session;

/// Download an account export from the index file DocSpring support sent you
///
/// Downloads every archive that the index file (account_migration_index_mig_....json.gz, or the .json inside it)
/// lists, and extracts them into one folder: --output, or a folder named after the export (mig_...) in the current
/// directory. Each archive's own index.json is saved in the export's indices/ folder. Run it again after an
/// interruption to download the rest: it skips the archives it already extracted, and downloads again any that arrived
/// damaged. The index file's links work for 48 hours after support made it.
#[derive(Debug, Args)]
pub struct DownloadArgs {
    /// The index file: account_migration_index_mig_....json.gz, or the .json inside it
    #[arg(value_name = "INDEX_FILE")]
    index: PathBuf,
    /// The folder to save the export in. Default: a folder named after the export (mig_...) in the current directory
    #[arg(long, short, value_name = "DIR")]
    output: Option<PathBuf>,
    /// Keep each archive (in the archives/ folder) after extracting it
    #[arg(long)]
    keep_archives: bool,
    /// Only download the archives (into the archives/ folder), without extracting them
    #[arg(long, conflicts_with = "keep_archives")]
    no_extract: bool,
}

/// The index file. Older exports may leave out any key but the batches, so the rest have defaults.
#[derive(Debug, Deserialize)]
struct Index {
    #[serde(default)]
    migration_type: Option<String>,
    batches: Vec<Batch>,
    #[serde(default)]
    total_size: Option<u64>,
    #[serde(default)]
    accounts_count: u64,
    #[serde(default)]
    templates_count: u64,
    #[serde(default)]
    submissions_count: u64,
    #[serde(default)]
    combined_submissions_count: u64,
}

#[derive(Debug, Deserialize)]
struct Batch {
    parts: Vec<String>,
}

/// One archive: its link and the name it's saved as
#[derive(Debug, PartialEq)]
struct Part {
    url: String,
    file_name: String,
}

/// The folders in an export that the command keeps for itself: an archive can't write to them
const RESERVED: [&str; 2] = ["archives", "indices"];

const EXPIRED: &str = "The export's links have expired: they work for 48 hours after DocSpring support made the index \
                       file. Ask support for a new one, then run this again with it to download the rest.";

pub async fn download(runner: &Runner, args: DownloadArgs) -> CommandResult {
    let index = read_index(&args.index)?;
    let parts = parts(&index)?;
    let dir = args.output.clone().unwrap_or_else(|| PathBuf::from(export_name(&args.index)));
    let archives = dir.join("archives");
    let indices = dir.join("indices");
    for folder in [&dir, &archives, &indices] {
        std::fs::create_dir_all(folder).map_err(|error| CliError::api(format!("Couldn't create {}: {error}", folder.display())))?;
    }
    runner.notice(&format!(
        "{} archive{}{} to download into {}",
        parts.len(),
        if parts.len() == 1 { "" } else { "s" },
        index.total_size.map(|size| format!(" ({})", human_size(size))).unwrap_or_default(),
        dir.display()
    ));
    let http = session::http_client()?;
    let (mut downloaded, mut skipped) = (0, 0);
    for (number, part) in parts.iter().enumerate() {
        let archive = archives.join(&part.file_name);
        let extracted = indices.join(index_name(&part.file_name));
        if (args.no_extract && archive.exists()) || (!args.no_extract && extracted.exists()) {
            skipped += 1;
            continue;
        }
        if !archive.exists() {
            runner.notice(&format!("Downloading {} of {}: {}", number + 1, parts.len(), part.file_name));
            fetch(&http, part, &archive).await?;
            downloaded += 1;
        }
        let index = check(&archive)?;
        if !args.no_extract {
            extract(&archive, &dir)?;
            crate::config::write_file(&extracted, &index, false)?;
            if !args.keep_archives {
                std::fs::remove_file(&archive).map_err(|error| CliError::api(format!("Couldn't delete {}: {error}", archive.display())))?;
            }
        }
    }
    // Only the archives the command kept are left in it
    if std::fs::read_dir(&archives).is_ok_and(|mut entries| entries.next().is_none()) {
        let _ = std::fs::remove_dir(&archives);
    }

    let summary = json!({
        "directory": dir,
        "migration_type": index.migration_type,
        "archives": parts.len(),
        "downloaded": downloaded,
        "skipped": skipped,
        "extracted": !args.no_extract,
        "accounts_count": index.accounts_count,
        "templates_count": index.templates_count,
        "submissions_count": index.submissions_count,
        "combined_submissions_count": index.combined_submissions_count,
    });
    if runner.global.json {
        runner.print(&summary, None);
    } else if !runner.global.quiet {
        let counts: Vec<String> = [
            (index.accounts_count, "account"),
            (index.templates_count, "template"),
            (index.submissions_count, "submission"),
            (index.combined_submissions_count, "combined PDF"),
        ]
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, name)| format!("{count} {name}{}", if *count == 1 { "" } else { "s" }))
        .collect();
        let contents = if counts.is_empty() {
            String::new()
        } else {
            format!(" ({})", counts.join(", "))
        };
        output::line(&format!("Saved the export{contents} in {}", dir.display()));
    }
    Ok(())
}

/// Reads the index file, gzipped (as support sends it) or not
fn read_index(path: &Path) -> Result<Index, CliError> {
    let bytes = std::fs::read(path).map_err(|error| CliError::usage(format!("Couldn't read {}: {error}", path.display())))?;
    let json = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_end(&mut json)
            .map_err(|error| CliError::usage(format!("Couldn't unzip {}: {error}", path.display())))?;
        json
    } else {
        bytes
    };
    serde_json::from_slice(&json).map_err(|error| {
        CliError::usage(format!(
            "{} isn't an account export's index file (account_migration_index_mig_....json.gz): {error}",
            path.display()
        ))
    })
}

fn parts(index: &Index) -> Result<Vec<Part>, CliError> {
    let urls: Vec<&String> = index.batches.iter().flat_map(|batch| &batch.parts).collect();
    if urls.is_empty() {
        return Err(CliError::usage("The index file lists no archives"));
    }
    urls.iter()
        .enumerate()
        .map(|(number, url)| {
            let parsed = url::Url::parse(url).map_err(|error| CliError::usage(format!("The index file has a bad link ({error}): {url}")))?;
            if !matches!(parsed.scheme(), "https" | "http") {
                return Err(CliError::usage(format!("The index file has a link that isn't a web address: {url}")));
            }
            Ok(Part {
                url: url.to_string(),
                file_name: file_name(&parsed, number),
            })
        })
        .collect()
}

/// The archive's own name, the link's last path segment (mbp_..._templates-acc_...-00000001-00001000.tar.gz), or
/// part-<n>.tar.gz for a link without a usable one
fn file_name(url: &url::Url, number: usize) -> String {
    // Still percent-encoded: a name with `%` in it isn't usable
    let name = url.path_segments().and_then(|mut segments| segments.next_back()).unwrap_or_default();
    let usable = name.ends_with(".tar.gz")
        && !name.starts_with('.')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character));
    if usable {
        name.to_owned()
    } else {
        format!("part-{:04}.tar.gz", number + 1)
    }
}

/// Where an archive's index.json is saved once it's extracted: indices/<archive name>.json
fn index_name(file_name: &str) -> String {
    format!("{}.json", file_name.trim_end_matches(".tar.gz"))
}

/// The folder an export is saved in by default: its ID (mig_...) from the index file's name
fn export_name(index: &Path) -> String {
    let name = index.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    match name.find("mig_") {
        Some(start) => name[start..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect(),
        None => "docspring-export".to_owned(),
    }
}

/// Streams an archive to disk: to <name>.part, renamed when it's complete, so an interrupted download is started again
async fn fetch(http: &reqwest::Client, part: &Part, path: &Path) -> Result<(), CliError> {
    let name = &part.file_name;
    let failed = |error: reqwest::Error| CliError::api(format!("Couldn't download {name}: {}", describe(&error)));
    let mut response = http.get(&part.url).send().await.map_err(failed)?;
    let status = response.status();
    // CloudFront and S3 refuse a signed link that has expired with 403
    if status.as_u16() == 403 {
        return Err(CliError::api(EXPIRED));
    }
    if !status.is_success() {
        return Err(CliError::api(format!("Downloading {name} failed: {status}")));
    }
    let expected = response.content_length();
    let partial = path.with_file_name(format!("{name}.part"));
    let write_failed = |error: std::io::Error| CliError::api(format!("Couldn't save {}: {error}", partial.display()));
    let mut file = tokio::fs::File::create(&partial).await.map_err(write_failed)?;
    let mut written: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        file.write_all(&chunk).await.map_err(write_failed)?;
        written += chunk.len() as u64;
    }
    file.flush().await.map_err(write_failed)?;
    drop(file);
    if expected.is_some_and(|expected| expected != written) {
        return Err(CliError::api(format!(
            "The download of {name} stopped early ({written} of {} bytes): run this again",
            expected.unwrap_or_default()
        )));
    }
    tokio::fs::rename(&partial, path)
        .await
        .map_err(|error| CliError::api(format!("Couldn't save {}: {error}", path.display())))
}

/// Reads a whole archive before anything in it is extracted, and returns its index.json. A damaged one (cut short,
/// changed on the way, or not an export's archive) is deleted, so the next run downloads it again.
fn check(archive: &Path) -> Result<Vec<u8>, CliError> {
    let name = archive.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let file = std::fs::File::open(archive).map_err(|error| CliError::api(format!("Couldn't read {}: {error}", archive.display())))?;
    read_archive(file).map_err(|problem| {
        // The error below says what went wrong; if the archive can't be deleted, the next run fails the same way
        let _ = std::fs::remove_file(archive);
        CliError::api(format!(
            "Couldn't extract {name}: {problem}. It was deleted: run this again to download it again"
        ))
    })
}

/// Reads every entry of an archive, then the rest of the gzip stream, whose footer has the checksum of everything in
/// it. Returns the archive's index.json, or what's wrong with it.
fn read_archive(file: impl Read) -> Result<Vec<u8>, String> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut index = None;
    for entry in tar.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path().map_err(|error| error.to_string())?.into_owned();
        if let Some(folder) = reserved_folder(&path) {
            return Err(format!(
                "it has {}, in the {folder}/ folder that this command keeps for itself",
                path.display()
            ));
        }
        if entry.header().entry_type().is_file() && is_index(&path) {
            let mut json = Vec::new();
            entry.read_to_end(&mut json).map_err(|error| error.to_string())?;
            index = Some(json);
        } else {
            std::io::copy(&mut entry, &mut std::io::sink()).map_err(|error| error.to_string())?;
        }
    }
    // The entries stop at the first of the two empty blocks that end a tar file. Without the second, the archive was
    // cut short where one file ended (a gzip of a tar that was stopped part way is still a valid gzip). Reading to the
    // end also checks the gzip footer.
    let rest = std::io::copy(&mut tar.into_inner(), &mut std::io::sink()).map_err(|error| error.to_string())?;
    if rest < 512 {
        return Err("it ends part way through".to_owned());
    }
    index.ok_or_else(|| "it has no index.json, so it isn't an account export's archive".to_owned())
}

/// Extracts a checked archive into the export's folder, all but its index.json. The archive was read in full, so an
/// error here is the disk's, and the archive is kept for the next run.
fn extract(archive: &Path, dir: &Path) -> Result<(), CliError> {
    let name = archive.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let failed = |error: std::io::Error| CliError::api(format!("Couldn't extract {name}: {error}"));
    let file = std::fs::File::open(archive).map_err(failed)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    tar.set_preserve_permissions(false);
    tar.set_overwrite(true);
    for entry in tar.entries().map_err(failed)? {
        let mut entry = entry.map_err(failed)?;
        // Only files and folders: an export has nothing else, and a link could point outside the folder
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) || is_index(&entry.path().map_err(failed)?) {
            continue;
        }
        // unpack_in skips a path that would leave the folder (`..`)
        entry.unpack_in(dir).map_err(failed)?;
    }
    Ok(())
}

/// An entry's path as tar's unpack_in writes it, inside the export's folder: without `.`, a leading `/` or a drive
fn inside(path: &Path) -> impl Iterator<Item = Component<'_>> {
    path.components()
        .filter(|part| !matches!(part, Component::CurDir | Component::RootDir | Component::Prefix(_)))
}

fn is_index(path: &Path) -> bool {
    inside(path).eq([Component::Normal("index.json".as_ref())])
}

/// The folder that an entry would write into if it's one the command keeps for itself. macOS and Windows ignore case,
/// and Windows drops trailing dots and spaces from a folder's name.
fn reserved_folder(path: &Path) -> Option<&'static str> {
    let Some(Component::Normal(first)) = inside(path).next() else {
        return None;
    };
    let first = first.to_string_lossy();
    let first = first.trim_end_matches(['.', ' ']);
    RESERVED.into_iter().find(|folder| first.eq_ignore_ascii_case(folder))
}

fn human_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} bytes"),
        1024..1_048_576 => format!("{:.0} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archives_are_named_after_their_links() {
        let url = |text: &str| url::Url::parse(text).unwrap();
        assert_eq!(
            file_name(
                &url("https://downloads.docspring.com/account_migrations/mig_1/mgb_1-templates-acc_1/mbp_1-templates-acc_1-00000001-00001000.tar.gz?Expires=1&Signature=x"),
                0
            ),
            "mbp_1-templates-acc_1-00000001-00001000.tar.gz"
        );
        // Nothing that could leave the folder, and nothing that isn't an archive
        assert_eq!(file_name(&url("https://example.com/a/..%2F..%2Fevil.tar.gz"), 1), "part-0002.tar.gz");
        assert_eq!(file_name(&url("https://example.com/download?id=1"), 2), "part-0003.tar.gz");
        assert_eq!(index_name("mbp_1-templates.tar.gz"), "mbp_1-templates.json");
    }

    /// An archive as the app makes it, from (path, contents) pairs. The names go in as they are: the tar crate's own
    /// set_path refuses the absolute ones an archive from elsewhere could have.
    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        gzip(&tar_file(files))
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_file(files: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, contents.as_bytes()).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn an_archive_is_read_in_full_before_it_is_extracted() {
        let good = archive(&[("./index.json", "{}"), ("./acc_1/templates/tpl_1.json", "{\"id\":\"tpl_1\"}")]);
        assert_eq!(read_archive(good.as_slice()), Ok(b"{}".to_vec()));

        // The gzip footer's checksum doesn't match: the entries read fine, so only reading to the end finds it
        let mut changed = good.clone();
        let checksum = changed.len() - 8;
        changed[checksum] ^= 0xff;
        let problem = read_archive(changed.as_slice()).unwrap_err();
        assert!(problem.contains("checksum"), "{problem}");

        for cut in [good.len() / 2, good.len() - 4] {
            assert!(read_archive(&good[..cut]).is_err(), "cut at {cut} of {}", good.len());
        }
        // Stopped where the first file ends (a header and a block of contents), then gzipped in full
        let stopped = gzip(&tar_file(&[("./index.json", "{}"), ("./acc_1/a.json", "{}")])[..1024]);
        assert_eq!(read_archive(stopped.as_slice()), Err("it ends part way through".to_owned()));
        assert_eq!(
            read_archive(archive(&[("./acc_1/a.json", "{}")]).as_slice()),
            Err("it has no index.json, so it isn't an account export's archive".to_owned())
        );
    }

    #[test]
    fn an_archive_cant_write_to_the_folders_the_command_keeps() {
        for path in [
            "./indices/part2.json",
            "indices/x",
            "/indices/x",
            "./Indices/x",
            "ARCHIVES/x.tar.gz",
            "./indices./x",
        ] {
            let problem = read_archive(archive(&[("./index.json", "{}"), (path, "{}")]).as_slice()).unwrap_err();
            assert!(problem.contains("folder that this command keeps for itself"), "{path}: {problem}");
        }
        for path in ["./acc_1/indices/x", "./indices.json", "./archive/x"] {
            assert!(
                read_archive(archive(&[("./index.json", "{}"), (path, "{}")]).as_slice()).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn an_export_is_saved_in_a_folder_named_after_it() {
        assert_eq!(
            export_name(Path::new("Downloads/account_migration_index_mig_AbC123.json.gz")),
            "mig_AbC123"
        );
        assert_eq!(export_name(Path::new("index.json")), "docspring-export");
    }
}
