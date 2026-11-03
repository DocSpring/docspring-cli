//! Commands run as the binary, against a stand-in for the API on 127.0.0.1: what happens between the requests (a slow
//! response, another command refreshing the login, two logins at once) that unit tests can't reach.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::Digest;

const PDF: &[u8] = b"%PDF-1.7\nnot a real PDF\n";

struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

impl Reply {
    fn json(status: u16, value: Value) -> Reply {
        Reply {
            status,
            body: value.to_string().into_bytes(),
        }
    }

    fn pdf() -> Reply {
        Reply {
            status: 200,
            body: PDF.to_vec(),
        }
    }
}

/// Each request's method, path and Authorization header
type RequestLog = Mutex<Vec<(String, String, Option<String>)>>;

/// Answers a request, given the server's address (for the file links in a submission)
type Handler = dyn Fn(&Request, &str) -> Reply + Send + Sync;

/// An HTTP server that answers each request with the handler's reply, one connection per request
struct Server {
    url: String,
    requests: Arc<RequestLog>,
}

impl Server {
    fn start(handler: impl Fn(&Request, &str) -> Reply + Send + Sync + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a port for the test server");
        let url = format!("http://{}", listener.local_addr().expect("the test server's address"));
        let handler: Arc<Handler> = Arc::new(handler);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (log, base) = (requests.clone(), url.clone());
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (handler, log, base) = (handler.clone(), log.clone(), base.clone());
                thread::spawn(move || serve(stream, &*handler, &log, &base));
            }
        });
        Server { url, requests }
    }

    fn requests(&self) -> Vec<(String, String, Option<String>)> {
        self.requests.lock().expect("the request log").clone()
    }
}

fn serve(mut stream: TcpStream, handler: &Handler, log: &RequestLog, base: &str) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone the test server's connection"));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut words = line.split_whitespace();
    let (method, path) = (words.next().unwrap_or_default().to_owned(), words.next().unwrap_or_default().to_owned());
    let (mut length, mut authorization) = (0, None);
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().expect("a numeric Content-Length"),
                "authorization" => authorization = Some(value.trim().to_owned()),
                _ => {}
            }
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("the request's body");
    log.lock()
        .expect("the request log")
        .push((method.clone(), path.clone(), authorization.clone()));
    let reply = handler(&Request { method, path, authorization }, base);
    let content_type = if reply.body.starts_with(b"{") {
        "application/json"
    } else {
        "application/pdf"
    };
    let head = format!(
        "HTTP/1.1 {} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.body.len()
    );
    // The CLI may have stopped waiting
    let _ = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(&reply.body));
}

/// A submission as the API returns it, with one file (none while it's pending)
fn submission(state: &str, base: &str, file_key: &str, permanent_only: bool) -> Value {
    let file = json!({
        "state": "processed",
        "error_message": null,
        "download_url": if permanent_only { Value::Null } else { json!(format!("{base}/file")) },
        "permanent_url": format!("{base}/file"),
        "filename": "sub_test.pdf",
        "content_type": "application/pdf",
        "size": PDF.len(),
        "sha256": format!("{:x}", sha2::Sha256::digest(PDF)),
    });
    let mut files = serde_json::Map::new();
    if state != "pending" {
        files.insert(file_key.to_owned(), file);
    }
    json!({
        "id": "sub_test", "template_id": "tpl_test", "template_type": "pdf", "template_version": null, "batch_id": null,
        "source": "api", "state": state, "test": true, "editable": false, "data": {}, "data_errors": [],
        "error_message": null, "metadata": {}, "files": files, "expired": false, "expires_at": null,
        "processed_at": null, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
        "has_password": false, "signature_requests": [], "signing_order": "parallel", "actions": [],
        "truncated_text": {}, "output_formats": ["pdf"], "preview_generated_at": null,
    })
}

/// The CLI with only this test's config directory and credentials
fn docspring(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_docspring"));
    for (name, _) in std::env::vars() {
        if name.starts_with("DOCSPRING_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(dir)
        .env("DOCSPRING_CONFIG_DIR", dir.join("config"))
        .env("DOCSPRING_CREDENTIAL_STORE", "file");
    command
}

fn with_token(command: &mut Command, server: &Server) -> Output {
    command
        .env("DOCSPRING_TOKEN_ID", "api_test")
        .env("DOCSPRING_TOKEN_SECRET", "secret")
        .env("DOCSPRING_HOST", &server.url)
        .output()
        .expect("run docspring")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A saved login for profile default, as another command's refresh leaves it
fn save_login(config: &Path, access_token: &str) {
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).expect("the clock").as_secs() + 3600;
    std::fs::write(
        config.join("credentials.toml"),
        format!(
            "[profiles.default]\nkind = \"login\"\naccess_token = \"{access_token}\"\nrefresh_token = \"refresh\"\n\
             expires_at = {expires_at}\n"
        ),
    )
    .expect("write credentials.toml");
}

#[test]
fn a_preview_downloads_while_the_signature_requests_are_still_open() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = Server::start(|request, base| match request.path.as_str() {
        "/file" => Reply::pdf(),
        _ => Reply::json(200, submission("waiting_for_signature_requests", base, "preview", false)),
    });
    let output = with_token(
        docspring(dir.path()).args(["submissions", "download", "sub_test", "--file", "preview", "-o", "preview.pdf"]),
        &server,
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(dir.path().join("preview.pdf")).expect("the saved preview"), PDF);
}

#[test]
fn submit_stops_waiting_at_its_timeout_even_while_a_request_hangs() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = Server::start(|request, base| {
        if request.method == "GET" {
            // A status check that takes far longer than --timeout
            thread::sleep(Duration::from_secs(10));
        }
        Reply::json(
            if request.method == "POST" { 201 } else { 200 },
            submission("pending", base, "pdf", false),
        )
    });
    let started = Instant::now();
    let output = with_token(
        docspring(dir.path()).args(["submit", "tpl_test", "--data", r#"{"data": {}}"#, "--timeout", "1"]),
        &server,
    );
    let elapsed = started.elapsed();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("wasn't ready after 1 seconds"), "{}", stderr(&output));
    assert!(elapsed < Duration::from_secs(3), "submit --timeout 1 took {elapsed:?}");
}

#[test]
fn submit_refuses_signature_requests_before_it_creates_the_submission() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = Server::start(|_, base| Reply::json(201, submission("waiting_for_signature_requests", base, "pdf", false)));
    let data = r#"{"data": {}, "signature_requests": [{"email": "signer@example.com", "name": "Signer", "fields": ["signature"]}]}"#;
    let output = with_token(docspring(dir.path()).args(["submit", "tpl_test", "--data", data]), &server);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("docspring submissions create"), "{}", stderr(&output));
    // Creating it would email the signers, and running submit again would email them again
    assert!(server.requests().is_empty(), "{:?}", server.requests());

    let output = with_token(
        docspring(dir.path()).args([
            "submit",
            "tpl_test",
            "--data",
            r#"{"data": {}, "signature_requests": []}"#,
            "--timeout",
            "1",
        ]),
        &server,
    );
    assert!(
        !server.requests().is_empty(),
        "an empty list is no signature requests: {}",
        stderr(&output)
    );
}

#[test]
fn auth_status_says_commands_fail_with_half_an_api_token() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let output = docspring(dir.path())
        .args(["auth", "status", "--json"])
        .env("DOCSPRING_TOKEN_ID", "api_test_1")
        .output()
        .expect("run docspring");
    assert!(output.status.success(), "{}", stderr(&output));
    let status: Value = serde_json::from_slice(&output.stdout).expect("auth status --json prints JSON");
    assert_eq!(status["used"]["source"], "env");
    assert!(
        status["used"]["error"]
            .as_str()
            .is_some_and(|error| error.contains("DOCSPRING_TOKEN_SECRET")),
        "{status}"
    );
}

#[test]
fn model_code_check_has_its_own_status_for_an_out_of_date_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = Server::start(|_, _| {
        Reply::json(
            200,
            json!({ "lang": "typescript", "root_type_name": "Data", "code": "export interface Data {}" }),
        )
    });
    let check = |file: &str| {
        with_token(
            docspring(dir.path()).args(["templates", "model-code", "tpl_test", "--lang", "typescript", "-o", file, "--check"]),
            &server,
        )
    };
    std::fs::write(dir.path().join("current.ts"), "export interface Data {}\n").expect("write current.ts");
    std::fs::write(dir.path().join("stale.ts"), "export interface Data { name: string }\n").expect("write stale.ts");
    assert!(check("current.ts").status.success());
    // CI can tell an out-of-date file (5) from a request that failed (1)
    let output = check("stale.ts");
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    assert!(stderr(&output).contains("isn't the template's current model code"), "{}", stderr(&output));
}

#[test]
fn all_follows_next_cursor_and_prints_every_page_as_one_list() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let folder = |id: &str| {
        json!({ "id": id, "name": id, "path": format!("/{id}"), "parent_folder_id": null,
                "created_at": "2026-11-03T00:00:00Z", "updated_at": "2026-11-03T00:00:00Z" })
    };
    let server = Server::start(move |request, _| {
        let page = if request.path.contains("cursor=fld_2") {
            json!({ "data": [folder("fld_3")], "next_cursor": null })
        } else {
            json!({ "data": [folder("fld_1"), folder("fld_2")], "next_cursor": "fld_2" })
        };
        Reply::json(200, page)
    });
    let output = with_token(docspring(dir.path()).args(["folders", "list", "--all", "--json"]), &server);
    assert!(output.status.success(), "{}", stderr(&output));
    let list: Value = serde_json::from_slice(&output.stdout).expect("--json prints JSON");
    let ids: Vec<&str> = list["data"]
        .as_array()
        .expect("data")
        .iter()
        .filter_map(|folder| folder["id"].as_str())
        .collect();
    assert_eq!(ids, ["fld_1", "fld_2", "fld_3"]);
    assert_eq!(list["next_cursor"], Value::Null);
    let paths: Vec<String> = server.requests().into_iter().map(|(_, path, _)| path).collect();
    assert_eq!(paths.len(), 2, "{paths:?}");
    // The biggest page the API allows, so --all makes as few requests as it can
    assert!(paths.iter().all(|path| path.contains("limit=100")), "{paths:?}");
    assert!(paths[1].contains("cursor=fld_2"), "{paths:?}");

    // Without --all, one page and the cursor for the next
    let output = with_token(docspring(dir.path()).args(["folders", "list"]), &server);
    let table = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        table.contains("fld_2") && !table.contains("fld_3") && table.contains("--cursor fld_2"),
        "{table}"
    );
}

#[test]
fn a_permanent_link_download_runs_again_when_another_command_refreshed_the_login() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = dir.path().join("config");
    std::fs::create_dir(&config).expect("create the config directory");
    let saved = config.clone();
    let server = Server::start(move |request, base| match (request.path.as_str(), request.authorization.as_deref()) {
        // Another command refreshes the login just before this request, which revokes the access token it sends
        ("/file", Some("Bearer old")) => {
            save_login(&saved, "new");
            Reply::json(
                401,
                json!({"error": {"code": "unauthorized", "message": "The access token has been revoked."}}),
            )
        }
        ("/file", _) => Reply::pdf(),
        // The account turned off signed download links: only the permanent link, which takes the login
        _ => Reply::json(200, submission("processed", base, "pdf", true)),
    });
    std::fs::write(
        config.join("config.toml"),
        format!(
            "default_profile = \"default\"\n[profiles.default]\ncredential = \"login\"\nhost = \"{0}\"\nissuer = \"{0}\"\n",
            server.url
        ),
    )
    .expect("write config.toml");
    save_login(&config, "old");

    let output = docspring(dir.path())
        .args(["submissions", "download", "sub_test", "-o", "out.pdf"])
        .output()
        .expect("run docspring");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(dir.path().join("out.pdf")).expect("the saved PDF"), PDF);
    let tokens: Vec<Option<String>> = server.requests().into_iter().map(|(_, _, authorization)| authorization).collect();
    assert_eq!(tokens.last(), Some(&Some("Bearer new".to_owned())), "{tokens:?}");
}

#[test]
fn logins_at_the_same_time_keep_each_others_profiles() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (entered, first_entered) = mpsc::channel::<()>();
    let (release, released) = mpsc::channel::<()>();
    let entered = Mutex::new(entered);
    let released = Mutex::new(released);
    let checks = AtomicUsize::new(0);
    let server = Server::start(move |_request, _base| {
        // The first login's token check waits until the second login has finished
        if checks.fetch_add(1, Ordering::SeqCst) == 0 {
            entered.lock().expect("the channel").send(()).expect("the test is waiting");
            released
                .lock()
                .expect("the channel")
                .recv_timeout(Duration::from_secs(20))
                .expect("the test releases the first login");
        }
        Reply::json(200, json!({"authenticated": true}))
    });
    let login = |name: &str, token: &str| {
        let mut child = docspring(dir.path())
            .args(["login", "--with-token", "--profile", name, "--host", &server.url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run docspring login");
        child
            .stdin
            .take()
            .expect("login's standard input")
            .write_all(format!("{token}\nsecret_{token}\n").as_bytes())
            .expect("send the API token");
        child
    };

    let alpha = login("alpha", "api_test_alpha");
    first_entered.recv_timeout(Duration::from_secs(20)).expect("alpha checks its token");
    let beta = login("beta", "api_test_beta").wait_with_output().expect("beta finishes");
    assert!(beta.status.success(), "{}", stderr(&beta));
    release.send(()).expect("alpha is waiting");
    let alpha = alpha.wait_with_output().expect("alpha finishes");
    assert!(alpha.status.success(), "{}", stderr(&alpha));

    let config: toml::Table = std::fs::read_to_string(dir.path().join("config/config.toml"))
        .expect("read config.toml")
        .parse()
        .expect("config.toml is TOML");
    let profiles: Vec<&String> = config["profiles"].as_table().expect("a profiles table").keys().collect();
    assert_eq!(profiles, ["alpha", "beta"]);
    assert_eq!(
        config["default_profile"].as_str(),
        Some("beta"),
        "beta finished first, so it's the default"
    );
}

#[test]
fn a_token_login_to_a_server_without_api_v2_says_which_release_it_needs() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // An Enterprise install from before the CLI: no API v2
    let server = Server::start(|_request, _base| Reply::json(404, json!({"status": "error", "error": "Not found"})));
    let mut child = docspring(dir.path())
        .args(["login", "--with-token", "--host", &server.url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run docspring login");
    child
        .stdin
        .take()
        .expect("login's standard input")
        .write_all(b"api_test\nsecret\n")
        .expect("send the API token");
    let output = child.wait_with_output().expect("login finishes");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("/api/v2/authentication responded 404: check --host. A DocSpring Enterprise install needs the release"),
        "{}",
        stderr(&output)
    );
    assert!(!dir.path().join("config/config.toml").exists(), "no profile is saved");
}

/// An account export's archive, as the app's export services make it (`tar -zcf archive.tar.gz .` in a folder with
/// index.json), with a link that extraction must skip
fn export_archive(files: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()));
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, format!("./{path}"), contents.as_bytes())
            .expect("add a file to the archive");
    }
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    builder
        .append_link(&mut header, "./link", "/etc/hosts")
        .expect("add a link to the archive");
    builder
        .into_inner()
        .expect("finish the archive")
        .finish()
        .expect("finish compressing the archive")
}

#[test]
fn exports_download_extracts_every_archive_and_picks_up_where_an_expired_link_stopped_it() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let first = export_archive(&[
        ("index.json", r#"{"resource_type":"templates"}"#),
        ("templates/tpl_1/template.json", r#"{"id":"tpl_1"}"#),
    ]);
    let second = export_archive(&[
        ("index.json", r#"{"resource_type":"submissions"}"#),
        ("submissions/sub_1/submission.json", r#"{"id":"sub_1"}"#),
    ]);
    // The second link has expired until support sends a new index file
    let expired = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let server = Server::start({
        let expired = expired.clone();
        move |request, _| {
            if request.path.contains("mbp_1") {
                Reply {
                    status: 200,
                    body: first.clone(),
                }
            } else if request.path.contains("mbp_2") && !expired.load(Ordering::SeqCst) {
                Reply {
                    status: 200,
                    body: second.clone(),
                }
            } else {
                Reply::json(403, json!({"message": "Access denied"}))
            }
        }
    });
    let link = |name: &str| format!("{}/account_migrations/mig_Test1/mgb_1/{name}.tar.gz?Expires=1&Signature=x", server.url);
    let index = json!({
        "migration_type": "export",
        "batches": [
            {"resource_type": "templates", "parts": [link("mbp_1-templates-acc_1-00000001-00000001")]},
            {"resource_type": "submissions", "parts": [link("mbp_2-submissions-tpl_1-00000001-00000001")]},
        ],
        "total_size": 2048, "accounts_count": 1, "templates_count": 1, "submissions_count": 1,
    });
    let mut gzipped = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzipped.write_all(index.to_string().as_bytes()).expect("compress the index file");
    let index_file = dir.path().join("account_migration_index_mig_Test1.json.gz");
    std::fs::write(&index_file, gzipped.finish().expect("compress the index file")).expect("write the index file");

    // Credentials in the environment never go to the export's links
    let output = with_token(docspring(dir.path()).args(["exports", "download"]).arg(&index_file), &server);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("links have expired"), "{}", stderr(&output));
    let export = dir.path().join("mig_Test1");
    assert_eq!(
        std::fs::read_to_string(export.join("templates/tpl_1/template.json")).expect("the first archive's files"),
        r#"{"id":"tpl_1"}"#
    );
    assert!(export.join("indices/mbp_1-templates-acc_1-00000001-00000001.json").exists());
    assert!(!export.join("submissions").exists());

    expired.store(false, Ordering::SeqCst);
    let output = with_token(docspring(dir.path()).args(["exports", "download", "--json"]).arg(&index_file), &server);
    assert!(output.status.success(), "{}", stderr(&output));
    let summary: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(summary["downloaded"], 1);
    assert_eq!(summary["skipped"], 1);
    assert_eq!(summary["submissions_count"], 1);
    assert_eq!(
        std::fs::read_to_string(export.join("submissions/sub_1/submission.json")).expect("the second archive's files"),
        r#"{"id":"sub_1"}"#
    );
    assert_eq!(
        std::fs::read_to_string(export.join("indices/mbp_2-submissions-tpl_1-00000001-00000001.json")).expect("the second archive's index"),
        r#"{"resource_type":"submissions"}"#
    );
    // The archives are deleted once extracted, the archives' own index files aren't left on top of each other, and
    // the links in them are skipped
    assert!(!export.join("archives").exists());
    assert!(!export.join("index.json").exists());
    assert!(std::fs::symlink_metadata(export.join("link")).is_err());

    let requests = server.requests();
    assert_eq!(requests.iter().filter(|(_, path, _)| path.contains("mbp_1")).count(), 1, "{requests:?}");
    assert!(requests.iter().all(|(_, _, authorization)| authorization.is_none()), "{requests:?}");
}

/// Writes an export's index file, gzipped as support sends it, that links to each archive
fn export_index(dir: &Path, links: &[String]) -> std::path::PathBuf {
    let index = json!({"migration_type": "export", "batches": [{"resource_type": "templates", "parts": links}]});
    let mut gzipped = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzipped.write_all(index.to_string().as_bytes()).expect("compress the index file");
    let path = dir.join("account_migration_index_mig_Test2.json.gz");
    std::fs::write(&path, gzipped.finish().expect("compress the index file")).expect("write the index file");
    path
}

#[test]
fn exports_download_deletes_a_damaged_archive_and_downloads_it_again() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let good = export_archive(&[
        ("index.json", r#"{"resource_type":"templates"}"#),
        ("acc_1/templates/tpl_1/template.json", r#"{"id":"tpl_1"}"#),
    ]);
    // Arrives in full, but changed on the way: only the gzip footer's checksum shows it
    let mut damaged = good.clone();
    let checksum = damaged.len() - 8;
    damaged[checksum] ^= 0xff;
    let fixed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = Server::start({
        let fixed = fixed.clone();
        move |_, _| Reply {
            status: 200,
            body: if fixed.load(Ordering::SeqCst) { good.clone() } else { damaged.clone() },
        }
    });
    let name = "mbp_1-templates-acc_1-00000001-00000001";
    let index_file = export_index(dir.path(), &[format!("{}/{name}.tar.gz", server.url)]);
    let export = dir.path().join("mig_Test2");

    let output = docspring(dir.path())
        .args(["exports", "download", "--keep-archives"])
        .arg(&index_file)
        .output()
        .expect("run docspring");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("checksum"), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("It was deleted: run this again to download it again"),
        "{}",
        stderr(&output)
    );
    // Nothing from it is extracted or marked as done, and it's not kept
    assert!(!export.join("acc_1").exists());
    assert!(!export.join(format!("indices/{name}.json")).exists());
    assert!(!export.join(format!("archives/{name}.tar.gz")).exists());

    fixed.store(true, Ordering::SeqCst);
    let output = docspring(dir.path())
        .args(["exports", "download", "--keep-archives"])
        .arg(&index_file)
        .output()
        .expect("run docspring");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        std::fs::read_to_string(export.join("acc_1/templates/tpl_1/template.json")).expect("the archive's files"),
        r#"{"id":"tpl_1"}"#
    );
    assert!(export.join(format!("indices/{name}.json")).exists());
    assert!(export.join(format!("archives/{name}.tar.gz")).exists());
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn exports_download_refuses_an_archive_that_writes_to_its_own_folders() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let second = "mbp_2-templates-acc_1-00000002-00000002";
    // Would mark the second archive as extracted, so it was never downloaded
    let first = export_archive(&[
        ("index.json", r#"{"resource_type":"templates"}"#),
        ("acc_1/templates/tpl_1/template.json", r#"{"id":"tpl_1"}"#),
        (format!("indices/{second}.json").as_str(), "{}"),
    ]);
    let server = Server::start(move |_, _| Reply {
        status: 200,
        body: first.clone(),
    });
    let index_file = export_index(
        dir.path(),
        &[
            format!("{}/mbp_1-templates-acc_1-00000001-00000001.tar.gz", server.url),
            format!("{}/{second}.tar.gz", server.url),
        ],
    );
    let output = docspring(dir.path())
        .args(["exports", "download"])
        .arg(&index_file)
        .output()
        .expect("run docspring");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(&format!(
            "it has indices/{second}.json, in the indices/ folder that this command keeps for itself"
        )),
        "{}",
        stderr(&output)
    );
    let export = dir.path().join("mig_Test2");
    assert!(!export.join(format!("indices/{second}.json")).exists());
    assert!(!export.join("acc_1").exists());
}

#[test]
fn exports_download_says_when_a_file_isnt_an_export_index() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(dir.path().join("index.json"), r#"{"data": []}"#).expect("write the file");
    let output = docspring(dir.path())
        .args(["exports", "download", "index.json"])
        .output()
        .expect("run docspring");
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("isn't an account export's index file"), "{}", stderr(&output));
}
