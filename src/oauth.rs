//! Logging in with OAuth: the authorization code flow with PKCE, a browser and a loopback redirect (RFC 8252), token
//! refreshes and revocation. DocSpring knows the CLI by its client ID metadata document, so there's no registration.

use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::errors::{describe, CliError};

pub const CLIENT_ID: &str = "https://docspring.com/oauth/cli-client-metadata.json";
/// The consent screen lets the user choose less
pub const SCOPE: &str = "read write delete integrations";
pub const US_ISSUER: &str = "https://app.docspring.com";
pub const EU_ISSUER: &str = "https://app-eu.docspring.com";
/// How long `docspring login` waits for the browser
const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the login listener waits for a connection's request: a browser can open a connection and send nothing
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request to the login server can take
const OAUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// The authorization server metadata (RFC 8414)
#[derive(Clone, Debug, Deserialize)]
pub struct ServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// A refresh the server refused (`invalid_grant`): the login has expired or was disconnected
#[derive(Debug)]
pub enum RefreshError {
    Refused(String),
    Failed(CliError),
}

/// The issuer's metadata, from `<issuer>/.well-known/oauth-authorization-server`
pub async fn discover(http: &reqwest::Client, issuer: &str) -> Result<ServerMetadata, CliError> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/oauth-authorization-server");
    let response = http
        .get(&url)
        .timeout(OAUTH_TIMEOUT)
        .send()
        .await
        .map_err(|error| CliError::api(format!("Couldn't reach {issuer}: {}", describe(&error))))?;
    if !response.status().is_success() {
        return Err(CliError::auth(format!(
            "{url} responded {}: {issuer} isn't a DocSpring login server. For a DocSpring Enterprise install, pass \
             --issuer with its address (such as https://docspring.example.com). The CLI needs the Enterprise release \
             that added it, or a later one.",
            response.status().as_u16()
        )));
    }
    let metadata: ServerMetadata = response
        .json()
        .await
        .map_err(|error| CliError::api(format!("Couldn't read {url}: {}", describe(&error))))?;
    if metadata.issuer.trim_end_matches('/') != issuer {
        return Err(CliError::auth(format!(
            "{url} is for a different server ({}), so the CLI won't log in with it",
            metadata.issuer
        )));
    }
    Ok(metadata)
}

/// A PKCE verifier and its S256 challenge (RFC 7636)
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn pkce() -> Pkce {
    let verifier = random_string(32);
    let challenge = base64url(&sha2::Sha256::digest(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

fn random_string(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("the OS has a random number generator");
    base64url(&buffer)
}

fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Opens the consent screen in a browser and waits for its redirect to a listener on 127.0.0.1, then exchanges the
/// code for tokens. `on_url` gets the link to open, for when no browser opens (an SSH session).
pub async fn authorize(
    http: &reqwest::Client,
    metadata: &ServerMetadata,
    open_browser: bool,
    on_url: impl Fn(&str),
) -> Result<TokenResponse, CliError> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| CliError::auth(format!("Couldn't listen on 127.0.0.1 for the login: {error}")))?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let pkce = pkce();
    let state = random_string(24);
    let mut url = url::Url::parse(&metadata.authorization_endpoint)
        .map_err(|error| CliError::auth(format!("The login server's authorization endpoint isn't a URL: {error}")))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", SCOPE)
        .append_pair("state", &state)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");
    on_url(url.as_str());
    if open_browser {
        // The link is printed too, so a browser that doesn't open isn't an error
        let _ = webbrowser::open(url.as_str());
    }
    let code = tokio::time::timeout(LOGIN_TIMEOUT, wait_for_callback(&listener, &state, metadata))
        .await
        .map_err(|_| CliError::auth("The login timed out: no answer from the browser in 10 minutes"))??;
    exchange_code(http, metadata, &code, &pkce.verifier, &redirect_uri).await
}

/// Checks the redirect's `state` and `iss` (RFC 9207) and returns its code
pub fn check_callback(query: &[(String, String)], state: &str, metadata: &ServerMetadata) -> Result<String, CliError> {
    let value = |name: &str| query.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
    if value("state") != Some(state) {
        return Err(CliError::auth(
            "The browser's answer wasn't for this login (its state didn't match). Run `docspring login` again.",
        ));
    }
    let iss = value("iss");
    if (iss.is_some() || metadata.authorization_response_iss_parameter_supported)
        && iss.map(|iss| iss.trim_end_matches('/')) != Some(metadata.issuer.trim_end_matches('/'))
    {
        return Err(CliError::auth(format!(
            "The browser's answer came from a different server ({}), not {}. Run `docspring login` again.",
            iss.unwrap_or("none"),
            metadata.issuer
        )));
    }
    if let Some(error) = value("error") {
        let message = match error {
            "access_denied" => "The login was cancelled.".to_owned(),
            _ => format!("The login failed: {}", value("error_description").unwrap_or(error)),
        };
        return Err(CliError::auth(message));
    }
    value("code")
        .map(str::to_owned)
        .ok_or_else(|| CliError::auth("The browser's answer had no authorization code. Run `docspring login` again."))
}

/// Answers requests to the listener until this login's redirect comes to /callback, and returns its code. Anything
/// else (a favicon, a tab left open from an earlier login, another program) gets an answer and the wait goes on.
async fn wait_for_callback(listener: &TcpListener, state: &str, metadata: &ServerMetadata) -> Result<String, CliError> {
    let mut requests = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                // Each connection has its own task, so one that sends nothing doesn't hold up the others
                requests.spawn(async move { tokio::time::timeout(REQUEST_TIMEOUT, read_request(stream)).await.ok().flatten() });
            }
            // None only when no connection is open, and then only a new one can come
            Some(finished) = requests.join_next() => {
                // A connection that closed or sent nothing in time
                let Ok(Some((mut stream, target))) = finished else { continue };
                let callback = target.strip_prefix("/callback").filter(|rest| rest.is_empty() || rest.starts_with('?'));
                let Some(query) = callback else {
                    respond(&mut stream, "404 Not Found", None).await;
                    continue;
                };
                let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
                    .into_owned()
                    .collect();
                if !pairs.iter().any(|(key, value)| key == "state" && value == state) {
                    let page = callback_page(
                        "This isn't the login your terminal is waiting for. Open the link that <code>docspring login</code> \
                         printed last.",
                    );
                    respond(&mut stream, "400 Bad Request", Some(&page)).await;
                    continue;
                }
                let result = check_callback(&pairs, state, metadata);
                let page = match &result {
                    Ok(_) => callback_page("You can close this tab and go back to your terminal."),
                    Err(error) => callback_page(&format!("The login didn't finish: {}", html_escape(&error.message))),
                };
                respond(&mut stream, "200 OK", Some(&page)).await;
                return result;
            }
        }
    }
}

/// A connection's request target, once its request line and headers have come (a browser sends no body with a GET)
async fn read_request(mut stream: tokio::net::TcpStream) -> Option<(tokio::net::TcpStream, String)> {
    let mut buffer = vec![0u8; 8192];
    let mut length = 0;
    while length < buffer.len() && !buffer[..length].windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer[length..]).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => length += read,
        }
    }
    let request = String::from_utf8_lossy(&buffer[..length]);
    let target = request.lines().next()?.split(' ').nth(1)?.to_owned();
    Some((stream, target))
}

async fn respond(stream: &mut tokio::net::TcpStream, status: &str, page: Option<&str>) {
    let page = page.unwrap_or("");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn callback_page(message: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>DocSpring CLI</title></head>\
         <body style=\"font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 32rem; padding: 0 1rem\">\
         <h1 style=\"font-size: 1.4rem\">DocSpring CLI</h1><p>{message}</p></body></html>"
    )
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub async fn exchange_code(
    http: &reqwest::Client,
    metadata: &ServerMetadata,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, CliError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", CLIENT_ID),
        ("code_verifier", verifier),
    ];
    token_request(http, &metadata.token_endpoint, &form).await.map_err(|error| match error {
        RefreshError::Refused(message) => CliError::auth(format!("The login server refused the login: {message}")),
        RefreshError::Failed(error) => error,
    })
}

pub async fn refresh(http: &reqwest::Client, token_endpoint: &str, refresh_token: &str) -> Result<TokenResponse, RefreshError> {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", CLIENT_ID),
    ];
    token_request(http, token_endpoint, &form).await
}

async fn token_request(http: &reqwest::Client, endpoint: &str, form: &[(&str, &str)]) -> Result<TokenResponse, RefreshError> {
    let response = http
        .post(endpoint)
        .form(form)
        .timeout(OAUTH_TIMEOUT)
        .send()
        .await
        .map_err(|error| RefreshError::Failed(CliError::api(format!("Couldn't reach {endpoint}: {}", describe(&error)))))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| RefreshError::Failed(CliError::api(format!("Couldn't read {endpoint}'s response: {}", describe(&error)))))?;
    if status.is_success() {
        return serde_json::from_str(&body)
            .map_err(|error| RefreshError::Failed(CliError::api(format!("Couldn't read {endpoint}'s response: {error}"))));
    }
    match serde_json::from_str::<ErrorResponse>(&body) {
        Ok(error) if status.as_u16() == 400 || status.as_u16() == 401 => {
            let description = error.error_description.unwrap_or_default();
            Err(RefreshError::Refused(if description.is_empty() {
                error.error
            } else {
                format!("{} ({description})", error.error)
            }))
        }
        _ => Err(RefreshError::Failed(CliError::api(format!("{endpoint} responded {}", status.as_u16())))),
    }
}

/// Revokes a token (RFC 7009). Revoking a refresh token ends that login's session.
pub async fn revoke(http: &reqwest::Client, revocation_endpoint: &str, token: &str, hint: &str) -> Result<(), CliError> {
    let form = [("token", token), ("token_type_hint", hint), ("client_id", CLIENT_ID)];
    let response = http
        .post(revocation_endpoint)
        .form(&form)
        .timeout(OAUTH_TIMEOUT)
        .send()
        .await
        .map_err(|error| CliError::api(format!("Couldn't reach {revocation_endpoint}: {}", describe(&error))))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(CliError::api(format!("{revocation_endpoint} responded {}", response.status().as_u16())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ServerMetadata {
        ServerMetadata {
            issuer: "https://app.docspring.com".to_owned(),
            authorization_endpoint: "https://app.docspring.com/oauth/authorize".to_owned(),
            token_endpoint: "https://app.docspring.com/oauth/token".to_owned(),
            revocation_endpoint: Some("https://app.docspring.com/oauth/revoke".to_owned()),
            authorization_response_iss_parameter_supported: true,
        }
    }

    fn query(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    #[test]
    fn the_pkce_challenge_is_the_verifiers_sha256() {
        let pkce = pkce();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(pkce.challenge, base64url(&sha2::Sha256::digest(pkce.verifier.as_bytes())));
        assert_ne!(pkce.verifier, super::pkce().verifier);
        // RFC 7636's example
        assert_eq!(
            base64url(&sha2::Sha256::digest(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_callback_needs_this_logins_state_and_issuer() {
        let ok = query(&[("code", "abc"), ("state", "s1"), ("iss", "https://app.docspring.com")]);
        assert_eq!(check_callback(&ok, "s1", &metadata()).unwrap(), "abc");

        let error = check_callback(&ok, "s2", &metadata()).unwrap_err();
        assert!(error.message.contains("state didn't match"), "{}", error.message);

        let other_server = query(&[("code", "abc"), ("state", "s1"), ("iss", "https://evil.example")]);
        let error = check_callback(&other_server, "s1", &metadata()).unwrap_err();
        assert!(error.message.contains("different server (https://evil.example)"), "{}", error.message);

        let no_iss = query(&[("code", "abc"), ("state", "s1")]);
        assert!(check_callback(&no_iss, "s1", &metadata()).is_err());

        let denied = query(&[("error", "access_denied"), ("state", "s1"), ("iss", "https://app.docspring.com")]);
        let error = check_callback(&denied, "s1", &metadata()).unwrap_err();
        assert_eq!(error.message, "The login was cancelled.");
        assert_eq!(error.code, crate::errors::exit::AUTH);
    }

    async fn get(port: u16, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn the_listener_waits_for_this_logins_callback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = tokio::spawn(async move {
            // A connection that sends nothing doesn't hold up the callback
            let _idle = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let favicon = get(port, "/favicon.ico").await;
            let stale = get(port, "/callback?code=old&state=s0&iss=https%3A%2F%2Fapp.docspring.com").await;
            let callback = get(port, "/callback?code=abc&state=s%201&iss=https%3A%2F%2Fapp.docspring.com").await;
            (favicon, stale, callback)
        });
        let code = tokio::time::timeout(Duration::from_secs(5), wait_for_callback(&listener, "s 1", &metadata()))
            .await
            .expect("an idle connection held up the callback")
            .unwrap();
        assert_eq!(code, "abc");
        let (favicon, stale, callback) = browser.await.unwrap();
        assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");
        assert!(
            stale.starts_with("HTTP/1.1 400") && stale.contains("isn't the login your terminal is waiting for"),
            "{stale}"
        );
        assert!(callback.contains("You can close this tab"), "{callback}");
    }

    #[tokio::test]
    async fn the_browser_page_says_why_a_login_failed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let browser = tokio::spawn(async move { get(port, "/callback?code=abc&state=s1&iss=https%3A%2F%2Fevil.example").await });
        let error = wait_for_callback(&listener, "s1", &metadata()).await.unwrap_err();
        assert!(error.message.contains("different server (https://evil.example)"), "{}", error.message);
        let page = browser.await.unwrap();
        assert!(
            page.contains("The login didn't finish: The browser's answer came from a different server"),
            "{page}"
        );
        assert!(!page.contains("You can close this tab"), "{page}");
    }
}
