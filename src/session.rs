//! Which credentials a command uses and where its requests go, and the Rust SDK's client for them.
//!
//! A profile named with --profile or DOCSPRING_PROFILE comes first, so an API token exported in the shell can't
//! silently replace the profile you asked for. Then the API token in DOCSPRING_TOKEN_ID and DOCSPRING_TOKEN_SECRET
//! (CI and agents), then the default profile. A profile's requests always go to the server it was saved for: its
//! credentials are never sent anywhere else.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::config::{config_dir, saved_by_newer_cli, Config, CredentialKind, Profile};
use crate::errors::CliError;
use crate::oauth;
use crate::secrets::{self, CredentialsLock, Secret, SecretStore};
use crate::GlobalArgs;

const US_API_HOST: &str = "sync.api.docspring.com";
const EU_API_HOST: &str = "sync.api-eu.docspring.com";
/// A login's access token is refreshed when it has less than this left, so a command (and a submission it waits for,
/// 5 minutes by default) doesn't outlive it
const REFRESH_BEFORE_EXPIRY: i64 = 10 * 60;
/// When a refresh fails, an access token that works for longer than this is used anyway
const STILL_VALID: i64 = 60;

pub fn user_agent() -> String {
    format!("docspring-cli-{}", crate::VERSION)
}

#[derive(Clone)]
pub enum Auth {
    Basic { token_id: String, token_secret: String },
    Bearer(String),
}

pub struct Session {
    pub client: docspring::Client,
    pub auth: Auth,
    /// The profile whose credentials the command uses (none for an API token from the environment)
    pub profile: Option<String>,
}

/// What a command says when only one of the API token's environment variables is set
pub const INCOMPLETE_ENV_TOKEN: &str = "Set both DOCSPRING_TOKEN_ID and DOCSPRING_TOKEN_SECRET (an API token's ID and secret)";

/// An environment variable's value, unless it's unset or blank
pub fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The profile --profile (or DOCSPRING_PROFILE) names, unless it's blank
pub fn named_profile(global: &GlobalArgs) -> Option<String> {
    global.profile.clone().filter(|name| !name.trim().is_empty())
}

impl Session {
    pub async fn resolve(global: &GlobalArgs) -> Result<Session, CliError> {
        let env = env_var;
        let named_profile = named_profile(global);
        let (host, auth, profile) = match named_profile {
            Some(name) => profile_session(global, name).await?,
            None if env("DOCSPRING_TOKEN_ID").is_some() || env("DOCSPRING_TOKEN_SECRET").is_some() => {
                let (Some(token_id), Some(token_secret)) = (env("DOCSPRING_TOKEN_ID"), env("DOCSPRING_TOKEN_SECRET")) else {
                    return Err(CliError::auth(INCOMPLETE_ENV_TOKEN));
                };
                let host = api_host(
                    global.host.clone().or_else(|| env("DOCSPRING_HOST")),
                    global.region.clone().or_else(|| env("DOCSPRING_REGION")),
                )?;
                (host, Auth::Basic { token_id, token_secret }, None)
            }
            None => {
                let dir = config_dir()?;
                let config = Config::load(&dir)?;
                let Some(name) = config.default_profile.clone() else {
                    return Err(CliError::auth(
                        "You're not logged in. Run `docspring login`, or set DOCSPRING_TOKEN_ID and DOCSPRING_TOKEN_SECRET \
                         to an API token's ID and secret.",
                    ));
                };
                profile_session(global, name).await?
            }
        };
        let client = sdk_client(&api_base(&host), &auth, !global.no_validate)?;
        Ok(Session { client, auth, profile })
    }

    /// Whether this session's login has a newer access token than the one it used: another docspring command refreshed
    /// it while this one ran, and the server revokes the old access token once the new one is used
    pub fn login_replaced(&self) -> bool {
        let (Some(name), Auth::Bearer(used)) = (&self.profile, &self.auth) else {
            return false;
        };
        config_dir()
            .and_then(|dir| SecretStore::new(&dir))
            .is_ok_and(|store| access_token_changed(&store, name, used))
    }
}

/// Whether the profile's saved login has an access token other than `used`
fn access_token_changed(store: &SecretStore, profile: &str, used: &str) -> bool {
    matches!(store.get(profile), Ok(Some(Secret::Login { access_token, .. })) if access_token != used)
}

async fn profile_session(global: &GlobalArgs, name: String) -> Result<(String, Auth, Option<String>), CliError> {
    let dir = config_dir()?;
    let store = SecretStore::new(&dir)?;
    let (host, auth) = profile_credentials(&dir, &store, global, &name).await?;
    Ok((host, auth, Some(name)))
}

/// A profile's server and credentials, read (and refreshed) under the credentials lock. A login saves a profile and its
/// secret under that lock, so they're read as a pair: without it, a command could read the profile's old server and
/// the tokens a login in another terminal just saved for a new one, and send them to the old server.
async fn profile_credentials(dir: &Path, store: &SecretStore, global: &GlobalArgs, name: &str) -> Result<(String, Auth), CliError> {
    let lock = secrets::lock(dir).await?;
    let config = Config::load(dir)?;
    let profile = config.profile(name)?;
    if let CredentialKind::Other(kind) = &profile.credential {
        return Err(saved_by_newer_cli(name, kind));
    }
    let host = profile_host(name, profile, global)?;
    let not_saved = || {
        CliError::auth(format!(
            "Profile {name} has no saved credentials. Run `docspring login --profile {name}`{}.",
            if profile.credential == CredentialKind::ApiToken {
                " --with-token"
            } else {
                ""
            }
        ))
    };
    let auth = match (&profile.credential, store.get(name)?) {
        (CredentialKind::ApiToken, Some(Secret::ApiToken { token_secret })) => {
            let token_id = profile.token_id.clone().ok_or_else(not_saved)?;
            Auth::Basic { token_id, token_secret }
        }
        (
            CredentialKind::Login,
            Some(Secret::Login {
                access_token,
                refresh_token,
                expires_at,
            }),
        ) => {
            if expiring(expires_at) {
                Auth::Bearer(refresh(&lock, store, name, profile, access_token, refresh_token, expires_at).await?)
            } else {
                Auth::Bearer(access_token)
            }
        }
        _ => return Err(not_saved()),
    };
    Ok((host, auth))
}

/// The profile's own server. A --host or --region for another one is refused: sending a login's access token or an API
/// token's secret to whatever host a command names would hand it to that host.
fn profile_host(name: &str, profile: &Profile, global: &GlobalArgs) -> Result<String, CliError> {
    let host = api_host(profile.host.clone(), profile.region.clone())?;
    if global.host.is_none() && global.region.is_none() {
        return Ok(host);
    }
    let asked = api_host(global.host.clone(), global.region.clone())?;
    if api_base(&asked).eq_ignore_ascii_case(&api_base(&host)) {
        return Ok(host);
    }
    let flag = match (&global.host, &global.region) {
        (Some(host), _) => format!("--host {}", host.trim()),
        (None, region) => format!("--region {}", region.as_deref().unwrap_or_default().to_uppercase()),
    };
    Err(CliError::usage(format!(
        "Profile {name} is for DocSpring {}, and {flag} is another server: a profile's credentials only go to its own. \
         Leave out --host and --region to use profile {name}, or save a profile for that server with \
         `docspring login --profile <name> {flag}`.",
        profile.location()
    )))
}

fn expiring(expires_at: Option<i64>) -> bool {
    expires_at.is_some_and(|expires_at| expires_at - now() < REFRESH_BEFORE_EXPIRY)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64
}

/// Refreshes a login's access token. The caller holds the credentials lock and read the tokens under it, so no other
/// command refreshes them at the same time: refreshing with the old refresh token after the new one was used would make
/// the server revoke the whole login.
async fn refresh(
    _lock: &CredentialsLock,
    store: &SecretStore,
    name: &str,
    profile: &Profile,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<i64>,
) -> Result<String, CliError> {
    let expired = || {
        CliError::auth(format!(
            "Profile {name}'s login has expired or was disconnected (on the Integrations page in DocSpring, or by logging \
             in with less access on another computer). Run `docspring login{}` again.",
            if name == crate::config::DEFAULT_PROFILE {
                String::new()
            } else {
                format!(" --profile {name}")
            }
        ))
    };
    let refresh_token = refresh_token.ok_or_else(expired)?;
    let issuer = profile.issuer.clone().ok_or_else(expired)?;
    let http = http_client()?;
    let refreshed = match oauth::discover(&http, &issuer).await {
        Ok(metadata) => oauth::refresh(&http, &metadata.token_endpoint, &refresh_token).await,
        Err(error) => Err(oauth::RefreshError::Failed(error)),
    };
    let tokens = match refreshed {
        Ok(tokens) => tokens,
        Err(oauth::RefreshError::Refused(_)) => return Err(expired()),
        // The login server couldn't be reached or failed: the access token still works for a few minutes, and the
        // next command refreshes it
        Err(oauth::RefreshError::Failed(_)) if expires_at.is_some_and(|expires_at| expires_at - now() > STILL_VALID) => return Ok(access_token),
        Err(oauth::RefreshError::Failed(error)) => return Err(error),
    };
    let secret = Secret::Login {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.or(Some(refresh_token)),
        expires_at: tokens.expires_in.map(|seconds| now() + seconds),
    };
    store.set(name, &secret)?;
    Ok(tokens.access_token)
}

/// The API host for a host or region given by a flag, an env var or a profile. A host wins over a region.
pub fn api_host(host: Option<String>, region: Option<String>) -> Result<String, CliError> {
    if let Some(host) = host.filter(|host| !host.trim().is_empty()) {
        return Ok(host.trim().to_owned());
    }
    match region.as_deref().map(|region| region.trim().to_uppercase()).as_deref() {
        None | Some("") | Some("US") => Ok(US_API_HOST.to_owned()),
        Some("EU") => Ok(EU_API_HOST.to_owned()),
        // The Rust SDK's message
        Some(_) => Err(CliError::usage(format!(
            "{} is not a valid region. Valid regions: US, EU",
            region.unwrap_or_default().trim()
        ))),
    }
}

/// The OAuth server for a region (Enterprise installs and other hosts discover theirs)
pub fn region_issuer(region: Option<&str>) -> &'static str {
    match region.map(str::to_uppercase).as_deref() {
        Some("EU") => oauth::EU_ISSUER,
        _ => oauth::US_ISSUER,
    }
}

/// The API's base URL on a host: https:// when the host has no scheme, and any API version's path (/api/v1 from an
/// older SDK's setting) becomes /api/v2. The same rules as the Rust SDK's.
pub fn api_base(host: &str) -> String {
    let mut url = origin(host);
    if let Some(index) = url.to_ascii_lowercase().rfind("/api/v") {
        let version = &url[index + "/api/v".len()..];
        if !version.is_empty() && version.chars().all(|c| c.is_ascii_digit()) {
            url.truncate(index);
        }
    }
    format!("{url}/api/v2")
}

/// A host as a URL, without a trailing slash
pub fn origin(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    let mut url = if lower.starts_with("http://") || lower.starts_with("https://") {
        host.to_owned()
    } else {
        format!("https://{host}")
    };
    while url.ends_with('/') {
        url.pop();
    }
    url
}

/// An HTTP client for the CLI's own requests (OAuth, downloads). It never has credentials of its own.
pub fn http_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| CliError::api(format!("Couldn't create an HTTP client: {error}")))
}

/// The Rust SDK's client: the SDK sends HTTP Basic auth for API tokens, and a login's access token goes in a default
/// Authorization header on its reqwest client. reqwest drops that header when a redirect goes to another host.
fn sdk_client(api_base: &str, auth: &Auth, validate_requests: bool) -> Result<docspring::Client, CliError> {
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent())
        .connect_timeout(Duration::from_secs(30));
    if let Auth::Bearer(token) = auth {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CliError::auth("The saved access token isn't valid: run `docspring login` again"))?;
        value.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        builder = builder.default_headers(headers);
    }
    let http = builder
        .build()
        .map_err(|error| CliError::api(format!("Couldn't create an HTTP client: {error}")))?;
    let basic_auth = match auth {
        Auth::Basic { token_id, token_secret } => Some((token_id.clone(), Some(token_secret.clone()))),
        Auth::Bearer(_) => None,
    };
    let configuration = docspring::Configuration {
        base_path: api_base.to_owned(),
        user_agent: Some(user_agent()),
        client: http,
        basic_auth,
        oauth_access_token: None,
        bearer_access_token: None,
        api_key: None,
        validate_requests,
    };
    Ok(docspring::Client::new(Arc::new(configuration)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_regions_give_the_api_base() {
        assert_eq!(api_base(&api_host(None, None).unwrap()), "https://sync.api.docspring.com/api/v2");
        assert_eq!(
            api_base(&api_host(None, Some("eu".to_owned())).unwrap()),
            "https://sync.api-eu.docspring.com/api/v2"
        );
        assert_eq!(
            api_base(&api_host(Some("http://localhost:3000/".to_owned()), Some("EU".to_owned())).unwrap()),
            "http://localhost:3000/api/v2"
        );
        assert_eq!(api_base("docspring.example.com/api/v1"), "https://docspring.example.com/api/v2");
        assert_eq!(api_base("example.com/proxy/api/version"), "https://example.com/proxy/api/version/api/v2");
        assert!(api_host(None, Some("AU".to_owned())).is_err());
    }

    #[test]
    fn a_profile_only_sends_its_credentials_to_its_own_server() {
        let global = |host: Option<&str>, region: Option<&str>| GlobalArgs {
            host: host.map(str::to_owned),
            region: region.map(str::to_owned),
            ..GlobalArgs::default()
        };
        let profile = |host: Option<&str>, region: Option<&str>| Profile {
            credential: CredentialKind::Login,
            region: region.map(str::to_owned),
            host: host.map(str::to_owned),
            issuer: None,
            scope: None,
            token_id: None,
            unknown: Default::default(),
        };
        let eu = profile(None, Some("EU"));
        assert_eq!(profile_host("work", &eu, &global(None, None)).unwrap(), EU_API_HOST);
        assert_eq!(profile_host("work", &eu, &global(None, Some("eu"))).unwrap(), EU_API_HOST);
        assert_eq!(profile_host("work", &eu, &global(Some(EU_API_HOST), None)).unwrap(), EU_API_HOST);
        let error = profile_host("work", &eu, &global(None, Some("us"))).unwrap_err();
        assert_eq!(
            error.message,
            "Profile work is for DocSpring EU, and --region US is another server: a profile's credentials only go to its \
             own. Leave out --host and --region to use profile work, or save a profile for that server with \
             `docspring login --profile <name> --region US`."
        );
        assert!(profile_host("work", &eu, &global(Some("attacker.example.com"), Some("EU"))).is_err());

        // A profile saved without a region is a US one
        let us = profile(None, None);
        assert_eq!(profile_host("default", &us, &global(None, Some("US"))).unwrap(), US_API_HOST);
        assert!(profile_host("default", &us, &global(None, Some("EU"))).is_err());

        let enterprise = profile(Some("docspring.example.com"), None);
        assert_eq!(
            profile_host("ent", &enterprise, &global(Some("https://DocSpring.example.com/"), None)).unwrap(),
            "docspring.example.com"
        );
        let error = profile_host("ent", &enterprise, &global(Some("localhost:3000"), None)).unwrap_err();
        assert!(
            error
                .message
                .starts_with("Profile ent is for DocSpring docspring.example.com, and --host localhost:3000"),
            "{}",
            error.message
        );
        assert!(profile_host("ent", &enterprise, &global(None, Some("US"))).is_err());
    }

    #[test]
    fn a_login_is_replaced_when_its_saved_access_token_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::file_only(dir.path());
        assert!(!access_token_changed(&store, "default", "old"));
        let login = |access_token: &str| Secret::Login {
            access_token: access_token.to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at: Some(now() + 3600),
        };
        store.set("default", &login("old")).unwrap();
        assert!(!access_token_changed(&store, "default", "old"));
        store.set("default", &login("new")).unwrap();
        assert!(access_token_changed(&store, "default", "old"));
        assert!(!access_token_changed(&store, "work", "old"));
        // Logged out, or replaced with an API token: running the command again can't help
        store
            .set(
                "default",
                &Secret::ApiToken {
                    token_secret: "secret".to_owned(),
                },
            )
            .unwrap();
        assert!(!access_token_changed(&store, "default", "old"));
    }

    #[tokio::test]
    async fn a_token_that_still_works_is_used_when_the_login_server_cant_be_reached() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::file_only(dir.path());
        let profile = Profile {
            credential: CredentialKind::Login,
            region: None,
            host: None,
            // Nothing listens on port 1
            issuer: Some("http://127.0.0.1:1".to_owned()),
            scope: None,
            token_id: None,
            unknown: Default::default(),
        };
        let lock = secrets::lock(dir.path()).await.unwrap();
        let refresh_expiring = |expires_at: i64| {
            refresh(
                &lock,
                &store,
                "default",
                &profile,
                "access".to_owned(),
                Some("refresh".to_owned()),
                Some(expires_at),
            )
        };
        assert_eq!(refresh_expiring(now() + 300).await.unwrap(), "access");

        let error = refresh_expiring(now() + 30).await.unwrap_err();
        assert!(error.message.starts_with("Couldn't reach http://127.0.0.1:1"), "{}", error.message);
    }

    #[tokio::test]
    async fn a_command_never_pairs_a_profiles_old_server_with_a_new_logins_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_owned();
        let store = SecretStore::file_only(&path);
        let save = |host: &str, access_token: &str, expires_at: i64| {
            let mut config = Config::default();
            config.profiles.insert(
                "work".to_owned(),
                Profile {
                    credential: CredentialKind::Login,
                    region: None,
                    host: Some(host.to_owned()),
                    // Nothing listens on port 1: a refresh would fail
                    issuer: Some("http://127.0.0.1:1".to_owned()),
                    scope: None,
                    token_id: None,
                    unknown: Default::default(),
                },
            );
            config.save(&path).unwrap();
            let secret = Secret::Login {
                access_token: access_token.to_owned(),
                refresh_token: Some("refresh".to_owned()),
                expires_at: Some(expires_at),
            };
            store.set("work", &secret).unwrap();
        };
        // Profile work is on server A, and its access token is due for a refresh
        save("a.example.com", "token-a", now() + 30);

        // A login in another terminal holds the lock while the command starts, then saves work on server B
        let login = secrets::lock(&path).await.unwrap();
        let command = {
            let path = path.clone();
            tokio::spawn(async move {
                let store = SecretStore::file_only(&path);
                profile_credentials(&path, &store, &GlobalArgs::default(), "work").await
            })
        };
        // Long enough for the command to read the config and wait for the lock, if it read before taking it
        tokio::time::sleep(Duration::from_millis(300)).await;
        save("b.example.com", "token-b", now() + 3600);
        drop(login);

        let (host, auth) = command.await.unwrap().unwrap();
        assert_eq!(host, "b.example.com");
        assert!(matches!(auth, Auth::Bearer(token) if token == "token-b"));
    }

    #[test]
    fn a_token_is_refreshed_ten_minutes_before_it_expires() {
        assert!(!expiring(None));
        assert!(!expiring(Some(now() + 3600)));
        assert!(!expiring(Some(now() + 660)));
        // More than submit's default 5-minute wait
        assert!(expiring(Some(now() + 540)));
        assert!(expiring(Some(now() + 120)));
        assert!(expiring(Some(now() - 10)));
    }
}
