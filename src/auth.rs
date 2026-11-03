//! `docspring login`, `logout`, `auth status` and `profiles`: saving credentials in profiles.

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;

use clap::{Args, Subcommand};
use docspring::Api;
use serde_json::json;

use crate::config::{check_profile_name, config_dir, saved_by_newer_cli, Config, CredentialKind, Profile, DEFAULT_PROFILE};
use crate::errors::CliError;
use crate::oauth;
use crate::output;
use crate::runner::{CommandResult, Runner, Table};
use crate::secrets::{self, Saved, Secret, SecretStore};
use crate::session;

/// Log in to DocSpring in your browser, or save an API token
///
/// Saves the login in a profile (`default` unless you pass --profile), for commands to use. The tokens are kept in
/// your system's keychain. Each computer you log in on shares one "DocSpring CLI" connection on the Integrations page
/// in DocSpring: disconnecting it there logs out every one of them, and so does logging in again with less access.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Save an API token instead of logging in: its ID and secret are read from standard input (one per line), or
    /// asked for
    #[arg(long)]
    with_token: bool,
    /// The OAuth server to log in with for a --host, such as https://docspring.example.com (found from the host when
    /// it's left out)
    #[arg(long, value_name = "URL")]
    issuer: Option<String>,
    /// Print the login link without opening a browser
    #[arg(long)]
    no_browser: bool,
}

/// Log out: revoke a login's tokens and delete the profile
#[derive(Debug, Args)]
pub struct LogoutArgs {}

/// Your saved profiles
#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// List the saved profiles
    List,
    /// Make a profile the default, which commands use when you don't name one
    Use {
        /// The profile's name
        name: String,
    },
    /// Delete a profile and its saved credentials (a login's tokens are revoked)
    Remove {
        /// The profile's name
        name: String,
    },
}

/// Show the saved profiles and which credentials commands use
#[derive(Debug, Args)]
pub struct StatusArgs {}

impl ProfilesCommand {
    pub async fn run(self, runner: &Runner) -> CommandResult {
        match self {
            ProfilesCommand::List => list_profiles(runner, false),
            ProfilesCommand::Use { name } => {
                let dir = config_dir()?;
                // Logins and logouts change the config under the same lock
                let _lock = secrets::lock(&dir).await?;
                let mut config = Config::load(&dir)?;
                config.profile(&name)?;
                config.default_profile = Some(name.clone());
                config.save(&dir)?;
                runner.notice(&format!("Commands now use profile {name}."));
                Ok(())
            }
            ProfilesCommand::Remove { name } => remove_profile(runner, &name).await,
        }
    }
}

pub async fn status(runner: &Runner, _args: StatusArgs) -> CommandResult {
    list_profiles(runner, true)
}

pub async fn login(runner: &Runner, args: LoginArgs) -> CommandResult {
    let name = runner.global.profile.clone().unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    check_profile_name(&name)?;
    let dir = config_dir()?;
    let config = Config::load(&dir)?;
    let LoginServer { region, host, issuer } = login_server(
        &runner.global,
        args.issuer.as_deref(),
        config.profiles.get(&name),
        session::env_var("DOCSPRING_HOST"),
        session::env_var("DOCSPRING_REGION"),
    )?;
    let store = SecretStore::new(&dir)?;
    let (profile, secret) = if args.with_token {
        token_login(runner, region, host).await?
    } else {
        browser_login(runner, &args, issuer, region, host).await?
    };
    let location = profile.location();
    let kind = profile.credential.clone();
    // The config and credentials as they are now, under the lock: another command (a login in another terminal,
    // `profiles use`) may have changed them while this one waited for the browser
    let (saved, config, replaced) = {
        let _lock = secrets::lock(&dir).await?;
        let mut config = Config::load(&dir)?;
        let previous = store.get(&name).ok().flatten();
        let replaced = match (previous, config.profiles.get(&name)) {
            (
                Some(Secret::Login {
                    refresh_token: Some(token), ..
                }),
                Some(Profile { issuer: Some(issuer), .. }),
            ) => Some((issuer.clone(), token)),
            _ => None,
        };
        let saved = store.set(&name, &secret)?;
        if config.default_profile.is_none() {
            config.default_profile = Some(name.clone());
        }
        config.profiles.insert(name.clone(), profile);
        config.save(&dir)?;
        (saved, config, replaced)
    };
    // A login this one replaces would otherwise stay valid until it expires
    if let Some((issuer, token)) = replaced {
        revoke_quietly(&issuer, &token).await;
    }

    if let Saved::File(path, reason) = saved {
        runner.notice(&match reason {
            Some(reason) => format!(
                "No keychain to keep it in ({reason}), so it's in {}, readable only by you.",
                path.display()
            ),
            None => format!("It's in {}, readable only by you (DOCSPRING_CREDENTIAL_STORE=file).", path.display()),
        });
    }
    let default = if config.default_profile.as_deref() == Some(name.as_str()) {
        "the default".to_owned()
    } else {
        format!("use it with --profile {name}")
    };
    runner.notice(&format!(
        "Saved the {} for DocSpring {location} as profile {name} ({default}).",
        kind.label()
    ));
    if runner.global.json {
        runner.print(&json!({ "profile": name, "credential": kind, "location": location }), None);
    }
    Ok(())
}

/// The server a login goes to, and the OAuth server a browser login uses
#[derive(Debug, PartialEq)]
struct LoginServer {
    region: Option<String>,
    host: Option<String>,
    issuer: Option<String>,
}

/// The server a flag names, or the profile's last login's, or DOCSPRING_HOST's or DOCSPRING_REGION's (the variables
/// that go with an API token in the environment), or the US. Logging in to a host again uses the --issuer its last login
/// was given.
fn login_server(
    global: &crate::GlobalArgs,
    issuer: Option<&str>,
    existing: Option<&Profile>,
    env_host: Option<String>,
    env_region: Option<String>,
) -> Result<LoginServer, CliError> {
    let (region, host) = match (&global.region, &global.host) {
        (None, None) => match (existing, env_host, env_region) {
            (Some(profile), _, _) => (profile.region.clone(), profile.host.clone()),
            (None, Some(host), _) => (None, Some(host)),
            (None, None, Some(region)) => match region.to_uppercase().as_str() {
                region @ ("US" | "EU") => (Some(region.to_owned()), None),
                _ => return Err(CliError::usage(format!("DOCSPRING_REGION is {region:?}: it can be US or EU"))),
            },
            (None, None, None) => (Some("US".to_owned()), None),
        },
        (region, host) => (region.as_ref().map(|region| region.to_uppercase()), host.clone()),
    };
    if issuer.is_some() && host.is_none() {
        return Err(CliError::usage("--issuer is for logging in to a --host"));
    }
    let same_host = |profile: &&Profile| match (&profile.host, &host) {
        (Some(saved), Some(host)) => session::api_base(saved).eq_ignore_ascii_case(&session::api_base(host)),
        _ => false,
    };
    let issuer = issuer
        .map(str::to_owned)
        .or_else(|| existing.filter(same_host).and_then(|profile| profile.issuer.clone()));
    Ok(LoginServer { region, host, issuer })
}

async fn browser_login(
    runner: &Runner,
    args: &LoginArgs,
    issuer: Option<String>,
    region: Option<String>,
    host: Option<String>,
) -> Result<(Profile, Secret), CliError> {
    let http = session::http_client()?;
    let issuer = match (&issuer, &host) {
        (Some(issuer), _) => session::origin(issuer),
        (None, Some(host)) => session::origin(host),
        (None, None) => session::region_issuer(region.as_deref()).to_owned(),
    };
    let metadata = oauth::discover(&http, &issuer).await?;
    let open_browser = !args.no_browser;
    if open_browser {
        runner.notice(&format!("Opening {issuer} in your browser to log in..."));
    }
    let quiet = runner.global.quiet;
    let tokens = oauth::authorize(&http, &metadata, open_browser, |url| {
        if !open_browser {
            // Even with --quiet: the login can't finish without the link
            eprintln!("To log in to {issuer}, open this link in a browser:\n\n  {url}\n");
        } else if !quiet {
            eprintln!("If it doesn't open, go to:\n\n  {url}\n");
        }
    })
    .await
    .map_err(|error| {
        if error.message.contains("client_id") || error.message.contains("invalid_client") {
            CliError::auth(format!(
                "{issuer} doesn't know the DocSpring CLI: a DocSpring Enterprise install needs the release that added \
                 the CLI, or a later one."
            ))
        } else {
            error
        }
    })?;
    let profile = Profile {
        credential: CredentialKind::Login,
        region: if host.is_some() { None } else { region },
        host,
        issuer: Some(metadata.issuer.clone()),
        scope: tokens.scope.clone(),
        token_id: None,
        unknown: Default::default(),
    };
    let secret = Secret::Login {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_in.map(|seconds| session::now() + seconds),
    };
    Ok((profile, secret))
}

async fn token_login(runner: &Runner, region: Option<String>, host: Option<String>) -> Result<(Profile, Secret), CliError> {
    let (token_id, token_secret) = read_token()?;
    // Check it before saving it
    let api_base = session::api_base(&session::api_host(host.clone(), region.clone())?);
    let configuration = docspring::Configuration {
        base_path: api_base.clone(),
        user_agent: Some(session::user_agent()),
        client: session::http_client()?,
        basic_auth: Some((token_id.clone(), Some(token_secret.clone()))),
        oauth_access_token: None,
        bearer_access_token: None,
        api_key: None,
        validate_requests: true,
    };
    let client = docspring::Client::new(Arc::new(configuration));
    client.test_authentication().await.map_err(|error| match &error {
        // A server without API v2: an Enterprise install from before the CLI, or a --host that isn't DocSpring
        docspring::Error::ResponseError(response) if response.status.as_u16() == 404 => CliError::api(format!(
            "{api_base}/authentication responded 404: check --host. A DocSpring Enterprise install needs the release \
             that added the DocSpring CLI, or a later one: the CLI calls API v2, which came in the same release."
        )),
        _ => CliError::from_sdk(error),
    })?;
    if token_id.starts_with("api_test_") {
        runner.notice("That's a test API token: it makes test submissions only.");
    }
    let profile = Profile {
        credential: CredentialKind::ApiToken,
        region: if host.is_some() { None } else { region },
        host,
        issuer: None,
        scope: None,
        token_id: Some(token_id),
        unknown: Default::default(),
    };
    Ok((profile, Secret::ApiToken { token_secret }))
}

/// An API token's ID and secret: two lines on standard input, or asked for in a terminal (the secret isn't echoed)
fn read_token() -> Result<(String, String), CliError> {
    let stdin = std::io::stdin();
    let (token_id, token_secret) = if stdin.is_terminal() {
        eprint!("API token ID: ");
        std::io::stderr().flush()?;
        let mut token_id = String::new();
        stdin.lock().read_line(&mut token_id)?;
        let token_secret = rpassword::prompt_password("API token secret: ")?;
        (token_id, token_secret)
    } else {
        let mut lines = stdin.lock().lines();
        let mut next = |what: &str| -> Result<String, CliError> {
            match lines.next() {
                Some(line) => Ok(line?),
                None => Err(CliError::usage(format!(
                    "Standard input ended before the API token's {what}: send its ID and secret on two lines"
                ))),
            }
        };
        (next("ID")?, next("secret")?)
    };
    let (token_id, token_secret) = (token_id.trim().to_owned(), token_secret.trim().to_owned());
    if token_id.is_empty() || token_secret.is_empty() {
        return Err(CliError::usage("The API token's ID and secret can't be empty"));
    }
    Ok((token_id, token_secret))
}

pub async fn logout(runner: &Runner, _args: LogoutArgs) -> CommandResult {
    let dir = config_dir()?;
    let config = Config::load(&dir)?;
    let name = match runner.global.profile.clone().or(config.default_profile.clone()) {
        Some(name) => name,
        None => return Err(CliError::usage("You're not logged in to any profile")),
    };
    remove_profile(runner, &name).await
}

async fn remove_profile(runner: &Runner, name: &str) -> CommandResult {
    let dir = config_dir()?;
    let store = SecretStore::new(&dir)?;
    // Under the lock to the end: a login in another terminal saves its profile under it too
    let _lock = secrets::lock(&dir).await?;
    let mut config = Config::load(&dir)?;
    let profile = config.profile(name)?.clone();
    // This version can't revoke the newer one's credentials, and deleting them would leave them working
    if let CredentialKind::Other(kind) = &profile.credential {
        return Err(saved_by_newer_cli(name, kind));
    }
    {
        // A keychain that can't be read or changed fails the command, which leaves the profile as it was: the login's
        // tokens would otherwise stay saved, and valid
        let keychain_failed = |error: CliError, outcome: &str| {
            let message = error.message.trim_end_matches('.').to_owned();
            CliError::api(format!("{message}. {outcome}: run the command again once the keychain can be used."))
        };
        let secret = store.get(name).map_err(|error| keychain_failed(error, "Nothing was changed"))?;
        if let (
            Some(Secret::Login {
                refresh_token, access_token, ..
            }),
            Some(issuer),
        ) = (secret, &profile.issuer)
        {
            // Revoking the refresh token ends the login's session, with its access tokens
            let revoked = match refresh_token {
                Some(token) => revoke(issuer, &token, "refresh_token").await,
                None => revoke(issuer, &access_token, "access_token").await,
            };
            if let Err(error) = revoked {
                runner.notice(&format!(
                    "Couldn't revoke the login's tokens ({}). They stop working when they expire, or when you disconnect \
                     the DocSpring CLI on the Integrations page in DocSpring.",
                    error.message
                ));
            }
        }
        store
            .delete(name)
            .map_err(|error| keychain_failed(error, &format!("Profile {name} is kept")))?;
    }
    config.profiles.remove(name);
    let was_default = config.default_profile.as_deref() == Some(name);
    if was_default {
        config.default_profile = None;
    }
    config.save(&dir)?;
    let mut message = format!("Logged out of profile {name}.");
    if profile.credential == CredentialKind::ApiToken {
        message.push_str(" The API token still works: delete it on the API Tokens page in DocSpring if you don't need it.");
    }
    if was_default && !config.profiles.is_empty() {
        message.push_str(" It was the default profile: choose another with `docspring profiles use <name>`.");
    }
    runner.notice(&message);
    Ok(())
}

async fn revoke(issuer: &str, token: &str, hint: &str) -> CommandResult {
    let http = session::http_client()?;
    let metadata = oauth::discover(&http, issuer).await?;
    let Some(endpoint) = metadata.revocation_endpoint else {
        return Ok(());
    };
    oauth::revoke(&http, &endpoint, token, hint).await
}

/// Revokes a login that a new one replaced. A failure leaves a token that expires by itself, so it's not an error.
async fn revoke_quietly(issuer: &str, refresh_token: &str) {
    let _ = revoke(issuer, refresh_token, "refresh_token").await;
}

/// Where a command's credentials come from
enum Source {
    Env,
    /// One of DOCSPRING_TOKEN_ID and DOCSPRING_TOKEN_SECRET without the other, which commands refuse
    IncompleteEnv,
    Profile(String),
}

fn list_profiles(runner: &Runner, with_source: bool) -> CommandResult {
    let dir = config_dir()?;
    let config = Config::load(&dir)?;
    // The credentials Session::resolve picks
    let env_token = session::env_var("DOCSPRING_TOKEN_ID");
    let env_secret = session::env_var("DOCSPRING_TOKEN_SECRET");
    let source = match (session::named_profile(&runner.global), &env_token, &env_secret) {
        (Some(name), _, _) => Some(Source::Profile(name)),
        (None, Some(_), Some(_)) => Some(Source::Env),
        (None, None, None) => config.default_profile.clone().map(Source::Profile),
        (None, _, _) => Some(Source::IncompleteEnv),
    };
    let rows: Vec<serde_json::Value> = config
        .profiles
        .iter()
        .map(|(name, profile)| {
            json!({
                "name": name,
                "default": config.default_profile.as_deref() == Some(name.as_str()),
                "credential": profile.credential,
                "location": profile.location(),
                "token_id": profile.token_id,
                "test_token": profile.token_id.as_deref().map(|id| id.starts_with("api_test_")),
                "scope": profile.scope,
            })
        })
        .collect();
    let used = match &source {
        Some(Source::Env) => json!({ "source": "env", "token_id": env_token }),
        Some(Source::IncompleteEnv) => json!({ "source": "env", "token_id": env_token, "error": session::INCOMPLETE_ENV_TOKEN }),
        Some(Source::Profile(name)) => json!({ "source": "profile", "profile": name }),
        None => serde_json::Value::Null,
    };
    if runner.global.json {
        let mut value = json!({ "profiles": rows });
        if with_source {
            value["used"] = used;
        }
        runner.print(&value, None);
        return Ok(());
    }
    if runner.global.quiet {
        return Ok(());
    }
    if with_source {
        match &source {
            Some(Source::Env) => output::line(&format!(
                "Commands use the API token in DOCSPRING_TOKEN_ID ({}).",
                env_token.as_deref().unwrap_or_default()
            )),
            Some(Source::IncompleteEnv) => output::line(&format!("Commands fail: {}.", session::INCOMPLETE_ENV_TOKEN)),
            Some(Source::Profile(name)) => output::line(&format!("Commands use profile {name}.")),
            None => output::line("You're not logged in: run `docspring login`."),
        }
        if !rows.is_empty() {
            output::line("");
        }
    }
    if rows.is_empty() {
        if !with_source {
            output::line("No saved profiles: `docspring login` saves one.");
        }
        return Ok(());
    }
    let display: Vec<serde_json::Value> = config
        .profiles
        .iter()
        .map(|(name, profile)| {
            let default = if config.default_profile.as_deref() == Some(name.as_str()) {
                " (default)"
            } else {
                ""
            };
            let details = match profile.credential {
                CredentialKind::Login => profile.scope.clone().map(|scope| format!("access: {scope}")).unwrap_or_default(),
                CredentialKind::ApiToken => {
                    let id = profile.token_id.clone().unwrap_or_default();
                    if id.starts_with("api_test_") {
                        format!("{id} (test)")
                    } else {
                        id
                    }
                }
                CredentialKind::Other(_) => "saved by a newer version of the CLI".to_owned(),
            };
            json!({
                "profile": format!("{name}{default}"),
                "credential": profile.credential.label(),
                "server": profile.location(),
                "details": details,
            })
        })
        .collect();
    crate::output::table(
        &json!({ "data": display }),
        &Table {
            rows: "data",
            columns: &["profile", "credential", "server", "details"],
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global(region: Option<&str>, host: Option<&str>) -> crate::GlobalArgs {
        crate::GlobalArgs {
            region: region.map(str::to_owned),
            host: host.map(str::to_owned),
            ..crate::GlobalArgs::default()
        }
    }

    fn server(region: Option<&str>, host: Option<&str>, issuer: Option<&str>) -> LoginServer {
        LoginServer {
            region: region.map(str::to_owned),
            host: host.map(str::to_owned),
            issuer: issuer.map(str::to_owned),
        }
    }

    fn profile(region: Option<&str>, host: Option<&str>, issuer: Option<&str>) -> Profile {
        Profile {
            credential: CredentialKind::Login,
            region: region.map(str::to_owned),
            host: host.map(str::to_owned),
            issuer: issuer.map(str::to_owned),
            scope: None,
            token_id: None,
            unknown: Default::default(),
        }
    }

    #[test]
    fn a_new_login_uses_the_environments_region_or_host_when_no_flag_names_one() {
        let env = |name: &str| Some(name.to_owned());
        assert_eq!(
            login_server(&global(None, None), None, None, None, None).unwrap(),
            server(Some("US"), None, None)
        );
        assert_eq!(
            login_server(&global(None, None), None, None, None, env("eu")).unwrap(),
            server(Some("EU"), None, None)
        );
        assert_eq!(
            login_server(&global(None, None), None, None, env("docspring.example.com"), env("EU")).unwrap(),
            server(None, Some("docspring.example.com"), None)
        );
        assert_eq!(
            login_server(&global(Some("us"), None), None, None, None, env("EU")).unwrap(),
            server(Some("US"), None, None)
        );
        let error = login_server(&global(None, None), None, None, None, env("AU")).unwrap_err();
        assert_eq!(error.message, "DOCSPRING_REGION is \"AU\": it can be US or EU");

        // Logging in to a profile again goes to its server
        let eu = profile(Some("EU"), None, Some("https://app-eu.docspring.com"));
        assert_eq!(
            login_server(&global(None, None), None, Some(&eu), None, env("US")).unwrap(),
            server(Some("EU"), None, None)
        );
    }

    #[test]
    fn logging_in_to_a_host_again_uses_its_last_issuer() {
        let enterprise = profile(None, Some("api.docspring.example.com"), Some("https://docspring.example.com"));
        let issuer = Some("https://docspring.example.com");
        assert_eq!(
            login_server(&global(None, None), None, Some(&enterprise), None, None).unwrap(),
            server(None, Some("api.docspring.example.com"), issuer)
        );
        assert_eq!(
            login_server(
                &global(None, Some("https://API.docspring.example.com/")),
                None,
                Some(&enterprise),
                None,
                None
            )
            .unwrap(),
            server(None, Some("https://API.docspring.example.com/"), issuer)
        );
        // --issuer replaces it, and another host doesn't use it
        assert_eq!(
            login_server(&global(None, None), Some("https://sso.example.com"), Some(&enterprise), None, None).unwrap(),
            server(None, Some("api.docspring.example.com"), Some("https://sso.example.com"))
        );
        assert_eq!(
            login_server(&global(None, Some("other.example.com")), None, Some(&enterprise), None, None).unwrap(),
            server(None, Some("other.example.com"), None)
        );
        assert_eq!(
            login_server(&global(Some("EU"), None), None, Some(&enterprise), None, None).unwrap(),
            server(Some("EU"), None, None)
        );
        let error = login_server(&global(Some("EU"), None), Some("https://sso.example.com"), None, None, None).unwrap_err();
        assert_eq!(error.message, "--issuer is for logging in to a --host");
    }
}
