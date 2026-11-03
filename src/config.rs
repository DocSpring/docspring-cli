//! The config file, config.toml: the saved profiles and which one is the default. It never holds secrets: a profile's
//! tokens are in the keychain, or in credentials.toml (secrets.rs).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::CliError;

pub const DEFAULT_PROFILE: &str = "default";

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// The profile commands use when no profile or API token is given
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

/// Where a profile's requests go and which kind of credential it has
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub credential: CredentialKind,
    /// US or EU, for DocSpring's own servers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Another host, such as a DocSpring Enterprise install's
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// A login's OAuth server (its issuer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// A login's access, the scopes chosen on the consent screen
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// An API token's ID (its secret is stored with the secrets)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// OAuth tokens from `docspring login`
    Login,
    /// An API token saved with `docspring login --with-token`
    ApiToken,
}

impl CredentialKind {
    pub fn label(self) -> &'static str {
        match self {
            CredentialKind::Login => "login",
            CredentialKind::ApiToken => "API token",
        }
    }
}

impl Profile {
    /// Where the profile's requests go, as `auth status` shows it
    pub fn location(&self) -> String {
        match (&self.host, &self.region) {
            (Some(host), _) => host.clone(),
            (None, Some(region)) => region.to_uppercase(),
            (None, None) => "US".to_owned(),
        }
    }
}

/// The directory that holds config.toml and credentials.toml: DOCSPRING_CONFIG_DIR, or `docspring` in
/// $XDG_CONFIG_HOME (~/.config) on macOS and Linux, and in %APPDATA% on Windows
pub fn config_dir() -> Result<PathBuf, CliError> {
    if let Some(dir) = std::env::var_os("DOCSPRING_CONFIG_DIR").filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    default_config_dir()
}

/// The config directory when DOCSPRING_CONFIG_DIR isn't set
pub fn default_config_dir() -> Result<PathBuf, CliError> {
    if cfg!(windows) {
        return std::env::var_os("APPDATA")
            .filter(|dir| !dir.is_empty())
            .map(|dir| PathBuf::from(dir).join("docspring"))
            .ok_or_else(|| CliError::usage("Couldn't find your AppData folder: set DOCSPRING_CONFIG_DIR"));
    }
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|dir| dir.is_absolute());
    match xdg {
        Some(dir) => Ok(dir.join("docspring")),
        None => std::env::home_dir()
            .map(|home| home.join(".config").join("docspring"))
            .ok_or_else(|| CliError::usage("Couldn't find your home directory: set DOCSPRING_CONFIG_DIR")),
    }
}

impl Config {
    pub fn load(dir: &Path) -> Result<Config, CliError> {
        let path = dir.join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|error| CliError::usage(format!("{} isn't valid: {error}", path.display()))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(error) => Err(CliError::api(format!("Couldn't read {}: {error}", path.display()))),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), CliError> {
        let text = toml::to_string_pretty(self).expect("the config serializes");
        write_file(&dir.join("config.toml"), text.as_bytes(), false)
    }

    pub fn profile(&self, name: &str) -> Result<&Profile, CliError> {
        self.profiles.get(name).ok_or_else(|| {
            CliError::auth(format!(
                "There's no profile named {name}. `docspring profiles list` shows the saved profiles, and \
                 `docspring login --profile {name}` saves one."
            ))
        })
    }
}

/// A profile's name goes in file names and keychain entries: letters, digits, `-`, `_` and `.`
pub fn check_profile_name(name: &str) -> Result<(), CliError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if valid {
        Ok(())
    } else {
        Err(CliError::usage(format!(
            "{name:?} can't be a profile name: use letters, digits, -, _ and ., up to 64 characters"
        )))
    }
}

/// Writes a file in one step (a temporary file, then a rename), so a command that reads it at the same time sees the
/// old or the new contents. `private` files are readable only by you.
pub fn write_file(path: &Path, contents: &[u8], private: bool) -> Result<(), CliError> {
    let failed = |error: std::io::Error| CliError::api(format!("Couldn't write {}: {error}", path.display()));
    let dir = path.parent().expect("config files are in a directory");
    std::fs::create_dir_all(dir).map_err(failed)?;
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().expect("config files have names").to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        // The temporary file is ours, and nothing else will clean it up
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_saves_and_loads_profiles() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Config::load(dir.path()).unwrap(), Config::default());
        let mut config = Config {
            default_profile: Some("work".to_owned()),
            ..Config::default()
        };
        config.profiles.insert(
            "work".to_owned(),
            Profile {
                credential: CredentialKind::Login,
                region: Some("EU".to_owned()),
                host: None,
                issuer: Some("https://app-eu.docspring.com".to_owned()),
                scope: Some("read write".to_owned()),
                token_id: None,
            },
        );
        config.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        assert!(text.contains("default_profile = \"work\""), "{text}");
        assert!(text.contains("credential = \"login\""), "{text}");
        assert_eq!(Config::load(dir.path()).unwrap(), config);
    }

    #[test]
    fn a_bad_config_file_says_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), "default_profile = [").unwrap();
        let error = Config::load(dir.path()).unwrap_err();
        assert!(error.message.contains("config.toml isn't valid"), "{}", error.message);
    }

    #[test]
    fn profile_names_are_safe_in_file_names() {
        for name in ["default", "work-eu", "ci_1", "staging.local"] {
            check_profile_name(name).unwrap();
        }
        for name in ["", "../x", "a/b", ".hidden", "with space", &"x".repeat(65)] {
            assert!(check_profile_name(name).is_err(), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_readable_only_by_you() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("credentials.toml");
        write_file(&path, b"secret", true).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }
}
