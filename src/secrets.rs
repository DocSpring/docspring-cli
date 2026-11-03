//! Profiles' secrets: a login's tokens, or an API token's secret. They're kept in the OS keychain (the macOS Keychain,
//! Windows Credential Manager, the Secret Service on Linux). Without one, such as on a server with no desktop session,
//! they go in credentials.toml next to config.toml, readable only by you. DOCSPRING_CREDENTIAL_STORE=file always uses
//! the file, and DOCSPRING_CREDENTIAL_STORE=keychain never does. A config directory other than the default one
//! (DOCSPRING_CONFIG_DIR) keeps its own keychain entries, named after the directory.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{default_config_dir, write_file};
use crate::errors::CliError;

const KEYCHAIN_SERVICE: &str = "docspring-cli";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Secret {
    Login {
        access_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        /// When the access token expires, in seconds since 1970
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<i64>,
    },
    ApiToken {
        token_secret: String,
    },
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secret::Login { expires_at, .. } => f.debug_struct("Login").field("expires_at", expires_at).finish_non_exhaustive(),
            Secret::ApiToken { .. } => f.debug_struct("ApiToken").finish_non_exhaustive(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// The keychain when there is one, the file otherwise
    Auto,
    Keychain,
    File,
}

/// Where a secret was saved
#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    Keychain,
    /// The file, and why the keychain couldn't be used (None when DOCSPRING_CREDENTIAL_STORE=file)
    File(PathBuf, Option<String>),
}

pub struct SecretStore {
    file: PathBuf,
    mode: Mode,
    /// The config directory, when it isn't the default one: its keychain entries' names include it
    dir: Option<PathBuf>,
    keychain: Keychain,
}

#[derive(Default, Serialize, Deserialize)]
struct CredentialsFile {
    #[serde(default)]
    profiles: BTreeMap<String, Secret>,
}

impl SecretStore {
    /// A store that keeps secrets in `dir`'s credentials.toml only, whatever DOCSPRING_CREDENTIAL_STORE says
    #[cfg(test)]
    pub fn file_only(dir: &Path) -> SecretStore {
        SecretStore {
            file: dir.join("credentials.toml"),
            mode: Mode::File,
            dir: None,
            keychain: Keychain::Os,
        }
    }

    /// A store in `dir` whose keychain is `keychain`
    #[cfg(test)]
    fn with_fake_keychain(dir: &Path, keychain: &std::sync::Arc<FakeKeychain>) -> SecretStore {
        SecretStore {
            file: dir.join("credentials.toml"),
            mode: Mode::Auto,
            dir: None,
            keychain: Keychain::Fake(keychain.clone()),
        }
    }

    pub fn new(dir: &Path) -> Result<SecretStore, CliError> {
        let mode = match std::env::var("DOCSPRING_CREDENTIAL_STORE").ok().as_deref().map(str::trim) {
            None | Some("") => Mode::Auto,
            Some("keychain") => Mode::Keychain,
            Some("file") => Mode::File,
            Some(other) => {
                return Err(CliError::usage(format!(
                    "DOCSPRING_CREDENTIAL_STORE is {other:?}: it can be keychain or file"
                )))
            }
        };
        let dir = std::path::absolute(dir).unwrap_or_else(|_| dir.to_owned());
        let default_dir = default_config_dir().ok().map(|default| std::path::absolute(&default).unwrap_or(default));
        Ok(SecretStore {
            file: dir.join("credentials.toml"),
            mode,
            dir: (Some(&dir) != default_dir.as_ref()).then_some(dir),
            keychain: Keychain::Os,
        })
    }

    /// The keychain entry's name for a profile: the profile's name, and the config directory when it isn't the
    /// default one, so a test or a script with its own DOCSPRING_CONFIG_DIR can't overwrite (and revoke) your logins
    fn keychain_account(&self, profile: &str) -> String {
        match &self.dir {
            Some(dir) => format!("{profile} ({})", dir.display()),
            None => profile.to_owned(),
        }
    }

    pub fn get(&self, profile: &str) -> Result<Option<Secret>, CliError> {
        let mut keychain_error = None;
        if self.mode != Mode::File {
            match self.keychain.get(&self.keychain_account(profile), profile) {
                Ok(Some(secret)) => return Ok(Some(secret)),
                Ok(None) => {}
                Err(error) if self.mode == Mode::Keychain => return Err(CliError::auth(error)),
                Err(error) => keychain_error = Some(error),
            }
        }
        if self.mode == Mode::Keychain {
            return Ok(None);
        }
        match self.read_file()?.profiles.remove(profile) {
            Some(secret) => Ok(Some(secret)),
            // Nothing in the file either: the keychain's error says why nothing was found
            None => match keychain_error {
                Some(error) if self.keychain.available() => Err(CliError::auth(error)),
                _ => Ok(None),
            },
        }
    }

    pub fn set(&self, profile: &str, secret: &Secret) -> Result<Saved, CliError> {
        let account = self.keychain_account(profile);
        let mut reason = None;
        if self.mode != Mode::File {
            match self.keychain.set(&account, profile, secret) {
                Ok(()) => {
                    // A copy saved in the file before the keychain worked would be found by nothing, but it's a secret
                    self.remove_from_file(profile)?;
                    return Ok(Saved::Keychain);
                }
                Err(error) if self.mode == Mode::Keychain => return Err(CliError::auth(error)),
                Err(error) => reason = Some(error),
            }
        }
        let mut file = self.read_file()?;
        file.profiles.insert(profile.to_owned(), secret.clone());
        self.write_file(&file)?;
        if let Some(error) = &reason {
            // get reads the keychain first, so an older entry there would hide the secret just saved (a refresh token
            // the server has since replaced)
            if let Err(stale) = self.keychain.delete(&account, profile) {
                if self.keychain.available() {
                    return Err(CliError::auth(format!(
                        "{error}, and its old entry there couldn't be deleted either ({stale}). Run `docspring login` \
                         again once the keychain can be used."
                    )));
                }
            }
        }
        Ok(Saved::File(self.file.clone(), reason))
    }

    /// Deletes a profile's secret from the file and the keychain. A keychain that's there but fails is an error, so
    /// a secret is never left behind without a word.
    pub fn delete(&self, profile: &str) -> Result<(), CliError> {
        if self.mode != Mode::Keychain {
            self.remove_from_file(profile)?;
        }
        if self.mode != Mode::File {
            if let Err(error) = self.keychain.delete(&self.keychain_account(profile), profile) {
                // Without a keychain, the secret could only be in the file
                if self.mode == Mode::Keychain || self.keychain.available() {
                    return Err(CliError::auth(error));
                }
            }
        }
        Ok(())
    }

    fn remove_from_file(&self, profile: &str) -> Result<(), CliError> {
        if !self.file.exists() {
            return Ok(());
        }
        let mut file = self.read_file()?;
        if file.profiles.remove(profile).is_some() {
            self.write_file(&file)?;
        }
        Ok(())
    }

    fn read_file(&self) -> Result<CredentialsFile, CliError> {
        match std::fs::read_to_string(&self.file) {
            Ok(text) => toml::from_str(&text).map_err(|error| {
                // Not toml's message: it quotes the line, which can hold a token
                let line = error.span().map(|span| text[..span.start].matches('\n').count() + 1);
                CliError::auth(format!(
                    "{} isn't valid TOML{}. Fix it, or delete it and log in again.",
                    self.file.display(),
                    line.map(|line| format!(" (line {line})")).unwrap_or_default()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CredentialsFile::default()),
            Err(error) => Err(CliError::auth(format!("Couldn't read {}: {error}", self.file.display()))),
        }
    }

    fn write_file(&self, file: &CredentialsFile) -> Result<(), CliError> {
        let text = toml::to_string_pretty(file).expect("credentials serialize");
        write_file(&self.file, text.as_bytes(), true)
    }
}

/// The OS keychain, or in tests an in-memory one whose calls can be made to fail
enum Keychain {
    Os,
    #[cfg(test)]
    Fake(std::sync::Arc<FakeKeychain>),
}

impl Keychain {
    fn available(&self) -> bool {
        match self {
            Keychain::Os => keyring::Entry::store_status().is_ok(),
            #[cfg(test)]
            Keychain::Fake(_) => true,
        }
    }

    fn get(&self, account: &str, profile: &str) -> Result<Option<Secret>, String> {
        let json = match self {
            Keychain::Os => match os_entry(account)?.get_password() {
                Ok(json) => json,
                Err(keyring::Error::NoEntry) => return Ok(None),
                Err(error) => return Err(format!("Couldn't read profile {profile}'s credentials from the keychain: {error}")),
            },
            #[cfg(test)]
            Keychain::Fake(fake) => match fake.call("read", profile, |entries| entries.get(account).cloned())? {
                Some(json) => json,
                None => return Ok(None),
            },
        };
        serde_json::from_str(&json)
            .map(Some)
            .map_err(|error| format!("The keychain's entry for profile {profile} isn't valid: {error}"))
    }

    fn set(&self, account: &str, profile: &str, secret: &Secret) -> Result<(), String> {
        let json = serde_json::to_string(secret).expect("secrets serialize");
        match self {
            Keychain::Os => os_entry(account)?
                .set_password(&json)
                .map_err(|error| format!("Couldn't save profile {profile}'s credentials in the keychain: {error}")),
            #[cfg(test)]
            Keychain::Fake(fake) => fake.call("save", profile, |entries| {
                entries.insert(account.to_owned(), json);
            }),
        }
    }

    fn delete(&self, account: &str, profile: &str) -> Result<(), String> {
        match self {
            Keychain::Os => match os_entry(account)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(format!("Couldn't delete profile {profile}'s credentials from the keychain: {error}")),
            },
            #[cfg(test)]
            Keychain::Fake(fake) => fake.call("delete", profile, |entries| {
                entries.remove(account);
            }),
        }
    }
}

fn os_entry(account: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|error| format!("The keychain isn't available: {error}"))
}

#[cfg(test)]
#[derive(Default)]
struct FakeKeychain {
    entries: std::sync::Mutex<BTreeMap<String, String>>,
    /// The calls that fail: read, save or delete
    failing: std::sync::Mutex<Vec<&'static str>>,
}

#[cfg(test)]
impl FakeKeychain {
    fn fail(&self, calls: &[&'static str]) {
        *self.failing.lock().unwrap() = calls.to_vec();
    }

    fn call<T>(&self, name: &str, profile: &str, f: impl FnOnce(&mut BTreeMap<String, String>) -> T) -> Result<T, String> {
        if self.failing.lock().unwrap().contains(&name) {
            return Err(format!("Couldn't {name} profile {profile}'s credentials in the keychain: denied"));
        }
        Ok(f(&mut self.entries.lock().unwrap()))
    }
}

/// Held while a command refreshes a login's tokens or changes saved secrets, so two commands never refresh the same
/// login at once: the server revokes every token of a login whose old refresh token is used after the new one. Locks
/// are released when the process exits, even when it crashes.
pub struct CredentialsLock {
    _file: std::fs::File,
}

pub async fn lock(dir: &Path) -> Result<CredentialsLock, CliError> {
    let path = dir.join("credentials.lock");
    tokio::task::spawn_blocking(move || {
        use fs4::fs_std::FileExt;
        let failed = |error: std::io::Error| CliError::auth(format!("Couldn't lock {}: {error}", path.display()));
        std::fs::create_dir_all(path.parent().expect("the lock file is in a directory")).map_err(failed)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(failed)?;
        // Another command holds it while it refreshes, which takes a second or two
        for _ in 0..600 {
            if file.try_lock_exclusive().map_err(failed)? {
                return Ok(CredentialsLock { _file: file });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(CliError::auth(format!(
            "Another docspring command has held {} for a minute: stop it, or try again",
            path.display()
        )))
    })
    .await
    .expect("the lock task doesn't panic")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_credentials_file_is_reported_without_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("credentials.toml"),
            "[profiles.default]\nkind = \"login\"\naccess_token = \"secret-access-token\n",
        )
        .unwrap();
        let error = SecretStore::file_only(dir.path()).get("default").unwrap_err();
        assert!(
            error
                .message
                .ends_with("credentials.toml isn't valid TOML (line 3). Fix it, or delete it and log in again."),
            "{}",
            error.message
        );
        assert!(!error.message.contains("secret"), "{}", error.message);
    }

    #[test]
    fn the_file_store_keeps_each_profiles_secret() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::file_only(dir.path());
        assert_eq!(store.get("default").unwrap(), None);
        let login = Secret::Login {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at: Some(1_900_000_000),
        };
        let token = Secret::ApiToken {
            token_secret: "secret".to_owned(),
        };
        assert_eq!(
            store.set("default", &login).unwrap(),
            Saved::File(dir.path().join("credentials.toml"), None)
        );
        store.set("ci", &token).unwrap();
        assert_eq!(store.get("default").unwrap(), Some(login));
        assert_eq!(store.get("ci").unwrap(), Some(token.clone()));
        store.delete("default").unwrap();
        assert_eq!(store.get("default").unwrap(), None);
        assert_eq!(store.get("ci").unwrap(), Some(token));
    }

    fn login(access_token: &str) -> Secret {
        Secret::Login {
            access_token: access_token.to_owned(),
            refresh_token: Some(format!("{access_token}-refresh")),
            expires_at: Some(1_900_000_000),
        }
    }

    #[test]
    fn a_keychain_that_fails_to_read_or_delete_is_an_error_so_no_secret_is_left_behind_silently() {
        let dir = tempfile::tempdir().unwrap();
        let keychain = std::sync::Arc::new(FakeKeychain::default());
        let store = SecretStore::with_fake_keychain(dir.path(), &keychain);
        assert_eq!(store.set("default", &login("access")).unwrap(), Saved::Keychain);

        keychain.fail(&["read"]);
        let error = store.get("default").unwrap_err();
        assert_eq!(error.message, "Couldn't read profile default's credentials in the keychain: denied");

        keychain.fail(&["delete"]);
        let error = store.delete("default").unwrap_err();
        assert_eq!(error.message, "Couldn't delete profile default's credentials in the keychain: denied");
        keychain.fail(&[]);
        assert_eq!(store.get("default").unwrap(), Some(login("access")));
        store.delete("default").unwrap();
        assert_eq!(store.get("default").unwrap(), None);
    }

    #[test]
    fn a_secret_saved_to_the_file_deletes_the_older_one_in_the_keychain_that_would_hide_it() {
        let dir = tempfile::tempdir().unwrap();
        let keychain = std::sync::Arc::new(FakeKeychain::default());
        let store = SecretStore::with_fake_keychain(dir.path(), &keychain);
        store.set("default", &login("old")).unwrap();

        keychain.fail(&["save"]);
        let saved = store.set("default", &login("new")).unwrap();
        assert_eq!(
            saved,
            Saved::File(
                dir.path().join("credentials.toml"),
                Some("Couldn't save profile default's credentials in the keychain: denied".to_owned())
            )
        );
        assert_eq!(store.get("default").unwrap(), Some(login("new")));

        // The old entry can't be deleted either: the command fails, since the next one would read it
        keychain.fail(&[]);
        store.set("default", &login("old")).unwrap();
        keychain.fail(&["save", "delete"]);
        let error = store.set("default", &login("new")).unwrap_err();
        assert!(
            error.message.contains("its old entry there couldn't be deleted either"),
            "{}",
            error.message
        );
    }

    #[test]
    fn keychain_entries_name_a_config_directory_other_than_the_default() {
        let default = SecretStore::new(&default_config_dir().unwrap()).unwrap();
        assert_eq!(default.keychain_account("default"), "default");
        let dir = tempfile::tempdir().unwrap();
        let other = SecretStore::new(dir.path()).unwrap();
        assert_eq!(
            other.keychain_account("default"),
            format!("default ({})", std::path::absolute(dir.path()).unwrap().display())
        );
    }

    #[test]
    fn debug_hides_secrets() {
        let login = Secret::Login {
            access_token: "the-access-token".to_owned(),
            refresh_token: Some("the-refresh-token".to_owned()),
            expires_at: None,
        };
        let debug = format!(
            "{login:?} {:?}",
            Secret::ApiToken {
                token_secret: "the-secret".to_owned()
            }
        );
        assert!(!debug.contains("the-"), "{debug}");
    }

    #[tokio::test]
    async fn one_command_holds_the_lock_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock(dir.path()).await.unwrap();
        let path = dir.path().to_owned();
        let second = tokio::spawn(async move { lock(&path).await.map(|_| std::time::Instant::now()) });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let released = std::time::Instant::now();
        drop(first);
        let acquired = second.await.unwrap().unwrap();
        assert!(acquired >= released, "the second lock was taken while the first was held");
    }
}
