//! `docspring update`: replaces the CLI with a newer release from GitHub, checked against the release's SHA-256
//! checksums. An install that Homebrew or cargo manages is updated with them instead.

use std::path::Path;

use clap::Args;
use serde_json::json;

use crate::errors::CliError;
use crate::output;
use crate::runner::{CommandResult, Runner};

const REPO_OWNER: &str = "DocSpring";
const REPO_NAME: &str = "docspring-cli";

/// Update the CLI to the latest release, or to the version you name
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Only check: print the latest version, and whether this one is older
    #[arg(long)]
    check: bool,
    /// The version to install, such as 1.2.0
    #[arg(long, value_name = "VERSION")]
    version: Option<String>,
}

/// How the running executable was installed
#[derive(Debug, PartialEq, Eq)]
pub enum InstallSource {
    /// The installer script, a release archive, or a copy we can replace
    Standalone,
    Homebrew,
    Cargo,
}

pub async fn update(runner: &Runner, args: UpdateArgs) -> CommandResult {
    let current = crate::VERSION;
    if args.check {
        let latest = tokio::task::spawn_blocking(latest_version)
            .await
            .expect("the release check doesn't panic")?;
        let newer = is_newer(&latest, current);
        if runner.global.json {
            runner.print(&json!({ "current": current, "latest": latest, "update_available": newer }), None);
        } else if !runner.global.quiet {
            match newer {
                true => output::line(&format!(
                    "{latest} is available (you have {current}). Run `docspring update` to install it."
                )),
                false => output::line(&format!("{current} is the latest version.")),
            }
        }
        return Ok(());
    }
    if std::env::var_os("DOCSPRING_NO_SELF_UPDATE").is_some_and(|value| !value.is_empty()) {
        return Err(CliError::usage(
            "Updating is turned off for this install (DOCSPRING_NO_SELF_UPDATE): update it the way you installed it",
        ));
    }
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| CliError::api(format!("Couldn't find the docspring executable: {error}")))?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".cargo")));
    match install_source(&executable, cargo_home.as_deref()) {
        InstallSource::Homebrew => return Err(CliError::usage("Homebrew installed docspring: update it with `brew upgrade docspring`")),
        InstallSource::Cargo => {
            return Err(CliError::usage(
                "cargo installed docspring: update it with `cargo install --locked docspring-cli`",
            ))
        }
        InstallSource::Standalone => {}
    }
    // The release `--check` names, so the two agree: self_update's own choice prefers the same major version and
    // can pick a pre-release
    let version = match args.version.clone() {
        Some(version) => version.trim_start_matches('v').to_owned(),
        None => {
            let latest = tokio::task::spawn_blocking(latest_version)
                .await
                .expect("the release check doesn't panic")?;
            if !is_newer(&latest, current) {
                if runner.global.json {
                    runner.print(&json!({ "previous": current, "current": current, "updated": false }), None);
                } else {
                    runner.notice(&format!("{current} is the latest version."));
                }
                return Ok(());
            }
            latest
        }
    };
    let quiet = runner.global.quiet;
    let status = tokio::task::spawn_blocking(move || {
        let mut builder = self_update::backends::github::Update::configure();
        builder
            .repo_owner(REPO_OWNER)
            .repo_name(REPO_NAME)
            .bin_name("docspring")
            .bin_path_in_archive(archive_bin_path(cfg!(windows)))
            .current_version(crate::VERSION)
            .asset_matcher(|assets| select_asset(assets, self_update::get_target()))
            .checksum_from_asset("sha256.sum")
            .verify_release_digest(true)
            .show_download_progress(!quiet)
            .show_output(false)
            .no_confirm(true)
            // GH_TOKEN or GITHUB_TOKEN when one is set: GitHub allows 60 requests an hour per IP without one
            .auth_token_from_env()
            .release_tag(format!("v{version}"));
        builder.build()?.update()
    })
    .await
    .expect("the update doesn't panic")
    .map_err(|error| CliError::api(format!("The update failed: {error}")))?;
    let installed = status.version().to_owned();
    if runner.global.json {
        runner.print(
            &json!({ "previous": current, "current": installed, "updated": status.is_updated() }),
            None,
        );
    } else if status.is_updated() {
        runner.notice(&format!("Updated docspring from {current} to {installed}."));
    } else {
        runner.notice(&format!("{current} is the latest version."));
    }
    Ok(())
}

fn latest_version() -> Result<String, CliError> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .auth_token_from_env()
        .build()
        .and_then(|list| list.fetch())
        .map_err(|error| CliError::api(format!("Couldn't check for updates: {error}")))?;
    newest_stable((&releases).into_iter().map(|release| release.version())).ok_or_else(|| CliError::api("The DocSpring CLI has no releases yet"))
}

/// The highest version that isn't a pre-release (release candidates are for testing), skipping tags that aren't
/// versions
fn newest_stable<'a>(versions: impl Iterator<Item = &'a str>) -> Option<String> {
    versions
        .filter_map(|version| parse_version(version).map(|parsed| (parsed, version)))
        .filter(|(parsed, _)| parsed.pre.is_empty())
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, version)| version.trim_start_matches('v').to_owned())
}

/// The archive dist makes for a target: docspring-cli-<target>.tar.xz, or .zip for Windows (not its .sha256 files or
/// the installers)
pub fn select_asset(assets: &[self_update::update::ReleaseAsset], target: &str) -> Option<self_update::update::ReleaseAsset> {
    let extension = if target.contains("windows") { "zip" } else { "tar.xz" };
    let name = format!("{REPO_NAME}-{target}.{extension}");
    assets.iter().find(|asset| asset.name() == name).cloned()
}

/// Where the executable is in dist's archives: at the top of the Windows zips, in a directory in the tarballs.
/// self_update fills in `{{ bin }}` with the bin name, which already ends in .exe on Windows.
fn archive_bin_path(windows: bool) -> String {
    if windows {
        "{{ bin }}".to_owned()
    } else {
        format!("{REPO_NAME}-{{{{ target }}}}/{{{{ bin }}}}")
    }
}

pub fn install_source(executable: &Path, cargo_home: Option<&Path>) -> InstallSource {
    let path = executable.to_string_lossy();
    if path.contains("/Cellar/") || path.contains("/homebrew/") || path.contains("/linuxbrew/") {
        return InstallSource::Homebrew;
    }
    if let Some(cargo_home) = cargo_home {
        let cargo_bin = cargo_home.join("bin");
        let cargo_bin = cargo_bin.canonicalize().unwrap_or(cargo_bin);
        if executable.starts_with(&cargo_bin) {
            return InstallSource::Cargo;
        }
    }
    InstallSource::Standalone
}

fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

fn parse_version(version: &str) -> Option<semver::Version> {
    semver::Version::parse(version.trim_start_matches('v')).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> self_update::update::ReleaseAsset {
        self_update::update::ReleaseAsset::new(name, format!("https://example.com/{name}"))
    }

    #[test]
    fn it_picks_the_targets_archive() {
        let assets = vec![
            asset("docspring-cli-installer.sh"),
            asset("docspring-cli-aarch64-apple-darwin.tar.xz.sha256"),
            asset("docspring-cli-aarch64-apple-darwin.tar.xz"),
            asset("docspring-cli-x86_64-pc-windows-msvc.zip.sha256"),
            asset("docspring-cli-x86_64-pc-windows-msvc.zip"),
            asset("sha256.sum"),
        ];
        let pick = |target| select_asset(&assets, target).map(|asset| asset.name().to_owned());
        assert_eq!(pick("aarch64-apple-darwin").as_deref(), Some("docspring-cli-aarch64-apple-darwin.tar.xz"));
        assert_eq!(
            pick("x86_64-pc-windows-msvc").as_deref(),
            Some("docspring-cli-x86_64-pc-windows-msvc.zip")
        );
        assert_eq!(pick("x86_64-unknown-linux-musl"), None);
    }

    #[test]
    fn package_managers_update_their_own_installs() {
        let cargo_home = tempfile::tempdir().unwrap();
        let cargo_home = cargo_home.path().canonicalize().unwrap();
        assert_eq!(
            install_source(Path::new("/opt/homebrew/Cellar/docspring/1.0.0/bin/docspring"), None),
            InstallSource::Homebrew
        );
        assert_eq!(
            install_source(Path::new("/home/linuxbrew/.linuxbrew/bin/docspring"), None),
            InstallSource::Homebrew
        );
        assert_eq!(
            install_source(&cargo_home.join("bin").join("docspring"), Some(&cargo_home)),
            InstallSource::Cargo
        );
        assert_eq!(
            install_source(Path::new("/home/me/.docspring/bin/docspring"), Some(&cargo_home)),
            InstallSource::Standalone
        );
    }

    #[test]
    fn versions_compare_by_number() {
        assert!(is_newer("1.10.0", "1.9.3"));
        assert!(is_newer("v2.0.0", "1.99.99"));
        assert!(is_newer("1.0.0", "1.0.0-rc.1"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn the_latest_release_is_the_highest_stable_one() {
        let versions = ["1.2.0", "v1.10.0", "2.0.0-rc.1", "nightly", "1.9.9"];
        assert_eq!(newest_stable(versions.into_iter()).as_deref(), Some("1.10.0"));
        assert_eq!(newest_stable(["1.0.0-rc.1"].into_iter()), None);
    }

    #[test]
    fn the_executable_is_where_dist_puts_it() {
        assert_eq!(archive_bin_path(false), "docspring-cli-{{ target }}/{{ bin }}");
        // Not "{{ bin }}.exe": that looked for docspring.exe.exe
        assert_eq!(archive_bin_path(true), "{{ bin }}");
    }
}
