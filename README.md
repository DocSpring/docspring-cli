# DocSpring CLI

[![Release](https://img.shields.io/github/v/release/DocSpring/docspring-cli)](https://github.com/DocSpring/docspring-cli/releases/latest)
[![crates.io](https://img.shields.io/crates/v/docspring-cli)](https://crates.io/crates/docspring-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

`docspring` is DocSpring's command-line interface. DocSpring fills PDF and Word templates with your data, generates
PDFs from HTML templates and page designs, combines PDFs and collects e-signatures. The CLI has a command for every
operation in the [DocSpring API](https://docspring.com/docs/api/), for your terminal, scripts, CI jobs and AI agents.

[Documentation](https://docspring.com/docs/cli/) · [API reference](https://docspring.com/docs/api/) ·
[crates.io](https://crates.io/crates/docspring-cli) · [Changelog](CHANGELOG.md)

On top of the API's operations, the CLI logs in with your browser and keeps its tokens in your system's keychain,
checks a request against the API's schemas before it sends it, fills in a template and saves its PDF in one command
(`docspring submit`), gets every page of a list (`--all`), and checks files of generated types in CI. Its `--json`
output and exit statuses are made for scripts and AI agents.

The code in this repository comes from DocSpring's monorepo ([About this repository](#about-this-repository)). Issues
and pull requests are welcome.

## Install

```sh
# Homebrew (macOS and Linux)
brew install docspring/tap/docspring

# macOS and Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/DocSpring/docspring-cli/releases/latest/download/docspring-cli-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/DocSpring/docspring-cli/releases/latest/download/docspring-cli-installer.ps1 | iex"

# Cargo (Rust 1.88 or later)
cargo install --locked docspring-cli
```

The [releases](https://github.com/DocSpring/docspring-cli/releases) have binaries for macOS, Linux and Windows (x86_64
and ARM64), with their SHA-256 checksums and GitHub build attestations. `docspring --version` prints the version you
have, and `docspring update` updates an install from the installers or the releases.

## Log in

```sh
docspring login
```

This opens DocSpring in your browser, where you sign in and choose what the CLI can do. The tokens are kept in your
system's keychain. For an account in the EU, run `docspring login --region EU`. `docspring login --with-token` saves
an API token instead, and commands also read an API token from `DOCSPRING_TOKEN_ID` and `DOCSPRING_TOKEN_SECRET`.

## Use

```sh
docspring templates list
# --test makes a free test PDF, with a watermark
docspring submit tpl_1234567890abcdef01 --data '{"data": {"first_name": "Jane"}}' --test -o filled.pdf
docspring submissions download sub_1234567890abcdef01 --file audit-trail
docspring templates submissions tpl_1234567890abcdef01 --all --json
docspring exports download account_migration_index_mig_1234567890abcdef.json.gz
```

`docspring help` lists the commands, and `--help` after any command shows its options. `--json` prints the API's JSON
response, and the exit status says what went wrong ([Scripts, CI and AI agents](https://docspring.com/docs/cli/#scripts-ci-and-ai-agents)).
`docspring exports download` saves the account export that DocSpring support sends when you ask for a copy of your
account's data. The [documentation](https://docspring.com/docs/cli/) has more examples.

## GitHub Actions

```yaml
- uses: DocSpring/docspring-cli@v1
- run: docspring submit tpl_1234567890abcdef01 --data @data.json -o filled.pdf
  env:
    DOCSPRING_TOKEN_ID: ${{ secrets.DOCSPRING_TOKEN_ID }}
    DOCSPRING_TOKEN_SECRET: ${{ secrets.DOCSPRING_TOKEN_SECRET }}
```

For an account in the EU, add `DOCSPRING_REGION: EU` to `env`. `DocSpring/docspring-cli@v1` installs the newest 1.x
release, and the `version` input installs another one (`latest` for the newest).

## About this repository

The CLI is built on the [DocSpring Rust SDK](https://github.com/DocSpring/docspring-rust). Its API commands
(`src/commands.rs`) are generated from DocSpring's [OpenAPI spec](https://docspring.com/api-docs/v2/openapi.json), and
the rest of the code is written by hand. Both live in DocSpring's monorepo, which writes this repository for each
release, so we apply a pull request's changes there.

## Support and security

Open an [issue](https://github.com/DocSpring/docspring-cli/issues) or email support@docspring.com. Please report
security problems privately to security@docspring.com.

## License

MIT. See [LICENSE](LICENSE).
