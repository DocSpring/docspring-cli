### 1.0.1 [November 3, 2026]

- A profile's credentials only go to the server it was saved for. A command that uses a profile with `--region` or
  `--host` for another server now fails instead of sending them there.
- A command that runs while you log in to the same profile again, on another server, uses the profile's old server and
  old login, or both new ones. Before, it could send the new login's token to the old server.
- `docspring login` without `--region` or `--host` uses `DOCSPRING_REGION` or `DOCSPRING_HOST` for a new profile, as
  commands do with an API token in the environment.
- Logging in again to a `--host` profile uses the `--issuer` its last login was given.
- A profile saved by a newer version of the CLI no longer stops your other profiles from working, and saving another
  profile keeps it.
- `docspring submit` and `docspring submissions download` check each file's size as well as its SHA-256 checksum, so a
  file the API lists without a checksum (an audit trail made before September 2024) is checked too.

### 1.0.0 [November 3, 2026]

- The first release of the DocSpring CLI: a `docspring` command for every operation in DocSpring's API v2, such as
  `docspring templates list` and `docspring submissions create`, with `--json` output for scripts and AI agents.
- `docspring login` logs in with your browser, and `docspring login --with-token` saves an API token. Profiles keep
  more than one account or region (`--profile`), and the tokens are kept in your system's keychain. Commands also read
  `DOCSPRING_TOKEN_ID` and `DOCSPRING_TOKEN_SECRET`, for CI.
- `docspring submit` fills in a template and saves the PDF, or a Word template's Word document, and
  `docspring submissions download` saves a submission's PDF, Word document, audit trail or preview.
- `docspring templates model-code --check` exits with status 5 when a file of generated types is out of date with its
  template, for CI.
- `--all` gets every page of a list and prints all the items as one list.
- `docspring exports download` saves the account export that DocSpring support sends when you ask for a copy of your
  account's data.
- Request bodies are checked against the API's schemas before they're sent, so a mistyped property name fails with the
  same details as the API's 422 response.
- Install it with Homebrew (`brew install docspring/tap/docspring`), the shell or PowerShell installer,
  `cargo install --locked docspring-cli`, or the `DocSpring/docspring-cli` GitHub Action. `docspring update` updates an
  install from the installers.
