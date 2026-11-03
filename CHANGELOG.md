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
