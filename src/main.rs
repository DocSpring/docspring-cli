//! The DocSpring CLI: a command for each operation in DocSpring's API, logging in, and filling in templates from your
//! terminal, scripts and CI. https://docspring.com/docs/cli/

mod auth;
mod commands;
mod config;
mod download;
mod errors;
mod exports;
mod model_code;
mod oauth;
mod output;
mod runner;
mod secrets;
mod session;
mod update;

use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::runner::{CommandResult, Runner};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "docspring",
    version,
    about = "DocSpring's command-line interface: fill in PDF and Word templates, generate PDFs and manage templates.",
    after_help = "Log in with `docspring login`, or set DOCSPRING_TOKEN_ID and DOCSPRING_TOKEN_SECRET to an API token's \
                  ID and secret. Docs: https://docspring.com/docs/cli/"
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

const GLOBAL: &str = "Global options";

/// The flags every command takes
#[derive(Args, Clone, Debug, Default)]
pub struct GlobalArgs {
    /// Print the API's JSON response (one JSON document on standard output). Errors are printed as JSON too.
    #[arg(long, global = true, help_heading = GLOBAL)]
    pub json: bool,
    /// The saved profile to use (`docspring profiles list` shows them). Without one, commands use DOCSPRING_TOKEN_ID
    /// and DOCSPRING_TOKEN_SECRET when they're set, and the default profile otherwise.
    #[arg(long, global = true, env = "DOCSPRING_PROFILE", value_name = "NAME", help_heading = GLOBAL)]
    pub profile: Option<String>,
    /// The region your DocSpring account is in: US or EU
    #[arg(long, global = true, value_parser = ["US", "EU"], ignore_case = true, help_heading = GLOBAL)]
    pub region: Option<String>,
    /// The API's host, such as your DocSpring Enterprise install's. It wins over --region.
    #[arg(long, global = true, help_heading = GLOBAL)]
    pub host: Option<String>,
    /// Send requests without checking them against the API's request schemas first. A body property this version of
    /// the CLI doesn't know still fails: it can't send it.
    #[arg(long, global = true, help_heading = GLOBAL)]
    pub no_validate: bool,
    /// Print nothing but errors
    #[arg(long, short, global = true, help_heading = GLOBAL)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(flatten)]
    Api(commands::ApiCommand),
    Login(auth::LoginArgs),
    Logout(auth::LogoutArgs),
    #[command(subcommand)]
    Profiles(auth::ProfilesCommand),
    Submit(download::SubmitArgs),
    Update(update::UpdateArgs),
    Completions(CompletionsArgs),
}

/// Print a shell completion script, such as `docspring completions zsh > ~/.zfunc/_docspring`
#[derive(Debug, Args)]
struct CompletionsArgs {
    shell: clap_complete::Shell,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage_error(&error),
    };
    let json = cli.global.json;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio's runtime starts");
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error.print(json);
            ExitCode::from(error.code)
        }
    }
}

/// A command line clap couldn't read, or --help or --version. clap prints them, and a mistake made with --json is also
/// printed as JSON on standard output, like every other error
fn usage_error(error: &clap::Error) -> ExitCode {
    let _ = error.print();
    // clap couldn't read the arguments, so --json is looked for among them (before a --, which ends the flags)
    let json = std::env::args_os().skip(1).take_while(|arg| arg != "--").any(|arg| arg == "--json");
    if json && error.use_stderr() {
        errors::CliError::usage(usage_message(error)).print_json();
    }
    ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(errors::exit::USAGE))
}

/// clap's error in a line, without its usage and tips
fn usage_message(error: &clap::Error) -> String {
    if error.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
        return "The command needs a subcommand or an argument: see its --help".to_owned();
    }
    let text = error.render().to_string();
    let line = text.lines().next().unwrap_or_default();
    line.strip_prefix("error: ").unwrap_or(line).to_owned()
}

async fn run(cli: Cli) -> CommandResult {
    let runner = Runner::new(cli.global);
    let result = run_command(&runner, cli.command).await;
    // Another docspring command refreshed this login while this one ran, which revoked the access token this one
    // used: run it again with the new one. The API refused the request that got the 401, so running it again is safe,
    // and submit sends the same Idempotency-Key both times, so a submission it already made isn't made twice.
    if matches!(&result, Err(error) if error.code == errors::exit::AUTH) && runner.login_replaced() {
        let cli = Cli::parse();
        return run_command(&Runner::new(cli.global), cli.command).await;
    }
    result
}

async fn run_command(runner: &Runner, command: Command) -> CommandResult {
    match command {
        Command::Api(command) => command.run(runner).await,
        Command::Login(args) => auth::login(runner, args).await,
        Command::Logout(args) => auth::logout(runner, args).await,
        Command::Profiles(command) => command.run(runner).await,
        Command::Submit(args) => download::submit(runner, args).await,
        Command::Update(args) => update::update(runner, args).await,
        Command::Completions(args) => {
            let mut script = Vec::new();
            clap_complete::generate(args.shell, &mut Cli::command(), "docspring", &mut script);
            output::text(script);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_tree_is_valid() {
        // Duplicate command names, flags that clash with the global flags, bad defaults
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_go_anywhere() {
        let cli = Cli::try_parse_from(["docspring", "templates", "get", "tpl_1", "--json", "--region", "EU"]).unwrap();
        assert!(cli.global.json);
        assert_eq!(cli.global.region.as_deref(), Some("EU"));
    }

    #[test]
    fn a_usage_error_is_one_line_for_json() {
        let error = Cli::try_parse_from(["docspring", "templates", "list", "--bogus"]).unwrap_err();
        assert_eq!(usage_message(&error), "unexpected argument '--bogus' found");
        let error = Cli::try_parse_from(["docspring", "templates"]).unwrap_err();
        assert_eq!(usage_message(&error), "The command needs a subcommand or an argument: see its --help");
    }

    #[test]
    fn a_missing_file_to_upload_is_a_usage_error_that_names_it() {
        let error = Cli::try_parse_from(["docspring", "templates", "upload", "missing-lease.pdf"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(usage_message(&error).starts_with("invalid value 'missing-lease.pdf' for '<DOCUMENT>': couldn't read it:"));
        let dir = tempfile::tempdir().unwrap();
        let error = Cli::try_parse_from(["docspring", "templates", "upload", dir.path().to_str().unwrap()]).unwrap_err();
        assert!(usage_message(&error).ends_with("it isn't a file"), "{error}");
    }

    #[test]
    fn an_id_that_would_send_the_request_elsewhere_is_a_usage_error() {
        for id in ["..", ".", ""] {
            let error = Cli::try_parse_from(["docspring", "templates", "email-actions", "delete", "tpl_1", id]).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{id:?}");
            assert!(error.to_string().contains("an ID can't be empty, . or .."), "{error}");
        }
        assert!(Cli::try_parse_from(["docspring", "templates", "get", "tpl_1.v2"]).is_ok());
    }
}
