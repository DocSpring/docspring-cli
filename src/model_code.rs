//! `docspring templates model-code`: the generated command, plus saving the code to a file and checking that a file
//! is up to date (for CI).

use std::path::PathBuf;

use clap::Args;
use docspring::Api;

use crate::commands::GetTemplateModelCodeArgs;
use crate::errors::CliError;
use crate::runner::{CommandResult, Runner};

#[derive(Debug, Args)]
pub struct ModelCodeArgs {
    #[command(flatten)]
    api: GetTemplateModelCodeArgs,
    /// Save the code in this file instead of printing it
    #[arg(long, short, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Check that --output's file has the template's current code: exits with status 5 and prints a diff when it
    /// doesn't (for CI)
    #[arg(long, requires = "output")]
    check: bool,
}

pub async fn run(runner: &Runner, args: ModelCodeArgs) -> CommandResult {
    let params = args.api.into_params(runner)?;
    let model_code = runner.client().await?.get_template_model_code(params).await.map_err(CliError::from_sdk)?;
    // --json prints the API's response whether the code goes to a file or not
    let print_json = || runner.print(&serde_json::to_value(&model_code).expect("model code serializes"), None);
    let Some(path) = args.output else {
        if runner.global.json {
            print_json();
        } else if !runner.global.quiet {
            crate::output::text(with_newline(&model_code.code));
        }
        return Ok(());
    };
    let code = with_newline(&unix_line_endings(&model_code.code));
    if args.check {
        let current = match std::fs::read_to_string(&path) {
            // A Windows checkout (git's core.autocrlf) has CRLF line endings: the code is the same
            Ok(current) => unix_line_endings(&current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(CliError::usage(format!("Couldn't read {}: {error}", path.display()))),
        };
        if current == code {
            runner.notice(&format!("{} is up to date", path.display()));
            if runner.global.json {
                print_json();
            }
            return Ok(());
        }
        let name = path.display().to_string();
        let diff = similar::TextDiff::from_lines(&current, &code);
        let patch = diff
            .unified_diff()
            .context_radius(3)
            .header(&name, "the template's model code")
            .to_string();
        let mut error = CliError::new(
            crate::errors::exit::CHECK_FAILED,
            format!("{name} isn't the template's current model code. Update it with the same command without --check.\n\n{patch}"),
        );
        error.json = serde_json::json!({ "error": { "code": "model_code_changed", "message": error.message, "diff": patch } });
        return Err(error);
    }
    crate::config::write_file(&path, code.as_bytes(), false)?;
    runner.notice(&format!(
        "Wrote {} ({} type {})",
        path.display(),
        model_code.lang.as_str(),
        model_code.root_type_name
    ));
    if runner.global.json {
        print_json();
    }
    Ok(())
}

fn with_newline(code: &str) -> String {
    if code.ends_with('\n') {
        code.to_owned()
    } else {
        format!("{code}\n")
    }
}

fn unix_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_line_endings_are_the_same_code() {
        assert_eq!(unix_line_endings("type A = {\r\n  b: string\r\n}\r\n"), "type A = {\n  b: string\n}\n");
        assert_eq!(with_newline("type A = {}"), "type A = {}\n");
    }
}
