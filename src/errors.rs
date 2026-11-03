//! Errors and exit codes. Every error goes to stderr; with `--json` it's also printed on stdout as JSON in the API's
//! error format, so a script reads one document either way.

use serde_json::{json, Value};

/// The CLI's exit codes
pub mod exit {
    pub const API: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const VALIDATION: u8 = 3;
    pub const AUTH: u8 = 4;
    /// A check found a difference: `templates model-code --check`'s file is out of date
    pub const CHECK_FAILED: u8 = 5;
}

#[derive(Debug)]
pub struct CliError {
    pub code: u8,
    pub message: String,
    /// The error as JSON, for `--json`: the API's error response, or one in the same format
    pub json: Value,
}

impl CliError {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        let message = message.into();
        let json = json!({ "error": { "code": code_name(code), "message": message } });
        CliError { code, message, json }
    }

    pub fn api(message: impl Into<String>) -> Self {
        CliError::new(exit::API, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        CliError::new(exit::USAGE, message)
    }

    pub fn auth(message: impl Into<String>) -> Self {
        CliError::new(exit::AUTH, message)
    }

    /// A request the SDK's request validator rejected before sending it: the details the API's 422 would have had
    pub fn validation(error: docspring::ValidationError) -> Self {
        let message = error.to_string();
        let json = json!({
            "error": { "code": "validation_failed", "message": message, "details": error.details }
        });
        CliError {
            code: exit::VALIDATION,
            message,
            json,
        }
    }

    /// An error from the SDK: the API's error response, a request it didn't send, or no response
    pub fn from_sdk<T>(error: docspring::Error<T>) -> Self {
        match error {
            docspring::Error::RequestValidation(error) => CliError::validation(error),
            docspring::Error::ResponseError(response) => {
                let status = response.status.as_u16();
                let code = match status {
                    401 | 403 => exit::AUTH,
                    422 => exit::VALIDATION,
                    _ => exit::API,
                };
                let body: Option<Value> = serde_json::from_str(&response.content).ok();
                let api_message = body
                    .as_ref()
                    .and_then(|body| body.pointer("/error/message"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let mut message = match api_message {
                    Some(message) => format!("{message} ({status})"),
                    None if response.content.trim().is_empty() => format!("DocSpring responded {status}"),
                    None => format!("DocSpring responded {status}: {}", response.content.trim()),
                };
                if status == 401 {
                    message.push_str(
                        "\nCheck the API token, or run `docspring login` again (`docspring auth status` shows which \
                         credentials commands use).",
                    );
                }
                let json = body
                    .filter(|body| body.get("error").is_some())
                    .unwrap_or_else(|| json!({ "error": { "code": code_name(code), "message": message } }));
                CliError { code, message, json }
            }
            docspring::Error::Reqwest(error) => CliError::api(format!("Couldn't reach DocSpring: {}", describe(&error))),
            docspring::Error::Serde(error) => CliError::api(format!("Couldn't read DocSpring's response: {error}")),
            docspring::Error::Io(error) => CliError::api(error.to_string()),
        }
    }

    pub fn print(&self, json: bool) {
        eprintln!("Error: {}", self.message);
        for line in self.unlisted_details() {
            eprintln!("  {line}");
        }
        if json {
            self.print_json();
        }
    }

    /// The error as JSON on standard output, for --json
    pub fn print_json(&self) {
        crate::output::json(&self.json);
    }
}

impl CliError {
    /// The error's details that its message leaves out: the API's and the SDK's messages list the first 3
    fn unlisted_details(&self) -> Vec<String> {
        let Some(details) = self.json.pointer("/error/details").and_then(Value::as_array) else {
            return Vec::new();
        };
        details
            .iter()
            .map(detail_line)
            .filter(|line| !self.message.contains(line.as_str()))
            .collect()
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        CliError::api(error.to_string())
    }
}

/// An error detail as the API's message words it: its pointer (or parameter) and message
fn detail_line(detail: &Value) -> String {
    let subject = detail
        .get("pointer")
        .and_then(Value::as_str)
        .map(|pointer| if pointer.is_empty() { "the request body" } else { pointer })
        .or_else(|| detail.get("parameter").and_then(Value::as_str))
        .unwrap_or("");
    let message = detail.get("message").and_then(Value::as_str).unwrap_or("");
    format!("{subject} {message}")
}

/// A reqwest error with its causes (reqwest's own message leaves out why a connection failed)
pub fn describe(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    message
}

fn code_name(code: u8) -> &'static str {
    match code {
        exit::USAGE => "usage_error",
        exit::VALIDATION => "validation_failed",
        exit::AUTH => "unauthorized",
        exit::CHECK_FAILED => "check_failed",
        _ => "cli_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validation_error(pointers: &[&str]) -> CliError {
        let details = pointers
            .iter()
            .map(|pointer| docspring::models::ErrorDetail {
                code: "unknown_property".into(),
                message: "isn't a documented property".into(),
                pointer: Some((*pointer).into()),
                ..Default::default()
            })
            .collect();
        CliError::validation(docspring::ValidationError { details })
    }

    #[test]
    fn prints_only_the_details_the_message_leaves_out() {
        let error = validation_error(&["/dta"]);
        assert_eq!(error.message, "Invalid request: /dta isn't a documented property");
        assert!(error.unlisted_details().is_empty());

        let error = validation_error(&["/a", "/b", "/c", "/d", "/e"]);
        assert!(error.message.ends_with("(and 2 more)"));
        assert_eq!(
            error.unlisted_details(),
            ["/d isn't a documented property", "/e isn't a documented property"]
        );
    }
}
