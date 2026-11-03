//! What every command shares: the SDK client for the credentials it uses, reading `--data`, and printing the result.

use std::ffi::OsStr;
use std::io::Read;

use clap::builder::{PossibleValue, StringValueParser, TypedValueParser};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::OnceCell;

use crate::errors::CliError;
use crate::output;
use crate::session::Session;
use crate::GlobalArgs;

pub type CommandResult = Result<(), CliError>;

/// How a list operation's response prints as a table (cli_commands.yml)
pub struct Table {
    /// The response property that holds the rows
    pub rows: &'static str,
    /// The properties of each row the table shows
    pub columns: &'static [&'static str],
}

pub struct Runner {
    pub global: GlobalArgs,
    session: OnceCell<Session>,
}

impl Runner {
    pub fn new(global: GlobalArgs) -> Self {
        Runner {
            global,
            session: OnceCell::new(),
        }
    }

    /// The profile or API token this command uses, with a login's access token refreshed when it's about to expire
    pub async fn session(&self) -> Result<&Session, CliError> {
        self.session.get_or_try_init(|| Session::resolve(&self.global)).await
    }

    /// Whether the command's login got a newer access token while it ran (Session::login_replaced)
    pub fn login_replaced(&self) -> bool {
        self.session.get().is_some_and(Session::login_replaced)
    }

    /// The Rust SDK's client for this command's credentials
    pub async fn client(&self) -> Result<&docspring::Client, CliError> {
        Ok(&self.session().await?.client)
    }

    /// A request body from `--data` (the JSON, `@file` or `-` for stdin). The JSON is checked against the operation's
    /// request schema before serde reads it into the SDK's request model, which would drop properties it doesn't know
    /// (a typo would vanish).
    pub fn body<T: DeserializeOwned + Serialize>(&self, operation_id: &str, data: &str) -> Result<T, CliError> {
        self.body_from_value(operation_id, read_json(data)?)
    }

    /// A request body from JSON, checked against the operation's request schema as `body` does. With --no-validate, a
    /// property the SDK's model doesn't know still fails: the request would go without it (a typo, or a property the
    /// API added after this version of the CLI).
    pub fn body_from_value<T: DeserializeOwned + Serialize>(&self, operation_id: &str, value: Value) -> Result<T, CliError> {
        if !self.global.no_validate {
            let details = docspring::request_validator::request_errors(operation_id, &Map::new(), Some(&value));
            if !details.is_empty() {
                return Err(CliError::validation(docspring::ValidationError { details }));
            }
        }
        let body: T = serde_json::from_value(value.clone()).map_err(|error| CliError::usage(format!("--data doesn't fit the request: {error}")))?;
        let sent = serde_json::to_value(&body).map_err(|error| CliError::usage(format!("--data doesn't fit the request: {error}")))?;
        let mut lost = Vec::new();
        lost_properties(&value, &sent, "", &mut lost);
        if !lost.is_empty() {
            let details = lost
                .into_iter()
                .map(|pointer| {
                    let mut detail = docspring::models::ErrorDetail::new(
                        "unknown_property".to_owned(),
                        format!(
                            "{pointer} isn't a property this version of the DocSpring CLI knows, so the request would go without \
                             it. Check its name, or update the CLI (docspring update) for a property the API has added."
                        ),
                    );
                    detail.pointer = Some(pointer);
                    detail
                })
                .collect();
            return Err(CliError::validation(docspring::ValidationError { details }));
        }
        Ok(body)
    }

    /// A date-time argument, in RFC 3339 (`2026-01-31T09:00:00Z`). For one that isn't, the request validator's
    /// details, as the API's 422 would give them (`api_name` is the parameter's name in the API).
    pub fn date_time(&self, operation_id: &str, api_name: &str, value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>, CliError> {
        if let Ok(date_time) = chrono::DateTime::parse_from_rfc3339(value) {
            return Ok(date_time);
        }
        if !self.global.no_validate {
            let query = Map::from_iter([(api_name.to_owned(), Value::String(value.to_owned()))]);
            let details: Vec<_> = docspring::request_validator::request_errors(operation_id, &query, None)
                .into_iter()
                .filter(|detail| detail.parameter.as_deref() == Some(api_name))
                .collect();
            if !details.is_empty() {
                return Err(CliError::validation(docspring::ValidationError { details }));
            }
        }
        Err(CliError::usage(format!(
            "{value} isn't an RFC 3339 date and time, such as 2026-01-31T09:00:00Z"
        )))
    }

    /// Prints an operation's response, or returns its error
    pub fn finish<T: Serialize, E>(&self, result: Result<T, docspring::Error<E>>, table: Option<&Table>) -> CommandResult {
        let response = result.map_err(CliError::from_sdk)?;
        let value = serde_json::to_value(&response).map_err(|error| CliError::api(format!("Couldn't print the response: {error}")))?;
        self.print(&value, table);
        Ok(())
    }

    /// Prints a result: JSON with `--json`, nothing with `--quiet`, otherwise a table for a list and `key: value` lines
    /// for anything else
    pub fn print(&self, value: &Value, table: Option<&Table>) {
        if self.global.json {
            output::json(value);
        } else if self.global.quiet {
        } else if let Some(table) = table {
            output::table(value, table);
        } else {
            output::object(value);
        }
    }

    /// A message for the person running the command, on stderr (left out with `--quiet`)
    pub fn notice(&self, message: &str) {
        if !self.global.quiet {
            eprintln!("{message}");
        }
    }
}

/// A path parameter, such as a template's ID. The SDK doesn't encode `.`, so `.` or `..` would send the request to
/// another URL (`templates email-actions delete tpl_1 ..` to the template itself), and an empty ID to the list.
pub fn path_segment(value: &str) -> Result<String, String> {
    match value.trim() {
        "" | "." | ".." => Err("an ID can't be empty, . or ..".to_owned()),
        _ => Ok(value.to_owned()),
    }
}

/// A file to upload. It must be there, so the error names it: the SDK's only has the OS's message.
pub fn upload_file(value: &str) -> Result<std::path::PathBuf, String> {
    match std::fs::metadata(value) {
        Ok(metadata) if metadata.is_file() => Ok(value.into()),
        Ok(_) => Err("it isn't a file".to_owned()),
        Err(error) => Err(format!("couldn't read it: {error}")),
    }
}

/// `--data`'s JSON: the JSON itself, `@path` to read a file, or `-` to read stdin
pub fn read_json(data: &str) -> Result<Value, CliError> {
    let (text, source) = if data == "-" {
        (stdin()?, "standard input".to_owned())
    } else if let Some(path) = data.strip_prefix('@') {
        let text = std::fs::read_to_string(path).map_err(|error| CliError::usage(format!("Couldn't read {path}: {error}")))?;
        (text, path.to_owned())
    } else {
        (data.to_owned(), "--data".to_owned())
    };
    serde_json::from_str(&text).map_err(|error| CliError::usage(format!("{source} isn't valid JSON: {error}")))
}

/// Standard input, read once: a command run again with a refreshed login (main.rs) reads the same body
fn stdin() -> Result<String, CliError> {
    static STDIN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(text) = STDIN.get() {
        return Ok(text.clone());
    }
    let mut text = String::new();
    std::io::stdin()
        .read_to_string(&mut text)
        .map_err(|error| CliError::usage(format!("Couldn't read standard input: {error}")))?;
    Ok(STDIN.get_or_init(|| text).clone())
}

/// The JSON pointers of properties in `given` that the SDK's model left out of `sent` (a null left out changes
/// nothing). Values aren't compared: serde writes some numbers differently (11 as 11.0).
fn lost_properties(given: &Value, sent: &Value, pointer: &str, lost: &mut Vec<String>) {
    match (given, sent) {
        (Value::Object(given), Value::Object(sent)) => {
            for (name, value) in given {
                let child = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                match sent.get(name) {
                    Some(sent_value) => lost_properties(value, sent_value, &child, lost),
                    None if !value.is_null() => lost.push(child),
                    None => {}
                }
            }
        }
        (Value::Array(given), Value::Array(sent)) if given.len() == sent.len() => {
            for (index, (value, sent_value)) in given.iter().zip(sent).enumerate() {
                lost_properties(value, sent_value, &format!("{pointer}/{index}"), lost);
            }
        }
        _ => {}
    }
}

/// An enum argument's parser. Help and shell completions list the API's values, and it takes any value, which the SDK
/// keeps in its enum's Unknown: the request validator then says what's wrong with a value the API doesn't have, as the
/// API would (as JSON with --json, which clap's own errors can't be), and a value the API added since this release
/// still works.
#[derive(Clone, Debug)]
pub struct EnumValueParser(Vec<&'static str>);

impl EnumValueParser {
    pub fn new(values: impl IntoIterator<Item = &'static str>) -> Self {
        EnumValueParser(values.into_iter().collect())
    }
}

impl TypedValueParser for EnumValueParser {
    type Value = String;

    fn parse_ref(&self, cmd: &clap::Command, arg: Option<&clap::Arg>, value: &OsStr) -> Result<String, clap::Error> {
        StringValueParser::new().parse_ref(cmd, arg, value)
    }

    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        Some(Box::new(self.0.iter().map(|value| PossibleValue::new(*value))))
    }
}

/// The pages a list command's `--all` gets, as one list response: the first page's properties, with every page's
/// items and `next_cursor` null
pub struct Pages {
    rows: &'static str,
    first: Option<Value>,
    items: Vec<Value>,
    cursor: Option<String>,
}

impl Pages {
    pub fn new(rows: &'static str) -> Pages {
        Pages {
            rows,
            first: None,
            items: Vec::new(),
            cursor: None,
        }
    }

    /// Adds a page and returns the next page's cursor, or None after the last page
    pub fn add<T: Serialize, E>(&mut self, result: Result<T, docspring::Error<E>>) -> Result<Option<String>, CliError> {
        let page = result.map_err(CliError::from_sdk)?;
        let mut page = serde_json::to_value(&page).map_err(|error| CliError::api(format!("Couldn't read the response: {error}")))?;
        let items = page.get_mut(self.rows).and_then(Value::as_array_mut).map(std::mem::take);
        let Some(items) = items else {
            return Err(CliError::api(format!("The response has no {} list", self.rows)));
        };
        self.items.extend(items);
        let next = page.get("next_cursor").and_then(Value::as_str).map(str::to_owned);
        // The cursor that got this page would get it again, forever
        if next.is_some() && next == self.cursor {
            return Err(CliError::api(format!(
                "The API returned the same next_cursor twice ({}), so --all stopped",
                next.unwrap_or_default()
            )));
        }
        self.first.get_or_insert(page);
        self.cursor.clone_from(&next);
        Ok(next)
    }

    pub fn into_value(self) -> Value {
        let mut value = self.first.unwrap_or_else(|| Value::Object(Map::new()));
        value[self.rows] = Value::Array(self.items);
        value["next_cursor"] = Value::Null;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pages_stop_when_the_api_repeats_a_cursor() {
        let page = |cursor: &str| -> Result<Value, docspring::Error<()>> { Ok(serde_json::json!({ "data": [], "next_cursor": cursor })) };
        let mut pages = Pages::new("data");
        assert_eq!(pages.add(page("tpl_2")).expect("the first page"), Some("tpl_2".to_owned()));
        let error = pages.add(page("tpl_2")).expect_err("the same cursor again would loop forever");
        assert!(error.message.contains("same next_cursor twice"), "{}", error.message);
    }

    #[test]
    fn date_times_are_rfc_3339() {
        let runner = Runner::new(GlobalArgs::default());
        let date_time = runner.date_time("listSubmissions", "created_after", "2026-01-31T09:00:00Z").unwrap();
        assert_eq!(date_time.to_rfc3339(), "2026-01-31T09:00:00+00:00");

        // The API's 422
        let error = runner.date_time("listSubmissions", "created_after", "yesterday").unwrap_err();
        assert_eq!(error.code, crate::errors::exit::VALIDATION);
        let details = error.json.pointer("/error/details").and_then(Value::as_array).unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["parameter"], "created_after");
        assert_eq!(details[0]["code"], "format");

        let runner = Runner::new(GlobalArgs {
            no_validate: true,
            ..GlobalArgs::default()
        });
        let error = runner.date_time("listSubmissions", "created_after", "yesterday").unwrap_err();
        assert_eq!(error.code, crate::errors::exit::USAGE);
        assert_eq!(error.message, "yesterday isn't an RFC 3339 date and time, such as 2026-01-31T09:00:00Z");
    }

    #[test]
    fn enum_arguments_take_any_value_and_list_the_apis() {
        let command = clap::Command::new("docspring");
        let parser = EnumValueParser::new(["pending", "processed"]);
        assert_eq!(parser.parse_ref(&command, None, OsStr::new("exploded")).unwrap(), "exploded");
        let values: Vec<String> = parser.possible_values().unwrap().map(|value| value.get_name().to_owned()).collect();
        assert_eq!(values, ["pending", "processed"]);
    }

    #[test]
    fn no_validate_still_fails_on_properties_the_cli_would_leave_out() {
        let runner = Runner::new(GlobalArgs {
            no_validate: true,
            ..GlobalArgs::default()
        });
        let body: docspring::models::CreateFolderRequest = runner
            .body_from_value("createFolder", serde_json::json!({ "name": "Leases", "parent_folder_id": null }))
            .unwrap();
        assert_eq!(body.parent_folder_id, Some(None));

        let error = runner
            .body_from_value::<docspring::models::CreateFolderRequest>(
                "createFolder",
                serde_json::json!({ "name": "Leases", "parnet_folder_id": "fld_1" }),
            )
            .unwrap_err();
        assert_eq!(error.code, crate::errors::exit::VALIDATION);
        let details = error.json.pointer("/error/details").and_then(Value::as_array).unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["code"], "unknown_property");
        assert_eq!(details[0]["pointer"], "/parnet_folder_id");

        // Inside a map of objects, and free-form data stays as it came; a null left out changes nothing
        let error = runner
            .body_from_value::<docspring::models::CreateSubmissionRequest>(
                "createSubmission",
                serde_json::json!({
                    "data": { "anything": { "nested": true } },
                    "field_overrides": { "first/name": { "required": true, "colour": "red" } },
                    "a_future_option": null,
                }),
            )
            .unwrap_err();
        let details = error.json.pointer("/error/details").and_then(Value::as_array).unwrap();
        let pointers: Vec<&str> = details.iter().filter_map(|detail| detail["pointer"].as_str()).collect();
        assert_eq!(pointers, ["/field_overrides/first~1name/colour"]);
    }

    #[test]
    fn data_is_json_or_a_file() {
        assert_eq!(read_json(r#"{"a": 1}"#).unwrap(), serde_json::json!({ "a": 1 }));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), r#"{"b": [true]}"#).unwrap();
        assert_eq!(
            read_json(&format!("@{}", file.path().display())).unwrap(),
            serde_json::json!({ "b": [true] })
        );
        let error = read_json("{nope").unwrap_err();
        assert_eq!(error.code, crate::errors::exit::USAGE);
        assert!(error.message.starts_with("--data isn't valid JSON"), "{}", error.message);
        let error = read_json("@/nonexistent/file.json").unwrap_err();
        assert!(error.message.starts_with("Couldn't read /nonexistent/file.json"), "{}", error.message);
    }
}
