//! Printing results: JSON, tables for lists, and `key: value` lines for everything else.

use std::io::Write;

use serde_json::Value;

use crate::runner::Table;

/// Writes to standard output. When whatever reads it has stopped (`docspring templates list | head -1`), the rest is
/// left out quietly, as other command-line tools do, instead of panicking, and the command keeps its exit status.
pub fn text(text: impl AsRef<[u8]>) {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = stdout.write_all(text.as_ref()).and_then(|()| stdout.flush()) {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("Error: Couldn't write to standard output: {error}");
            std::process::exit(1);
        }
    }
}

/// A line on standard output (`text`)
pub fn line(line: &str) {
    text(format!("{line}\n"));
}

pub fn json(value: &Value) {
    line(&serde_json::to_string_pretty(value).expect("JSON values serialize"));
}

/// A list response as a table: one row per item with the table's columns, then the cursor for the next page
pub fn table(value: &Value, table: &Table) {
    let rows = value.get(table.rows).and_then(Value::as_array).cloned().unwrap_or_default();
    text(format_table(table.columns, &rows));
    if let Some(cursor) = value.get("next_cursor").and_then(Value::as_str) {
        line(&format!("\nMore results: add --cursor {cursor}"));
    }
}

pub fn format_table(columns: &[&str], rows: &[Value]) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| columns.iter().map(|column| cell(row.get(*column).unwrap_or(&Value::Null))).collect())
        .collect();
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            cells
                .iter()
                .map(|row| row[index].chars().count())
                .chain([column.len()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |values: Vec<String>| {
        let padded: Vec<String> = values.iter().zip(&widths).map(|(value, width)| format!("{value:<width$}")).collect();
        format!("{}\n", padded.join("  ").trim_end())
    };
    let mut output = line(columns.iter().map(|column| column.to_uppercase()).collect());
    for row in cells {
        output.push_str(&line(row));
    }
    output
}

/// An object as `key: value` lines; nested objects and lists are shown as compact JSON
pub fn object(value: &Value) {
    text(format_object(value));
}

pub fn format_object(value: &Value) -> String {
    match value {
        Value::Object(map) => map.iter().map(|(key, value)| format!("{key}: {}\n", cell(value))).collect(),
        other => format!("{}\n", cell(other)),
    }
}

fn cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tables_line_up_their_columns() {
        let rows = vec![
            json!({ "id": "tpl_1", "name": "Rental Contract", "ready": true }),
            json!({ "id": "tpl_22", "name": null, "ready": false }),
        ];
        assert_eq!(
            format_table(&["id", "name", "ready"], &rows),
            "ID      NAME             READY\ntpl_1   Rental Contract  true\ntpl_22                   false\n"
        );
    }

    #[test]
    fn objects_print_one_property_per_line() {
        let value = json!({ "id": "sub_1", "state": "processed", "metadata": { "user_id": 42 }, "expires_at": null });
        assert_eq!(
            format_object(&value),
            "id: sub_1\nstate: processed\nmetadata: {\"user_id\":42}\nexpires_at: \n"
        );
    }
}
