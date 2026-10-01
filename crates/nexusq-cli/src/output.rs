//! Output formatting.
//!
//! Every command returns its result through this module so that the
//! user-facing text and the JSON representation stay in sync. The
//! format is chosen once, in [`Cli`](crate::cli::Cli), and read from
//! there.

use crate::cli::OutputFormat;

/// A command's result, ready to be printed.
pub enum Output {
    /// A line of human-readable text.
    Message(String),
    /// A JSON value produced with `serde_json`.
    Json(serde_json::Value),
}

impl Output {
    /// Creates a message output.
    pub fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }

    /// Creates a JSON output.
    pub fn json(value: serde_json::Value) -> Self {
        Self::Json(value)
    }

    /// Renders the output for the requested format.
    ///
    /// When the caller asked for JSON but the output is a message, the
    /// message is wrapped in a small JSON object so a script parsing
    /// the output does not have to special-case formats.
    #[must_use]
    pub fn render(&self, format: OutputFormat) -> String {
        match (self, format) {
            (Self::Message(text), OutputFormat::Human) => text.clone(),
            (Self::Json(value), OutputFormat::Json) => {
                serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
            }
            (Self::Message(text), OutputFormat::Json) => {
                let value = serde_json::json!({ "message": text });
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
            }
            (Self::Json(value), OutputFormat::Human) => {
                serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_in_human_is_the_message() {
        let out = Output::message("hello");
        assert_eq!(out.render(OutputFormat::Human), "hello");
    }

    #[test]
    fn message_in_json_is_wrapped() {
        let out = Output::message("hello");
        let rendered = out.render(OutputFormat::Json);
        assert!(rendered.contains("\"message\""));
        assert!(rendered.contains("hello"));
    }

    #[test]
    fn json_in_json_is_pretty_printed() {
        let value = serde_json::json!({ "key": "value" });
        let out = Output::json(value);
        let rendered = out.render(OutputFormat::Json);
        assert!(rendered.contains("\"key\""));
        assert!(rendered.contains("\"value\""));
    }

    #[test]
    fn json_in_human_is_still_json() {
        let value = serde_json::json!({ "key": "value" });
        let out = Output::json(value);
        let rendered = out.render(OutputFormat::Human);
        assert!(rendered.contains("\"key\""));
    }
}
