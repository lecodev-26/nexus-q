//! Output formatting.
//!
//! Every command returns its result as an [`Output`] that carries the
//! two representations it knows how to produce: a human-readable
//! string and a JSON value. The caller picks the one that matches the
//! global `--output` flag.
//!
//! Carrying both representations in one value keeps the two in sync:
//! a command that adds a field to one adds it to the other, and no
//! command ever has to guess which format the user asked for.

use serde_json::Value;

use crate::cli::OutputFormat;

/// A command's result, in both renderings.
#[derive(Debug)]
pub struct Output {
    /// Human-readable form, usually a short message or a small table.
    pub human: String,
    /// Machine-readable form.
    pub json: Value,
}

impl Output {
    /// Creates an output from its two renderings.
    #[must_use]
    pub fn new(human: impl Into<String>, json: Value) -> Self {
        Self {
            human: human.into(),
            json,
        }
    }

    /// Creates an output from a message and a JSON value that mirrors
    /// it.
    #[must_use]
    pub fn message(human: impl Into<String>, json: Value) -> Self {
        Self::new(human, json)
    }

    /// Returns the string to print for the given format.
    #[must_use]
    pub fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Human => self.human.clone(),
            OutputFormat::Json => {
                serde_json::to_string_pretty(&self.json).unwrap_or_else(|_| "{}".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Output {
        Output::new("hello", json!({ "message": "hello" }))
    }

    #[test]
    fn human_render_returns_the_human_form() {
        assert_eq!(sample().render(OutputFormat::Human), "hello");
    }

    #[test]
    fn json_render_is_pretty_printed() {
        let rendered = sample().render(OutputFormat::Json);
        assert!(rendered.contains("\"message\""));
        assert!(rendered.contains("hello"));
    }

    #[test]
    fn json_render_is_valid_json() {
        let rendered = sample().render(OutputFormat::Json);
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["message"], "hello");
    }
}
