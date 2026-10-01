//! `nexusq key` — key management.

use crate::GlobalOptions;
use crate::cli::KeyCommand;
use crate::error::CliError;

/// Runs a `key` subcommand.
pub fn run(command: KeyCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        KeyCommand::Generate(_args) => not_yet("key generate"),
        KeyCommand::List(_args) => not_yet("key list"),
        KeyCommand::Info(_args) => not_yet("key info"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
