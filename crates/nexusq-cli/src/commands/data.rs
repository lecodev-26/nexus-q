//! `nexusq data` — encrypt and decrypt.

use crate::GlobalOptions;
use crate::cli::DataCommand;
use crate::error::CliError;

/// Runs a `data` subcommand.
pub fn run(command: DataCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        DataCommand::Encrypt(_args) => not_yet("data encrypt"),
        DataCommand::Decrypt(_args) => not_yet("data decrypt"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
