//! `nexusq data` — encrypt and decrypt.

use crate::GlobalOptions;
use crate::cli::DataCommand;
use crate::error::CliError;

/// Runs a `data` subcommand.
pub fn run(command: DataCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        DataCommand::Encrypt(_args) => unavailable("data encrypt"),
        DataCommand::Decrypt(_args) => unavailable("data decrypt"),
    }
}

fn unavailable(what: &str) -> Result<(), CliError> {
    Err(CliError::Usage(format!(
        "{what}: command not available in this build"
    )))
}
