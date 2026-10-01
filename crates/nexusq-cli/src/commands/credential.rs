//! `nexusq credential` — issue and verify credentials.

use crate::GlobalOptions;
use crate::cli::CredentialCommand;
use crate::error::CliError;

/// Runs a `credential` subcommand.
pub fn run(command: CredentialCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        CredentialCommand::Issue(_args) => not_yet("credential issue"),
        CredentialCommand::Verify(_args) => not_yet("credential verify"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
