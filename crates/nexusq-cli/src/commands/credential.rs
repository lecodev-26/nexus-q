//! `nexusq credential` — issue and verify credentials.

use crate::GlobalOptions;
use crate::cli::CredentialCommand;
use crate::error::CliError;

/// Runs a `credential` subcommand.
pub fn run(command: CredentialCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        CredentialCommand::Issue(_args) => unavailable("credential issue"),
        CredentialCommand::Verify(_args) => unavailable("credential verify"),
    }
}

fn unavailable(what: &str) -> Result<(), CliError> {
    Err(CliError::Usage(format!(
        "{what}: command not available in this build"
    )))
}
