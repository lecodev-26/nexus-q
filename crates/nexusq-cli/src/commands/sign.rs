//! `nexusq sign` — sign and verify.

use crate::GlobalOptions;
use crate::cli::SignCommand;
use crate::error::CliError;

/// Runs a `sign` subcommand.
pub fn run(command: SignCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        SignCommand::Sign(_args) => unavailable("sign sign"),
        SignCommand::Verify(_args) => unavailable("sign verify"),
    }
}

fn unavailable(what: &str) -> Result<(), CliError> {
    Err(CliError::Usage(format!(
        "{what}: command not available in this build"
    )))
}
