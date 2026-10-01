//! `nexusq identity` — identity management.

use crate::GlobalOptions;
use crate::cli::IdentityCommand;
use crate::error::CliError;

/// Runs an `identity` subcommand.
pub fn run(command: IdentityCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        IdentityCommand::Create(_args) => unavailable("identity create"),
        IdentityCommand::List(_args) => unavailable("identity list"),
    }
}

fn unavailable(what: &str) -> Result<(), CliError> {
    Err(CliError::Usage(format!(
        "{what}: command not available in this build"
    )))
}
