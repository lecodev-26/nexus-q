//! `nexusq identity` — identity management.

use crate::GlobalOptions;
use crate::cli::IdentityCommand;
use crate::error::CliError;

/// Runs an `identity` subcommand.
pub fn run(command: IdentityCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        IdentityCommand::Create(_args) => not_yet("identity create"),
        IdentityCommand::List(_args) => not_yet("identity list"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
