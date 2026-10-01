//! `nexusq sign` — sign and verify.

use crate::GlobalOptions;
use crate::cli::SignCommand;
use crate::error::CliError;

/// Runs a `sign` subcommand.
pub fn run(command: SignCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        SignCommand::Sign(_args) => not_yet("sign sign"),
        SignCommand::Verify(_args) => not_yet("sign verify"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
