//! `nexusq audit` — audit log operations.

use crate::GlobalOptions;
use crate::cli::AuditCommand;
use crate::error::CliError;

/// Runs an `audit` subcommand.
pub fn run(command: AuditCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify(_args) => not_yet("audit verify"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
