//! `nexusq audit` — audit log operations.

use crate::GlobalOptions;
use crate::cli::AuditCommand;
use crate::error::CliError;

/// Runs an `audit` subcommand.
pub fn run(command: AuditCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify(_args) => unavailable("audit verify"),
    }
}

fn unavailable(what: &str) -> Result<(), CliError> {
    Err(CliError::Usage(format!(
        "{what}: command not available in this build"
    )))
}
