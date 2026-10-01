//! `nexusq vault` — vault management.

use crate::GlobalOptions;
use crate::cli::VaultCommand;
use crate::error::CliError;

/// Runs a `vault` subcommand.
pub fn run(command: VaultCommand, _global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        VaultCommand::Create(_args) => not_yet("vault create"),
        VaultCommand::Status(_args) => not_yet("vault status"),
    }
}

fn not_yet(what: &str) -> Result<(), CliError> {
    Err(CliError::Generic(format!("{what} is not implemented yet")))
}
