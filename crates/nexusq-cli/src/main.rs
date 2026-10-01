//! `nexusq` — command-line interface for AXIOM NEXUS-Q.
//!
//! The CLI is a thin wrapper over `nexusq-core`. It parses arguments,
//! calls the library, formats the result, and maps errors to exit
//! codes. It contains no cryptography and no business logic.

mod cli;
mod commands;
mod error;
mod exit_codes;
mod output;
mod passwords;

use clap::Parser as _;

use crate::cli::{Cli, Command};
use crate::error::CliError;

fn main() {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => std::process::exit(exit_codes::SUCCESS),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(err.exit_code());
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    // Split the CLI into the global options and the subcommand so the
    // subcommand can be moved into its own handler without keeping
    // `cli` around.
    let Cli {
        output,
        quiet,
        command,
    } = cli;
    let global = GlobalOptions { output, quiet };

    match command {
        Command::Vault(cmd) => commands::vault::run(cmd, &global),
        Command::Key(cmd) => commands::key::run(cmd, &global),
        Command::Data(cmd) => commands::data::run(cmd, &global),
        Command::Sign(cmd) => commands::sign::run(cmd, &global),
        Command::Identity(cmd) => commands::identity::run(cmd, &global),
        Command::Credential(cmd) => commands::credential::run(cmd, &global),
        Command::Audit(cmd) => commands::audit::run(cmd, &global),
    }
}

/// Global options passed to every subcommand.
pub struct GlobalOptions {
    /// Selected output format.
    pub output: cli::OutputFormat,
    /// Whether to suppress non-error output.
    pub quiet: bool,
}
