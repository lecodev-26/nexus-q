//! `nexusq` — command-line interface for NEXUS-Q.
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

use crate::cli::{Cli, Command, OutputFormat};
use crate::error::CliError;

fn main() {
    let cli = Cli::parse();
    let format = cli.output;
    match run(cli) {
        Ok(()) => std::process::exit(exit_codes::SUCCESS),
        Err(err) => {
            print_error(&err, format);
            std::process::exit(err.exit_code());
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    let Cli {
        output,
        quiet,
        command,
    } = cli;
    let global = GlobalOptions { output, quiet };

    match command {
        Command::Health(args) => commands::diagnostics::health(args, &global),
        Command::Diagnostics(args) => commands::diagnostics::diagnostics(args, &global),
        Command::Vault(cmd) => commands::vault::run(cmd, &global),
        Command::Key(cmd) => commands::key::run(cmd, &global),
        Command::Data(cmd) => commands::data::run(cmd, &global),
        Command::Sign(cmd) => commands::sign::run(cmd, &global),
        Command::Identity(cmd) => commands::identity::run(cmd, &global),
        Command::Credential(cmd) => commands::credential::run(cmd, &global),
        Command::Audit(cmd) => commands::audit::run(cmd, &global),
    }
}

fn print_error(err: &CliError, format: OutputFormat) {
    match format {
        OutputFormat::Human => eprintln!("error: {err}"),
        OutputFormat::Json => {
            let value = serde_json::json!({
                "error": err.to_string(),
                "code": err.exit_code(),
            });
            match serde_json::to_string(&value) {
                Ok(text) => eprintln!("{text}"),
                Err(_) => eprintln!("error: {err}"),
            }
        }
    }
}

/// Global options passed to every subcommand.
pub struct GlobalOptions {
    /// Selected output format.
    pub output: OutputFormat,
    /// Whether to suppress non-error output.
    pub quiet: bool,
}
