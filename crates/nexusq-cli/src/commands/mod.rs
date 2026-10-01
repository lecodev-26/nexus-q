//! Subcommand implementations.
//!
//! One module per top-level subcommand. Each exposes a `run`
//! function that receives its parsed arguments and the global CLI
//! state, and returns a [`CliError`](crate::error::CliError) on
//! failure.
//!
//! The commands are thin: they translate the CLI's vocabulary into
//! calls on `nexusq-core`, format the result, and let the error
//! mapping take care of exit codes. No cryptography, no business
//! logic.

pub mod audit;
pub mod credential;
pub mod data;
pub mod identity;
pub mod key;
pub mod sign;
pub mod vault;
