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

use std::path::Path;

use nexusq_core::vault::{Session, Vault};

use crate::error::CliError;
use crate::passwords;

/// Opens a vault and unlocks it with a password.
///
/// The password comes from `--password-file` when given, otherwise
/// from an interactive prompt.
///
/// # Errors
///
/// Propagates any error from opening the vault, reading the password,
/// or unlocking. A wrong password surfaces as
/// [`CliError::Authentication`].
pub fn unlock_session(
    vault_path: &Path,
    password_file: Option<&Path>,
) -> Result<Session, CliError> {
    let vault = Vault::open(vault_path)?;
    let password = passwords::read(password_file, "Vault password: ")?;
    let session = vault.unlock(&password)?;
    Ok(session)
}

/// Opens a vault, unlocks it, runs `action`, and persists the result.
///
/// Every command that mutates the vault must go through this helper.
/// Without it, the change happens in memory and is discarded when the
/// process exits, because each CLI invocation is a fresh process that
/// starts from the on-disk state.
///
/// # Errors
///
/// Propagates any error from unlocking, from `action`, or from the
/// final `lock()`. When `action` fails, the vault is left untouched:
/// `lock()` is not called.
pub fn mutate_vault<F, R>(
    vault_path: &Path,
    password_file: Option<&Path>,
    action: F,
) -> Result<R, CliError>
where
    F: FnOnce(&mut Session) -> Result<R, CliError>,
{
    let mut session = unlock_session(vault_path, password_file)?;
    let result = action(&mut session)?;
    session.lock()?;
    Ok(result)
}
