//! Password input for the CLI.
//!
//! Two input paths:
//!
//! - **Interactive**: read from a TTY with a prompt and echo disabled.
//!   This is the default and the safest option for humans.
//! - **File**: read the whole contents of a file whose path the user
//!   passed with `--password-file`. Used by scripts and CI, where no
//!   TTY is available.
//!
//! Passing the password on the command line is not supported: it
//! lands in shell history and process listings.

use std::fs;
use std::path::Path;

use crate::error::CliError;
use zeroize::Zeroizing;

/// Reads a password from a file.
///
/// The file's contents are read as-is after stripping one trailing
/// newline (or CRLF), so a plain `echo "hunter2" > pw` works as
/// expected without a trailing byte creeping into the derivation.
///
/// # Errors
///
/// Returns [`CliError::Io`] if the file cannot be read.
pub fn from_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let bytes = fs::read(path).map_err(|e| {
        CliError::Io(format!(
            "failed to read password file {}: {e}",
            path.display()
        ))
    })?;
    Ok(Zeroizing::new(strip_trailing_newline(bytes)))
}

/// Reads a password interactively with a prompt.
///
/// If `confirm` is `true`, the user is asked twice and the two inputs
/// must match. Used when creating a new password (vault, backup) so a
/// typo does not lock the user out.
///
/// # Errors
///
/// Returns [`CliError::Usage`] if the inputs do not match, or
/// [`CliError::Io`] if reading from the terminal fails.
pub fn from_prompt(prompt: &str, confirm: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let first = rpassword::prompt_password(prompt)
        .map_err(|e| CliError::Io(format!("failed to read password: {e}")))?;

    if !confirm {
        return Ok(Zeroizing::new(first.into_bytes()));
    }

    let second = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| CliError::Io(format!("failed to read confirmation: {e}")))?;

    if first != second {
        return Err(CliError::Usage("passwords do not match".into()));
    }

    Ok(Zeroizing::new(first.into_bytes()))
}

/// Reads a password for an existing resource.
///
/// Uses the file when `password_file` is `Some`, otherwise prompts.
///
/// # Errors
///
/// Propagates errors from [`from_file`] and [`from_prompt`].
pub fn read(password_file: Option<&Path>, prompt: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match password_file {
        Some(path) => from_file(path),
        None => from_prompt(prompt, false),
    }
}

/// Reads a password for a resource that is being created.
///
/// Like [`read`], but the interactive prompt asks twice.
///
/// # Errors
///
/// Propagates errors from [`from_file`] and [`from_prompt`].
pub fn read_new(
    password_file: Option<&Path>,
    prompt: &str,
) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match password_file {
        Some(path) => from_file(path),
        None => from_prompt(prompt, true),
    }
}

/// Strips a single trailing `\n` or `\r\n` from the input.
fn strip_trailing_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::TempDir;

    #[test]
    fn strips_lf() {
        assert_eq!(strip_trailing_newline(b"pw\n".to_vec()), b"pw");
    }

    #[test]
    fn strips_crlf() {
        assert_eq!(strip_trailing_newline(b"pw\r\n".to_vec()), b"pw");
    }

    #[test]
    fn keeps_internal_newlines() {
        assert_eq!(
            strip_trailing_newline(b"line1\nline2\n".to_vec()),
            b"line1\nline2"
        );
    }

    #[test]
    fn leaves_no_newline_untouched() {
        assert_eq!(strip_trailing_newline(b"pw".to_vec()), b"pw");
    }

    #[test]
    fn from_file_reads_and_strips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pw.txt");
        {
            let mut f = fs::File::create(&path).unwrap();
            writeln!(f, "hunter2").unwrap();
        }
        assert_eq!(from_file(&path).unwrap(), b"hunter2");
    }

    #[test]
    fn from_file_fails_on_missing_file() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.txt");
        let err = from_file(&missing).unwrap_err();
        assert!(matches!(err, CliError::Io(_)));
    }
}
