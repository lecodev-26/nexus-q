//! `nexusq data` — encrypt and decrypt files.

use std::fs;

use nexusq_core::vault::KeyId;
use serde_json::json;

use crate::GlobalOptions;
use crate::cli::{DataCommand, DataDecryptArgs, DataEncryptArgs};
use crate::error::CliError;
use crate::output::Output;

use super::{mutate_vault, unlock_session};

/// Runs a `data` subcommand.
pub fn run(command: DataCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        DataCommand::Encrypt(args) => encrypt(args, global),
        DataCommand::Decrypt(args) => decrypt(args, global),
    }
}

fn encrypt(args: DataEncryptArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let key_id: KeyId = args
        .key_id
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid key id: {e}")))?;

    let metadata = args
        .metadata
        .as_deref()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();

    let input = args.input.clone();
    let output_path = mutate_vault(&args.vault, args.password_file.as_deref(), |session| {
        session
            .encrypt_file(&input, &key_id, metadata)
            .map_err(CliError::from)
    })?;

    let input_size = fs::metadata(&args.input).map(|m| m.len()).unwrap_or(0);

    let human = format!(
        "Encrypted: {}\nKey:       {}\nPlaintext: {} bytes",
        output_path.display(),
        key_id.as_str(),
        input_size,
    );
    let json = json!({
        "output": output_path.to_string_lossy(),
        "key_id": key_id.as_str(),
        "plaintext_size": input_size,
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn decrypt(args: DataDecryptArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let input = args.input.clone();
    let output = args.output_path.clone();
    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    session
        .decrypt_file(&input, &output)
        .map_err(CliError::from)?;

    let output_size = fs::metadata(&output).map(|m| m.len()).unwrap_or(0);

    let human = format!(
        "Decrypted: {}\nPlaintext: {} bytes",
        output.display(),
        output_size,
    );
    let json = json!({
        "output": output.to_string_lossy(),
        "plaintext_size": output_size,
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}
