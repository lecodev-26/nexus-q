//! `nexusq key` — key management.

use nexusq_core::vault::{Algorithm, KeyId, KeyStatus, Purpose};
use serde_json::{Value, json};

use crate::GlobalOptions;
use crate::cli::{AlgorithmArg, KeyCommand, KeyGenerateArgs, KeyInfoArgs, KeyListArgs, PurposeArg};
use crate::error::CliError;
use crate::output::Output;

use super::{mutate_vault, unlock_session};

/// Runs a `key` subcommand.
pub fn run(command: KeyCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        KeyCommand::Generate(args) => generate(args, global),
        KeyCommand::List(args) => list(args, global),
        KeyCommand::Info(args) => info(args, global),
    }
}

fn generate(args: KeyGenerateArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let algorithm = to_algorithm(args.algorithm);
    let purpose = to_purpose(args.purpose);
    let activate = args.activate;

    let (key_id, status) = mutate_vault(&args.vault, args.password_file.as_deref(), |session| {
        let key_id = session.generate_key(algorithm, purpose)?;
        if activate {
            session.activate_key(&key_id)?;
        }
        let status = session
            .find_key(&key_id)
            .map(|r| r.status())
            .unwrap_or(KeyStatus::Generated);
        Ok((key_id, status))
    })?;

    let human = format!(
        "Key generated: {}\nAlgorithm:  {}\nPurpose:    {}\nStatus:     {}",
        key_id.as_str(),
        algorithm.as_str(),
        purpose.as_str(),
        status.as_str(),
    );
    let json = json!({
        "key_id": key_id.as_str(),
        "algorithm": algorithm.as_str(),
        "purpose": purpose.as_str(),
        "status": status.as_str(),
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn list(args: KeyListArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let session = unlock_session(&args.vault, args.password_file.as_deref())?;

    let mut json_entries = Vec::new();
    let mut human_lines = Vec::new();
    for record in session.list_keys() {
        let md = &record.metadata;
        json_entries.push(json!({
            "key_id": md.key_id.as_str(),
            "algorithm": md.algorithm.as_str(),
            "purpose": md.purpose.as_str(),
            "status": md.status.as_str(),
            "version": md.version,
            "created_at": md.created_at.as_secs(),
            "hardware_backed": md.hardware_backed,
        }));
        human_lines.push(format!(
            "{:40}  {:16}  {:12}  {}",
            md.key_id.as_str(),
            md.algorithm.as_str(),
            md.purpose.as_str(),
            md.status.as_str(),
        ));
    }

    let human = if human_lines.is_empty() {
        "(no keys)".to_string()
    } else {
        human_lines.join("\n")
    };
    let json = Value::Array(json_entries);

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn info(args: KeyInfoArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let key_id: KeyId = args
        .key_id
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid key id: {e}")))?;

    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    let record = session
        .find_key(&key_id)
        .ok_or_else(|| CliError::Generic(format!("key not found: {}", key_id.as_str())))?;
    let md = &record.metadata;

    let public_key_hex = record
        .public_key_bytes()
        .map(hex::encode)
        .unwrap_or_else(|| "(none)".into());

    let human = format!(
        "Key:        {}\n\
         Algorithm:  {}\n\
         Purpose:    {}\n\
         Status:     {}\n\
         Version:    {}\n\
         Created:    {}\n\
         Hardware:   {}\n\
         Public key: {}",
        md.key_id.as_str(),
        md.algorithm.as_str(),
        md.purpose.as_str(),
        md.status.as_str(),
        md.version,
        md.created_at.as_secs(),
        if md.hardware_backed { "yes" } else { "no" },
        public_key_hex,
    );

    let json = json!({
        "key_id": md.key_id.as_str(),
        "algorithm": md.algorithm.as_str(),
        "purpose": md.purpose.as_str(),
        "status": md.status.as_str(),
        "version": md.version,
        "created_at": md.created_at.as_secs(),
        "created_by": md.created_by,
        "created_from": md.created_from.as_str(),
        "hardware_backed": md.hardware_backed,
        "owner": md.owner,
        "public_key_hex": record.public_key_bytes().map(hex::encode),
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn to_algorithm(arg: AlgorithmArg) -> Algorithm {
    match arg {
        AlgorithmArg::Ed25519 => Algorithm::Ed25519,
        AlgorithmArg::MlKem768 => Algorithm::MlKem768,
        AlgorithmArg::Aes256Gcm => Algorithm::Aes256Gcm,
        AlgorithmArg::ChaCha20Poly1305 => Algorithm::ChaCha20Poly1305,
    }
}

fn to_purpose(arg: PurposeArg) -> Purpose {
    match arg {
        PurposeArg::Sign => Purpose::Sign,
        PurposeArg::Encrypt => Purpose::Encrypt,
        PurposeArg::Decrypt => Purpose::Decrypt,
        PurposeArg::KeyAgreement => Purpose::KeyAgreement,
        PurposeArg::Wrap => Purpose::Wrap,
    }
}
