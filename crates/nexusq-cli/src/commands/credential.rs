//! `nexusq credential` — issue and verify credentials.

use std::fs;

use nexusq_core::identity::IdentityId;
use nexusq_core::vault::Timestamp;
use serde_json::json;

use crate::GlobalOptions;
use crate::cli::{
    CredentialCommand, CredentialIssueArgs, CredentialRevokeArgs, CredentialVerifyArgs,
};
use crate::error::CliError;
use crate::output::Output;

use super::unlock_session;

/// Runs a `credential` subcommand.
pub fn run(command: CredentialCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        CredentialCommand::Issue(args) => issue(args, global),
        CredentialCommand::Verify(args) => verify(args, global),
        CredentialCommand::Revoke(args) => revoke(args, global),
    }
}

fn issue(args: CredentialIssueArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let issuer: IdentityId = args
        .issuer
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid issuer id: {e}")))?;
    let subject: IdentityId = args
        .subject
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid subject id: {e}")))?;

    // The claims must be a JSON string. We validate by parsing and
    // re-serializing so the stored bytes are canonical.
    let claims_value: serde_json::Value = serde_json::from_str(&args.claims)
        .map_err(|e| CliError::Usage(format!("claims are not valid JSON: {e}")))?;
    let claims = serde_json::to_vec(&claims_value)
        .map_err(|e| CliError::Generic(format!("failed to serialize claims: {e}")))?;

    let expires_at = args.expires_at.map(Timestamp::from_secs);

    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    let bytes = session
        .issue_credential(&issuer, subject.clone(), claims, expires_at)
        .map_err(CliError::from)?;

    fs::write(&args.output_path, &bytes).map_err(|e| {
        CliError::Io(format!(
            "failed to write {}: {e}",
            args.output_path.display()
        ))
    })?;

    let expiry = match args.expires_at {
        Some(secs) => secs.to_string(),
        None => "never".to_string(),
    };

    let human = format!(
        "Credential issued\nIssuer:  {}\nSubject: {}\nOutput:  {}\nExpires: {}",
        issuer.as_str(),
        subject.as_str(),
        args.output_path.display(),
        expiry,
    );
    let json = json!({
        "issuer": issuer.as_str(),
        "subject": subject.as_str(),
        "output": args.output_path.to_string_lossy(),
        "expires_at": args.expires_at,
        "size": bytes.len(),
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn verify(args: CredentialVerifyArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let bytes = fs::read(&args.input)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", args.input.display())))?;

    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    let credential = session.verify_credential(&bytes).map_err(CliError::from)?;

    // Claims are stored as JSON; present them as a JSON value in the
    // output if they parse, otherwise as a hex blob.
    let claims_value: Option<serde_json::Value> = serde_json::from_slice(credential.claims()).ok();
    let claims_repr = match &claims_value {
        Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "(unrepresentable)".into()),
        None => format!("<{} bytes>", credential.claims().len()),
    };

    let expires_repr = credential
        .expires_at
        .map(|t| t.as_secs().to_string())
        .unwrap_or_else(|| "never".to_string());

    let human = format!(
        "Credential valid\nIssuer:  {}\nSubject: {}\nIssued:  {}\nExpires: {}\nClaims:  {}",
        credential.issuer.as_str(),
        credential.subject.as_str(),
        credential.issued_at.as_secs(),
        expires_repr,
        claims_repr,
    );
    let json = json!({
        "valid": true,
        "issuer": credential.issuer.as_str(),
        "subject": credential.subject.as_str(),
        "issued_at": credential.issued_at.as_secs(),
        "expires_at": credential.expires_at.map(|t| t.as_secs()),
        "claims": claims_value,
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn revoke(args: CredentialRevokeArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let mut session = unlock_session(&args.vault, args.password_file.as_deref())?;
    let bytes = std::fs::read(&args.input)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", args.input.display())))?;
    session.revoke_credential(&bytes).map_err(CliError::from)?;
    session.lock().map_err(CliError::from)?;
    if !global.quiet {
        println!("Credential revoked");
    }
    Ok(())
}
