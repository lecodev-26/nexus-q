//! `nexusq sign` — sign and verify files.

use std::fs;
use std::path::PathBuf;

use nexusq_core::crypto::sign::Signature;
use nexusq_core::identity::IdentityId;
use serde_json::json;

use crate::GlobalOptions;
use crate::cli::{SignCommand, SignSignArgs, SignVerifyArgs};
use crate::error::CliError;
use crate::output::Output;

use super::unlock_session;

/// Runs a `sign` subcommand.
pub fn run(command: SignCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        SignCommand::Sign(args) => sign(args, global),
        SignCommand::Verify(args) => verify(args, global),
    }
}

fn sign(args: SignSignArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let identity_id: IdentityId = args
        .identity
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid identity id: {e}")))?;

    let message = fs::read(&args.input)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", args.input.display())))?;

    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    let signature = session
        .identity_sign(&identity_id, &message)
        .map_err(CliError::from)?;

    let sig_path = signature_path(&args.input);
    let sig_hex = hex::encode(signature.to_bytes().as_slice());
    let mut contents = sig_hex;
    contents.push('\n');
    fs::write(&sig_path, contents.as_bytes())
        .map_err(|e| CliError::Io(format!("failed to write {}: {e}", sig_path.display())))?;

    let human = format!(
        "Signed:    {}\nSignature: {}\nIdentity:  {}",
        args.input.display(),
        sig_path.display(),
        identity_id.as_str(),
    );
    let json = json!({
        "input": args.input.to_string_lossy(),
        "signature": sig_path.to_string_lossy(),
        "identity": identity_id.as_str(),
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn verify(args: SignVerifyArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let identity_id: IdentityId = args
        .identity
        .parse()
        .map_err(|e| CliError::Usage(format!("invalid identity id: {e}")))?;

    let message = fs::read(&args.input)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", args.input.display())))?;

    let sig_hex = fs::read_to_string(&args.signature)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", args.signature.display())))?;
    let sig_hex = sig_hex.trim();
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| CliError::Usage(format!("signature file is not valid hex: {e}")))?;
    let signature = Signature::from_bytes(&sig_bytes)
        .map_err(|e| CliError::Usage(format!("invalid signature: {e}")))?;

    let session = unlock_session(&args.vault, args.password_file.as_deref())?;
    session
        .identity_verify(&identity_id, &message, &signature)
        .map_err(|_| CliError::Integrity("signature verification failed".into()))?;

    let human = format!(
        "Signature valid\nFile:     {}\nIdentity: {}",
        args.input.display(),
        identity_id.as_str(),
    );
    let json = json!({
        "valid": true,
        "input": args.input.to_string_lossy(),
        "identity": identity_id.as_str(),
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

/// Builds the `.sig` path for a given input.
fn signature_path(input: &std::path::Path) -> PathBuf {
    let mut name = input.file_name().unwrap_or_default().to_os_string();
    name.push(".sig");
    let parent = input.parent().unwrap_or_else(|| std::path::Path::new("."));
    parent.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn signature_path_appends_extension() {
        let p = signature_path(Path::new("doc.txt"));
        assert_eq!(p, PathBuf::from("doc.txt.sig"));
    }

    #[test]
    fn signature_path_keeps_parent() {
        let p = signature_path(Path::new("/tmp/doc.txt"));
        assert_eq!(p, PathBuf::from("/tmp/doc.txt.sig"));
    }

    #[test]
    fn signature_path_does_not_double_up() {
        let p = signature_path(Path::new("doc.txt.sig"));
        assert_eq!(p, PathBuf::from("doc.txt.sig.sig"));
    }
}
