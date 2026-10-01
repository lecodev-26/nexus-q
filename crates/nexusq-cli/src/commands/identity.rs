//! `nexusq identity` — identity management.

use serde_json::{Value, json};

use crate::GlobalOptions;
use crate::cli::{IdentityCommand, IdentityCreateArgs, IdentityListArgs};
use crate::error::CliError;
use crate::output::Output;

use super::{mutate_vault, unlock_session};

/// Runs an `identity` subcommand.
pub fn run(command: IdentityCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        IdentityCommand::Create(args) => create(args, global),
        IdentityCommand::List(args) => list(args, global),
    }
}

fn create(args: IdentityCreateArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let label = args.label.clone();
    let identity_id = mutate_vault(&args.vault, args.password_file.as_deref(), |session| {
        session.create_identity(label).map_err(CliError::from)
    })?;

    let label_str = args.label.as_deref().unwrap_or("(none)");
    let human = format!(
        "Identity created: {}\nLabel:            {}",
        identity_id.as_str(),
        label_str,
    );
    let json = json!({
        "identity_id": identity_id.as_str(),
        "label": args.label,
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn list(args: IdentityListArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let session = unlock_session(&args.vault, args.password_file.as_deref())?;

    let mut json_entries = Vec::new();
    let mut human_lines = Vec::new();

    for identity in session.list_identities() {
        let md = &identity.metadata;
        json_entries.push(json!({
            "identity_id": identity.id.as_str(),
            "label": md.label,
            "status": md.status.as_str(),
            "version": md.version,
            "signing_key": identity.signing_key.as_str(),
            "created_at": md.created_at.as_secs(),
        }));
        human_lines.push(format!(
            "{:40}  {:12}  {:10}  v{}",
            identity.id.as_str(),
            md.label.as_deref().unwrap_or("-"),
            md.status.as_str(),
            md.version,
        ));
    }

    let human = if human_lines.is_empty() {
        "(no identities)".to_string()
    } else {
        human_lines.join("\n")
    };
    let json = Value::Array(json_entries);

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}
