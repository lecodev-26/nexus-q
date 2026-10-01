//! `nexusq vault` — vault management.

use nexusq_core::vault::Vault;
use serde_json::json;

use crate::GlobalOptions;
use crate::cli::{VaultCommand, VaultCreateArgs, VaultStatusArgs};
use crate::error::CliError;
use crate::output::Output;
use crate::passwords;

/// Runs a `vault` subcommand.
pub fn run(command: VaultCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        VaultCommand::Create(args) => create(args, global),
        VaultCommand::Status(args) => status(args, global),
    }
}

fn create(args: VaultCreateArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let password = passwords::read_new(args.password_file.as_deref(), "New vault password: ")?;
    let vault = Vault::create(&args.path, &password, args.label.clone())?;

    let path = vault.path().display().to_string();
    let label = args.label.as_deref().unwrap_or("(none)");

    let human = format!("Vault created at {path}\nLabel: {label}");
    let json = json!({
        "path": path,
        "label": args.label,
        "status": "created",
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn status(args: VaultStatusArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let vault = Vault::open(&args.path)?;
    let header = vault.header();
    let kdf = header.kdf;

    let path = args.path.display().to_string();
    let human = format!(
        "Path:    {path}\n\
         Format:  v{}\n\
         KDF:     {} ({} MiB, {} iterations, parallelism {})\n\
         Salt:    {} bytes\n\
         State:   locked",
        header.version,
        kdf.algorithm.as_str(),
        kdf.memory_kib / 1024,
        kdf.iterations,
        kdf.parallelism,
        header.salt.len(),
    );

    let json = json!({
        "path": path,
        "format_version": header.version,
        "flags": header.flags,
        "kdf": {
            "algorithm": kdf.algorithm.as_str(),
            "memory_kib": kdf.memory_kib,
            "iterations": kdf.iterations,
            "parallelism": kdf.parallelism,
            "output_len": kdf.output_len,
        },
        "salt_len": header.salt.len(),
        "state": "locked",
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}
