//! Local health and diagnostics commands.
//!
//! These commands are read-only and never unlock a vault or print secret data.

use nexusq_core::{Metrics, OBSERVABILITY_SCHEMA_VERSION, vault::Vault};
use serde_json::json;

use crate::{GlobalOptions, cli::HealthArgs, error::CliError, output::Output};

pub fn health(args: HealthArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let vault_status = match args.vault.as_ref() {
        Some(path) => {
            Vault::open(path)?;
            "available"
        }
        None => "not_checked",
    };
    let json = json!({
        "status": "ok",
        "observability_schema": OBSERVABILITY_SCHEMA_VERSION,
        "hardware_backend": "software",
        "vault": vault_status,
    });
    let human = format!(
        "Status:              ok\nObservability schema: v{}\nHardware backend:     software\nVault:                {}",
        OBSERVABILITY_SCHEMA_VERSION, vault_status
    );
    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

pub fn diagnostics(args: HealthArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let mut vault_info = json!(null);
    let mut vault_human = "not checked".to_owned();
    if let Some(path) = args.vault.as_ref() {
        let vault = Vault::open(path)?;
        let header = vault.header();
        let kdf = header.kdf;
        vault_info = json!({
            "path": path.to_string_lossy(),
            "format_version": header.version,
            "state": "locked",
            "kdf": {
                "algorithm": kdf.algorithm.as_str(),
                "memory_kib": kdf.memory_kib,
                "iterations": kdf.iterations,
                "parallelism": kdf.parallelism,
            },
        });
        vault_human = format!(
            "{} (format v{}, locked, KDF {} / {} MiB / {} iterations / parallelism {})",
            path.display(),
            header.version,
            kdf.algorithm.as_str(),
            kdf.memory_kib / 1024,
            kdf.iterations,
            kdf.parallelism
        );
    }
    let metrics = Metrics::default();
    let json = json!({
        "status": "ok",
        "observability_schema": OBSERVABILITY_SCHEMA_VERSION,
        "hardware_backend": "software",
        "vault": vault_info,
        "metrics": {
            "process_uptime_seconds": metrics.uptime().as_secs_f64(),
            "metrics_endpoint": "server-only",
        },
    });
    let human = format!(
        "Status:              ok\nObservability schema: v{}\nHardware backend:     software\nVault:                {}\nMetrics:              server exposes Prometheus-compatible /metrics",
        OBSERVABILITY_SCHEMA_VERSION, vault_human
    );
    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_health_and_diagnostics() {
        let health = Cli::try_parse_from(["nexusq", "health"]).unwrap();
        assert!(matches!(health.command, Command::Health(_)));
        let diagnostics =
            Cli::try_parse_from(["nexusq", "diagnostics", "--vault", "vault.nqv"]).unwrap();
        assert!(matches!(diagnostics.command, Command::Diagnostics(_)));
    }
}
