//! `nexusq audit` — audit log operations.

use std::fs;

use nexusq_core::storage::{AuditLog, AuditSegment};
use serde_json::{Value, json};

use crate::GlobalOptions;
use crate::cli::{AuditCommand, AuditShowArgs, AuditVerifyArgs};
use crate::error::CliError;
use crate::output::Output;

/// Runs an `audit` subcommand.
pub fn run(command: AuditCommand, global: &GlobalOptions) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify(args) => verify(args, global),
        AuditCommand::Show(args) => show(args, global),
    }
}

fn verify(args: AuditVerifyArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let log = AuditLog::open(&args.audit_dir).map_err(|e| {
        CliError::Integrity(format!(
            "failed to open audit log at {}: {e}",
            args.audit_dir.display()
        ))
    })?;

    log.verify_all()
        .map_err(|e| CliError::Integrity(format!("audit chain verification failed: {e}")))?;

    let segments = log.segment_count().unwrap_or(0);

    let human = format!(
        "Audit chain valid\nDirectory: {}\nSegments:  {}",
        args.audit_dir.display(),
        segments,
    );
    let json = json!({
        "valid": true,
        "directory": args.audit_dir.to_string_lossy(),
        "segments": segments,
    });

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

fn show(args: AuditShowArgs, global: &GlobalOptions) -> Result<(), CliError> {
    let events = collect_events(&args.audit_dir)?;
    let events = match args.last {
        Some(n) => {
            let len = events.len();
            events.into_iter().skip(len.saturating_sub(n)).collect()
        }
        None => events,
    };

    let mut human_lines = Vec::new();
    let mut json_entries = Vec::new();
    for event in &events {
        human_lines.push(format!(
            "{:>6}  {:<22}  {:<16}  {:<40}  {}",
            event.index,
            event.event_type.as_str(),
            event.actor,
            event.subject,
            event.outcome.as_str(),
        ));
        json_entries.push(json!({
            "index": event.index,
            "timestamp": event.timestamp.as_secs(),
            "event_type": event.event_type.as_str(),
            "actor": event.actor,
            "subject": event.subject,
            "outcome": event.outcome.as_str(),
            "hash": hex::encode(&event.hash),
            "prev_hash": hex::encode(&event.prev_hash),
        }));
    }

    let human = if human_lines.is_empty() {
        "(no events)".to_string()
    } else {
        human_lines.join("\n")
    };
    let json = Value::Array(json_entries);

    if !global.quiet {
        println!("{}", Output::new(human, json).render(global.output));
    }
    Ok(())
}

/// Reads every event from every segment, in order.
fn collect_events(
    dir: &std::path::Path,
) -> Result<Vec<nexusq_core::storage::AuditEvent>, CliError> {
    let mut segments: Vec<(u32, std::path::PathBuf)> = Vec::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| CliError::Io(format!("failed to read {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CliError::Io(format!("failed to read entry: {e}")))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(number) = parse_segment_number(&path) {
            segments.push((number, path));
        }
    }
    segments.sort_by_key(|(n, _)| *n);

    let mut events = Vec::new();
    for (_number, path) in segments {
        let segment = AuditSegment::open(&path)
            .map_err(|e| CliError::Integrity(format!("failed to open {}: {e}", path.display())))?;
        events.extend(segment.events().iter().cloned());
    }
    Ok(events)
}

/// Parses `audit-NNNNN.nqa` into its numeric part.
fn parse_segment_number(path: &std::path::Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("audit-")?;
    let digits = rest.strip_suffix(".nqa")?;
    if digits.len() != 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_valid_segment_names() {
        assert_eq!(parse_segment_number(Path::new("audit-00001.nqa")), Some(1));
        assert_eq!(
            parse_segment_number(Path::new("audit-12345.nqa")),
            Some(12345)
        );
    }

    #[test]
    fn rejects_other_names() {
        assert_eq!(parse_segment_number(Path::new("audit.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("audit-abc.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("audit-1.nqa")), None);
        assert_eq!(parse_segment_number(Path::new("other-00001.nqa")), None);
    }
}
