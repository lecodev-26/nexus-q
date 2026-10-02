//! Persistent storage and on-disk formats.

pub mod audit_event;
pub mod audit_log;
pub mod audit_segment;
pub mod backup;
pub mod db;

pub use audit_event::{
    AuditEvent, AuditEventSpec, EventOutcome, EventType, GENESIS_HASH, HASH_LEN,
};
pub use audit_log::{AuditLog, AuditLogConfig, DEFAULT_MAX_EVENTS};
pub use audit_segment::{
    AuditSegment, FORMAT_VERSION as AUDIT_FORMAT_VERSION, MAGIC as AUDIT_MAGIC, MAX_EVENT_LEN,
    SEGMENT_ID_LEN, SegmentId,
};
pub use backup::{
    BackupError, BackupHeader, FORMAT_VERSION as BACKUP_FORMAT_VERSION, MAGIC as BACKUP_MAGIC,
};
pub use db::{
    DbError, FORMAT_VERSION as DB_FORMAT_VERSION, MAGIC as DB_MAGIC, Record, RecordKind, StorageDb,
};

/// Error type for storage operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// Database operation failed.
    #[error("db error: {0}")]
    Db(#[from] DbError),

    /// Backup operation failed.
    #[error("backup error: {0}")]
    Backup(#[from] BackupError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_db_error() {
        let err: StorageError = DbError::BadMagic.into();
        assert!(matches!(err, StorageError::Db(_)));
    }

    #[test]
    fn from_backup_error() {
        let err: StorageError = BackupError::BadMagic.into();
        assert!(matches!(err, StorageError::Backup(_)));
    }
}
