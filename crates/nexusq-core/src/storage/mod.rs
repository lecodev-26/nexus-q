//! Persistent storage and on-disk formats.

pub mod audit_event;
pub mod db;

pub use audit_event::{
    AuditEvent, AuditEventSpec, EventOutcome, EventType, GENESIS_HASH, HASH_LEN,
};
pub use db::{
    DbError, FORMAT_VERSION as DB_FORMAT_VERSION, MAGIC as DB_MAGIC, Record, RecordKind, StorageDb,
};
