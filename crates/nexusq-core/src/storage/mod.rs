//! Persistent storage and on-disk formats.

pub mod audit_event;
pub mod audit_segment;
pub mod db;

pub use audit_event::{
    AuditEvent, AuditEventSpec, EventOutcome, EventType, GENESIS_HASH, HASH_LEN,
};
pub use audit_segment::{
    AuditSegment, FORMAT_VERSION as AUDIT_FORMAT_VERSION, MAGIC as AUDIT_MAGIC, MAX_EVENT_LEN,
    SEGMENT_ID_LEN, SegmentId,
};
pub use db::{
    DbError, FORMAT_VERSION as DB_FORMAT_VERSION, MAGIC as DB_MAGIC, Record, RecordKind, StorageDb,
};
