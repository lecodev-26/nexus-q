//! Persistent storage and on-disk formats.

pub mod db;

pub use db::{
    DbError, FORMAT_VERSION as DB_FORMAT_VERSION, MAGIC as DB_MAGIC, Record, RecordKind, StorageDb,
};
