//! Vault metadata types.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultMeta {
    pub name: String,
    pub version: u8,
    pub created_at: String,
    pub entries: Vec<EntryMeta>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntryMeta {
    pub id: String,
    pub original_name: String,
    pub added_at: String,
    pub size_bytes: u64,
}

impl VaultMeta {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: 1,
            created_at: epoch_seconds_now(),
            entries: Vec::new(),
        }
    }
}

impl EntryMeta {
    pub fn new(original_name: &str, size_bytes: u64) -> Self {
        Self {
            id: entry_id(original_name),
            original_name: original_name.to_string(),
            added_at: epoch_seconds_now(),
            size_bytes,
        }
    }
}

pub fn entry_id(original_name: &str) -> String {
    let digest = Sha256::digest(original_name.as_bytes());
    hex::encode(digest)
}

fn epoch_seconds_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
        .to_string()
}
