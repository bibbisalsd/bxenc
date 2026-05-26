//! Vault metadata types.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VAULT_META_VERSION_V1: u8 = 1;
pub const VAULT_META_VERSION_V2: u8 = 2;
pub const VAULT_ID_LEN: usize = 16;
pub const ENTRY_ID_LEN: usize = 32;
pub const META_AAD_V1: &[u8] = b"vault.meta";
pub const META_AAD_V2: &[u8] = b"vault.meta.v2";
pub const ENTRY_AAD_V2_PREFIX: &[u8] = b"vault.entry.v2";

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultMetaV2 {
    pub name: String,
    pub version: u8,
    pub vault_id: [u8; VAULT_ID_LEN],
    pub created_at: String,
    pub entries_by_name: BTreeMap<String, EntryRecordV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntryRecordV2 {
    pub id: [u8; ENTRY_ID_LEN],
    pub original_name: String,
    pub added_at: String,
    pub size_bytes: u64,
}

impl VaultMeta {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: VAULT_META_VERSION_V1,
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

impl VaultMetaV2 {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: VAULT_META_VERSION_V2,
            vault_id: random_array(),
            created_at: epoch_seconds_now(),
            entries_by_name: BTreeMap::new(),
        }
    }

    pub fn insert_entry(&mut self, original_name: &str, size_bytes: u64) -> Result<(), String> {
        if self.entries_by_name.contains_key(original_name) {
            return Err(format!("vault entry already exists: {original_name}"));
        }

        let mut entry = EntryRecordV2::new(original_name, size_bytes);
        while self
            .entries_by_name
            .values()
            .any(|existing| existing.id == entry.id)
        {
            entry = EntryRecordV2::new(original_name, size_bytes);
        }

        self.entries_by_name
            .insert(original_name.to_string(), entry);
        Ok(())
    }

    pub fn list_entries(&self) -> Vec<EntryMeta> {
        self.entries_by_name
            .values()
            .map(EntryMeta::from_v2)
            .collect()
    }
}

impl EntryRecordV2 {
    pub fn new(original_name: &str, size_bytes: u64) -> Self {
        Self {
            id: random_array(),
            original_name: original_name.to_string(),
            added_at: epoch_seconds_now(),
            size_bytes,
        }
    }

    pub fn id_hex(&self) -> String {
        entry_id_hex(&self.id)
    }
}

impl EntryMeta {
    pub fn from_v2(entry: &EntryRecordV2) -> Self {
        Self {
            id: entry.id_hex(),
            original_name: entry.original_name.clone(),
            added_at: entry.added_at.clone(),
            size_bytes: entry.size_bytes,
        }
    }
}

pub fn entry_id(original_name: &str) -> String {
    let digest = Sha256::digest(original_name.as_bytes());
    hex::encode(digest)
}

pub fn entry_id_hex(entry_id: &[u8; ENTRY_ID_LEN]) -> String {
    hex::encode(entry_id)
}

pub fn entry_aad_v2(vault_id: &[u8; VAULT_ID_LEN], entry_id: &[u8; ENTRY_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_AAD_V2_PREFIX.len() + VAULT_ID_LEN + ENTRY_ID_LEN);
    aad.extend_from_slice(ENTRY_AAD_V2_PREFIX);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(entry_id);
    aad
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn epoch_seconds_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
        .to_string()
}
