//! Vault storage operations.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{
        engine::{self, Credential},
        kdf,
    },
    error::{BxError, BxResult},
    vault::meta::{
        entry_aad_v2, entry_id_hex, EntryMeta, EntryRecordV2, VaultMeta, VaultMetaV2, META_AAD_V1,
        META_AAD_V2, VAULT_META_VERSION_V1, VAULT_META_VERSION_V2,
    },
};

pub const META_FILE: &str = "vault.meta.bxenc";
pub const ENTRIES_DIR: &str = "entries";
pub const LOCK_FILE: &str = ".lock";
pub const STAGE_ENTRIES_DIR: &str = "entries.v2.stage";

pub struct Vault {
    meta: VaultMetadata,
    list_cache: Vec<EntryMeta>,
    root: PathBuf,
    credential: StoredCredential,
}

enum VaultMetadata {
    V1(VaultMeta),
    V2(VaultMetaV2),
}

pub struct VaultLock {
    path: PathBuf,
    _file: File,
}

#[derive(Clone)]
enum PendingEntry {
    V1(EntryMeta),
    V2(EntryRecordV2),
}

enum RemovedEntry {
    V1 { index: usize, entry: EntryMeta },
    V2(EntryRecordV2),
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub enum StoredCredential {
    Password(Zeroizing<Vec<u8>>),
    Keyfile(Zeroizing<[u8; kdf::KEY_LEN]>),
}

impl StoredCredential {
    pub fn from_credential(credential: Credential<'_>) -> Self {
        match credential {
            Credential::Password(password) => Self::Password(Zeroizing::new(password.to_vec())),
            Credential::Keyfile(keyfile) => {
                let mut key = Zeroizing::new([0u8; kdf::KEY_LEN]);
                key.copy_from_slice(keyfile);
                Self::Keyfile(key)
            }
        }
    }

    pub fn as_credential(&self) -> Credential<'_> {
        match self {
            Self::Password(password) => Credential::Password(password.as_slice()),
            Self::Keyfile(keyfile) => Credential::Keyfile(keyfile),
        }
    }
}

impl VaultLock {
    pub fn acquire(root: &Path) -> BxResult<Self> {
        let path = root.join(LOCK_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        writeln!(file, "{}", std::process::id())?;
        file.sync_all()?;
        Ok(Self { path, _file: file })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Vault {
    pub fn init(root: &Path, name: &str, credential: Credential<'_>) -> BxResult<Self> {
        let meta_path = root.join(META_FILE);
        if meta_path.exists() {
            return Err(BxError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("vault already exists at {}", root.display()),
            )));
        }

        fs::create_dir_all(root.join(ENTRIES_DIR))?;
        let lock = VaultLock::acquire(root)?;

        let vault = Self::from_metadata(
            VaultMetadata::V2(VaultMetaV2::new(name)),
            root.to_path_buf(),
            credential,
        );
        vault.flush_meta_locked(&lock)?;

        Ok(vault)
    }

    pub fn open(root: &Path, credential: Credential<'_>) -> BxResult<Self> {
        let meta_path = root.join(META_FILE);
        let blob = fs::read(&meta_path)
            .map_err(|_| BxError::VaultNotFound(meta_path.display().to_string()))?;

        if let Ok(plaintext) = engine::decrypt(credential, &blob, META_AAD_V2) {
            let plaintext = Zeroizing::new(plaintext);
            let meta: VaultMetaV2 =
                bincode::deserialize(plaintext.as_slice()).map_err(|_| BxError::MetaCorrupt)?;
            if meta.version != VAULT_META_VERSION_V2 {
                return Err(BxError::MetaCorrupt);
            }
            return Ok(Self::from_metadata(
                VaultMetadata::V2(meta),
                root.to_path_buf(),
                credential,
            ));
        }

        let plaintext = Zeroizing::new(
            engine::decrypt(credential, &blob, META_AAD_V1).map_err(|_| BxError::MetaCorrupt)?,
        );
        let meta: VaultMeta =
            bincode::deserialize(plaintext.as_slice()).map_err(|_| BxError::MetaCorrupt)?;
        if meta.version != VAULT_META_VERSION_V1 {
            return Err(BxError::MetaCorrupt);
        }

        Ok(Self::from_metadata(
            VaultMetadata::V1(meta),
            root.to_path_buf(),
            credential,
        ))
    }

    pub fn add_file(&mut self, src: &Path) -> BxResult<()> {
        let name = src
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid_input("source path does not have a valid UTF-8 file name"))?;
        let plaintext = Zeroizing::new(fs::read(src)?);

        self.add_entry_bytes(name, plaintext.as_slice())
    }

    pub fn add_text(&mut self, name: &str, text: &str) -> BxResult<()> {
        let plaintext = Zeroizing::new(text.as_bytes().to_vec());

        self.add_entry_bytes(name, plaintext.as_slice())
    }

    pub fn extract(&self, entry_name: &str, dest: &Path) -> BxResult<()> {
        let entry = self.entry_access(entry_name)?;
        let blob = fs::read(self.entry_path(&entry.id_hex))?;
        let plaintext = Zeroizing::new(engine::decrypt(
            self.credential.as_credential(),
            &blob,
            &entry.aad,
        )?);

        let mut out = File::create(dest)?;
        out.write_all(plaintext.as_slice())?;
        Ok(())
    }

    pub fn remove(&mut self, entry_name: &str) -> BxResult<()> {
        let lock = VaultLock::acquire(&self.root)?;
        if matches!(self.meta, VaultMetadata::V1(_)) {
            return Err(v1_read_only_error());
        }

        let removed = self
            .remove_metadata_entry(entry_name)
            .ok_or_else(|| BxError::EntryNotFound(entry_name.to_string()))?;
        let entry_id = removed.id_hex();

        if let Err(err) = self.flush_meta_locked(&lock) {
            self.restore_removed_entry(entry_name, removed);
            self.refresh_list_cache();
            return Err(err);
        }

        self.refresh_list_cache();
        fs::remove_file(self.entry_path(&entry_id))?;
        Ok(())
    }

    pub fn list(&self) -> &[EntryMeta] {
        &self.list_cache
    }

    pub fn migrate_v1_to_v2(&mut self) -> BxResult<()> {
        let lock = VaultLock::acquire(&self.root)?;
        let VaultMetadata::V1(v1_meta) = &self.meta else {
            return Ok(());
        };
        let v1_meta = v1_meta.clone();
        let mut seen_names = HashSet::with_capacity(v1_meta.entries.len());
        for entry in &v1_meta.entries {
            if !seen_names.insert(entry.original_name.as_str()) {
                return Err(BxError::Encrypt(format!(
                    "duplicate v1 vault entry name: {}",
                    entry.original_name
                )));
            }
        }

        let stage_dir = self.root.join(STAGE_ENTRIES_DIR);
        if stage_dir.exists() {
            fs::remove_dir_all(&stage_dir)?;
        }
        fs::create_dir(&stage_dir)?;

        let mut v2_meta = VaultMetaV2::new(&v1_meta.name);
        v2_meta.created_at = v1_meta.created_at.clone();
        let mut old_entry_ids = Vec::with_capacity(v1_meta.entries.len());

        for v1_entry in &v1_meta.entries {
            let blob = fs::read(self.entry_path(&v1_entry.id))?;
            let plaintext = Zeroizing::new(engine::decrypt(
                self.credential.as_credential(),
                &blob,
                v1_entry.id.as_bytes(),
            )?);

            let mut v2_entry = EntryRecordV2::new(&v1_entry.original_name, v1_entry.size_bytes);
            while v2_meta
                .entries_by_name
                .values()
                .any(|existing| existing.id == v2_entry.id)
            {
                v2_entry = EntryRecordV2::new(&v1_entry.original_name, v1_entry.size_bytes);
            }
            v2_entry.added_at = v1_entry.added_at.clone();

            let new_entry_id = entry_id_hex(&v2_entry.id);
            let new_entry_aad = entry_aad_v2(&v2_meta.vault_id, &v2_entry.id);
            let new_blob = engine::encrypt(
                self.credential.as_credential(),
                plaintext.as_slice(),
                &new_entry_aad,
            )?;

            write_blob_atomic(
                &stage_dir,
                &stage_dir.join(format!("{new_entry_id}.bxenc")),
                &new_blob,
            )?;
            old_entry_ids.push(v1_entry.id.clone());
            v2_meta
                .entries_by_name
                .insert(v1_entry.original_name.clone(), v2_entry);
        }

        self.move_staged_entries_to_entries(&stage_dir, &v2_meta)?;
        let new_entry_ids = v2_meta
            .entries_by_name
            .values()
            .map(EntryRecordV2::id_hex)
            .collect::<Vec<_>>();

        self.meta = VaultMetadata::V2(v2_meta);
        if let Err(err) = self.flush_meta_locked(&lock) {
            for new_id in new_entry_ids {
                let _ = fs::remove_file(self.entry_path(&new_id));
            }
            let _ = fs::remove_dir_all(&stage_dir);
            self.meta = VaultMetadata::V1(v1_meta);
            self.refresh_list_cache();
            return Err(err);
        }
        self.refresh_list_cache();

        if stage_dir.exists() {
            fs::remove_dir_all(&stage_dir)?;
        }
        for old_id in old_entry_ids {
            let path = self.entry_path(&old_id);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }

        Ok(())
    }

    fn from_metadata(meta: VaultMetadata, root: PathBuf, credential: Credential<'_>) -> Self {
        let list_cache = meta.list_entries();
        Self {
            meta,
            list_cache,
            root,
            credential: StoredCredential::from_credential(credential),
        }
    }

    fn add_entry_bytes(&mut self, name: &str, plaintext: &[u8]) -> BxResult<()> {
        let lock = VaultLock::acquire(&self.root)?;
        if matches!(self.meta, VaultMetadata::V1(_)) {
            return Err(v1_read_only_error());
        }

        if self.contains_entry(name) {
            return Err(BxError::Encrypt(format!(
                "vault entry already exists: {name}"
            )));
        }

        let size_bytes = u64::try_from(plaintext.len())
            .map_err(|_| invalid_input("entry is too large to record its size"))?;
        let (pending, entry_id, entry_aad) = self.pending_entry(name, size_bytes);

        let blob = engine::encrypt(self.credential.as_credential(), plaintext, &entry_aad)?;
        write_blob_atomic(&self.entries_dir(), &self.entry_path(&entry_id), &blob)?;

        self.insert_pending_entry(name, pending);
        if let Err(err) = self.flush_meta_locked(&lock) {
            self.remove_metadata_entry(name);
            self.refresh_list_cache();
            return Err(err);
        }

        self.refresh_list_cache();
        Ok(())
    }

    #[cfg(test)]
    fn flush_meta(&self) -> BxResult<()> {
        let lock = VaultLock::acquire(&self.root)?;
        self.flush_meta_locked(&lock)
    }

    fn flush_meta_locked(&self, _lock: &VaultLock) -> BxResult<()> {
        let (plaintext, aad) = match &self.meta {
            VaultMetadata::V1(meta) => (
                bincode::serialize(meta)
                    .map(Zeroizing::new)
                    .map_err(|err| BxError::Encrypt(err.to_string()))?,
                META_AAD_V1,
            ),
            VaultMetadata::V2(meta) => (
                bincode::serialize(meta)
                    .map(Zeroizing::new)
                    .map_err(|err| BxError::Encrypt(err.to_string()))?,
                META_AAD_V2,
            ),
        };
        let blob = engine::encrypt(self.credential.as_credential(), plaintext.as_slice(), aad)?;
        write_blob_atomic(&self.root, &self.root.join(META_FILE), &blob)
    }

    fn contains_entry(&self, name: &str) -> bool {
        match &self.meta {
            VaultMetadata::V1(meta) => meta.entries.iter().any(|entry| entry.original_name == name),
            VaultMetadata::V2(meta) => meta.entries_by_name.contains_key(name),
        }
    }

    fn pending_entry(&self, name: &str, size_bytes: u64) -> (PendingEntry, String, Vec<u8>) {
        match &self.meta {
            VaultMetadata::V1(_) => {
                let entry = EntryMeta::new(name, size_bytes);
                let entry_id = entry.id.clone();
                let aad = entry_id.as_bytes().to_vec();
                (PendingEntry::V1(entry), entry_id, aad)
            }
            VaultMetadata::V2(meta) => {
                let mut entry = EntryRecordV2::new(name, size_bytes);
                while meta
                    .entries_by_name
                    .values()
                    .any(|existing| existing.id == entry.id)
                {
                    entry = EntryRecordV2::new(name, size_bytes);
                }

                let entry_id = entry_id_hex(&entry.id);
                let aad = entry_aad_v2(&meta.vault_id, &entry.id);
                (PendingEntry::V2(entry), entry_id, aad)
            }
        }
    }

    fn insert_pending_entry(&mut self, name: &str, pending: PendingEntry) {
        match (&mut self.meta, pending) {
            (VaultMetadata::V1(meta), PendingEntry::V1(entry)) => meta.entries.push(entry),
            (VaultMetadata::V2(meta), PendingEntry::V2(entry)) => {
                meta.entries_by_name.insert(name.to_string(), entry);
            }
            _ => unreachable!("pending entry version must match vault metadata"),
        }
    }

    fn remove_metadata_entry(&mut self, entry_name: &str) -> Option<RemovedEntry> {
        match &mut self.meta {
            VaultMetadata::V1(meta) => {
                let index = meta
                    .entries
                    .iter()
                    .position(|entry| entry.original_name == entry_name)?;
                let entry = meta.entries.remove(index);
                Some(RemovedEntry::V1 { index, entry })
            }
            VaultMetadata::V2(meta) => meta
                .entries_by_name
                .remove(entry_name)
                .map(RemovedEntry::V2),
        }
    }

    fn restore_removed_entry(&mut self, entry_name: &str, removed: RemovedEntry) {
        match (&mut self.meta, removed) {
            (VaultMetadata::V1(meta), RemovedEntry::V1 { index, entry }) => {
                meta.entries.insert(index, entry);
            }
            (VaultMetadata::V2(meta), RemovedEntry::V2(entry)) => {
                meta.entries_by_name.insert(entry_name.to_string(), entry);
            }
            _ => unreachable!("removed entry version must match vault metadata"),
        }
    }

    fn entry_access(&self, entry_name: &str) -> BxResult<EntryAccess> {
        match &self.meta {
            VaultMetadata::V1(meta) => {
                let entry = meta
                    .entries
                    .iter()
                    .find(|entry| entry.original_name == entry_name)
                    .ok_or_else(|| BxError::EntryNotFound(entry_name.to_string()))?;
                Ok(EntryAccess {
                    id_hex: entry.id.clone(),
                    aad: entry.id.as_bytes().to_vec(),
                })
            }
            VaultMetadata::V2(meta) => {
                let entry = meta
                    .entries_by_name
                    .get(entry_name)
                    .ok_or_else(|| BxError::EntryNotFound(entry_name.to_string()))?;
                Ok(EntryAccess {
                    id_hex: entry_id_hex(&entry.id),
                    aad: entry_aad_v2(&meta.vault_id, &entry.id),
                })
            }
        }
    }

    fn refresh_list_cache(&mut self) {
        self.list_cache = self.meta.list_entries();
    }

    fn move_staged_entries_to_entries(
        &self,
        stage_dir: &Path,
        v2_meta: &VaultMetaV2,
    ) -> BxResult<()> {
        for entry in v2_meta.entries_by_name.values() {
            let entry_id = entry.id_hex();
            let staged = stage_dir.join(format!("{entry_id}.bxenc"));
            let final_path = self.entry_path(&entry_id);
            if final_path.exists() {
                return Err(BxError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("vault entry already exists at {}", final_path.display()),
                )));
            }
            fs::rename(staged, final_path)?;
        }
        Ok(())
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join(ENTRIES_DIR)
    }

    fn entry_path(&self, entry_id: &str) -> PathBuf {
        self.entries_dir().join(format!("{entry_id}.bxenc"))
    }
}

impl VaultMetadata {
    fn list_entries(&self) -> Vec<EntryMeta> {
        match self {
            Self::V1(meta) => meta.entries.clone(),
            Self::V2(meta) => meta.list_entries(),
        }
    }
}

impl RemovedEntry {
    fn id_hex(&self) -> String {
        match self {
            Self::V1 { entry, .. } => entry.id.clone(),
            Self::V2(entry) => entry.id_hex(),
        }
    }
}

struct EntryAccess {
    id_hex: String,
    aad: Vec<u8>,
}

fn write_blob_atomic(dir: &Path, target: &Path, blob: &[u8]) -> BxResult<()> {
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.as_file_mut().write_all(blob)?;
    tmp.as_file().sync_all()?;
    tmp.persist(target).map_err(|err| BxError::Io(err.error))?;
    Ok(())
}

fn invalid_input(message: &str) -> BxError {
    BxError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn v1_read_only_error() -> BxError {
    BxError::Encrypt("v1 vaults are read-only until migration to metadata v2".to_string())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process::Command};

    use bincode::Options;
    use tempfile::tempdir;

    use super::*;
    use crate::vault::meta::entry_id;

    const PASSWORD: &[u8] = b"vault unit password";
    const TEXT_ENTRY: &str = "note.txt";
    const TEXT_BODY: &str = "vault text body";
    const LOCK_CHILD_ROOT_ENV: &str = "BXENC_LOCK_TEST_CHILD_ROOT";

    fn password() -> Credential<'static> {
        Credential::Password(PASSWORD)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn write_legacy_v1_vault(root: &Path) -> BxResult<()> {
        fs::create_dir_all(root.join(ENTRIES_DIR))?;

        let mut meta = VaultMeta::new("legacy-v1");
        let entry = EntryMeta::new(TEXT_ENTRY, TEXT_BODY.len() as u64);
        let entry_blob = engine::encrypt(password(), TEXT_BODY.as_bytes(), entry.id.as_bytes())?;
        write_blob_atomic(
            &root.join(ENTRIES_DIR),
            &root.join(ENTRIES_DIR).join(format!("{}.bxenc", entry.id)),
            &entry_blob,
        )?;

        meta.entries.push(entry);
        let plaintext = bincode::serialize(&meta)
            .map(Zeroizing::new)
            .map_err(|err| BxError::Encrypt(err.to_string()))?;
        let meta_blob = engine::encrypt(password(), plaintext.as_slice(), META_AAD_V1)?;
        write_blob_atomic(root, &root.join(META_FILE), &meta_blob)?;
        Ok(())
    }

    #[test]
    fn init_creates_encrypted_meta_not_json() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let name = "unit-test-vault-name-never-plaintext";

        Vault::init(&root, name, password())?;

        let meta_path = root.join(META_FILE);
        let raw = fs::read(&meta_path)?;

        assert!(meta_path.exists());
        assert!(!root.join("vault.meta.json").exists());
        assert!(!contains_bytes(&raw, name.as_bytes()));

        Ok(())
    }

    #[test]
    fn meta_file_raw_bytes_are_not_valid_bincode_without_decryption() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");

        Vault::init(&root, "raw-meta-test", password())?;

        let raw = fs::read(root.join(META_FILE))?;
        let decoded = bincode::options()
            .with_limit(4096)
            .deserialize::<VaultMeta>(&raw);

        assert!(decoded.is_err());
        Ok(())
    }

    #[test]
    fn add_and_extract_file() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let src = tmp.path().join("source.txt");
        let dest = tmp.path().join("out.txt");
        let body = b"file body";
        fs::write(&src, body)?;

        let mut vault = Vault::init(&root, "file-test", password())?;
        vault.add_file(&src)?;
        vault.extract("source.txt", &dest)?;

        assert_eq!(fs::read(dest)?, body);
        Ok(())
    }

    #[test]
    fn add_and_extract_text() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let dest = tmp.path().join("note.out");

        let mut vault = Vault::init(&root, "text-test", password())?;
        vault.add_text(TEXT_ENTRY, TEXT_BODY)?;
        vault.extract(TEXT_ENTRY, &dest)?;

        assert_eq!(fs::read_to_string(dest)?, TEXT_BODY);
        Ok(())
    }

    #[test]
    fn remove_entry_flushes_meta_before_deleting_file() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");

        let mut vault = Vault::init(&root, "remove-test", password())?;
        vault.add_text(TEXT_ENTRY, TEXT_BODY)?;

        let entry_id = vault.list()[0].id.clone();
        fs::remove_file(vault.entry_path(&entry_id))?;

        let remove_result = vault.remove(TEXT_ENTRY);
        assert!(remove_result.is_err());

        let reopened = Vault::open(&root, password())?;
        assert!(reopened.list().is_empty());

        Ok(())
    }

    #[test]
    fn list_returns_all_entries() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");

        let mut vault = Vault::init(&root, "list-test", password())?;
        vault.add_text("a.txt", "a")?;
        vault.add_text("b.txt", "b")?;

        let names = vault
            .list()
            .iter()
            .map(|entry| entry.original_name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["a.txt", "b.txt"]);

        Ok(())
    }

    #[test]
    fn entry_filename_on_disk_is_random_not_original_or_sha256_name() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let original_name = "plain-name.txt";

        let mut vault = Vault::init(&root, "filename-test", password())?;
        vault.add_text(original_name, TEXT_BODY)?;

        let actual_id = &vault.list()[0].id;
        let legacy_id = entry_id(original_name);

        assert_eq!(actual_id.len(), 64);
        assert!(hex::decode(actual_id).is_ok());
        assert_ne!(actual_id, &legacy_id);
        assert!(root
            .join(ENTRIES_DIR)
            .join(format!("{actual_id}.bxenc"))
            .exists());
        assert!(!root.join(ENTRIES_DIR).join(original_name).exists());
        assert!(!root
            .join(ENTRIES_DIR)
            .join(format!("{legacy_id}.bxenc"))
            .exists());

        Ok(())
    }

    #[test]
    fn flush_meta_generates_fresh_nonce_each_time() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let vault = Vault::init(&root, "nonce-test", password())?;

        let first = fs::read(root.join(META_FILE))?;
        vault.flush_meta()?;
        let second = fs::read(root.join(META_FILE))?;

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn v1_metadata_still_opens_and_extracts() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let dest = tmp.path().join("legacy.out");

        write_legacy_v1_vault(&root)?;

        let vault = Vault::open(&root, password())?;
        assert_eq!(vault.list().len(), 1);
        assert_eq!(vault.list()[0].id, entry_id(TEXT_ENTRY));

        vault.extract(TEXT_ENTRY, &dest)?;
        assert_eq!(fs::read_to_string(dest)?, TEXT_BODY);

        Ok(())
    }

    #[test]
    fn v1_metadata_is_read_only_until_migration() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");

        write_legacy_v1_vault(&root)?;

        let mut vault = Vault::open(&root, password())?;
        let result = vault.add_text("new.txt", "new body");

        assert!(matches!(result, Err(BxError::Encrypt(message)) if message.contains("read-only")));
        Ok(())
    }

    #[test]
    fn child_process_cannot_acquire_held_lock() {
        let Ok(root) = env::var(LOCK_CHILD_ROOT_ENV) else {
            return;
        };

        let result = VaultLock::acquire(Path::new(&root));
        assert!(
            matches!(result, Err(BxError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists)
        );
    }

    #[test]
    fn second_process_lock_acquire_fails_while_lock_is_held() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        fs::create_dir_all(&root)?;

        let lock = VaultLock::acquire(&root)?;
        let lock_contents = fs::read_to_string(root.join(LOCK_FILE))?;
        assert_eq!(lock_contents.trim(), std::process::id().to_string());

        let second = VaultLock::acquire(&root);
        assert!(
            matches!(second, Err(BxError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists)
        );

        let child_status = Command::new(env::current_exe()?)
            .arg("--exact")
            .arg("vault::store::tests::child_process_cannot_acquire_held_lock")
            .env(LOCK_CHILD_ROOT_ENV, &root)
            .status()?;
        assert!(child_status.success());

        drop(lock);
        assert!(!root.join(LOCK_FILE).exists());
        Ok(())
    }
}
