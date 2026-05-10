//! Vault storage operations.

use std::{
    fs::{self, File},
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
    vault::meta::{EntryMeta, VaultMeta},
};

pub const META_FILE: &str = "vault.meta.bxenc";
pub const ENTRIES_DIR: &str = "entries";
const META_AAD: &[u8] = b"vault.meta";

pub struct Vault {
    meta: VaultMeta,
    root: PathBuf,
    credential: StoredCredential,
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

        let vault = Self {
            meta: VaultMeta::new(name),
            root: root.to_path_buf(),
            credential: StoredCredential::from_credential(credential),
        };
        vault.flush_meta()?;

        Ok(vault)
    }

    pub fn open(root: &Path, credential: Credential<'_>) -> BxResult<Self> {
        let meta_path = root.join(META_FILE);
        let blob = fs::read(&meta_path)
            .map_err(|_| BxError::VaultNotFound(meta_path.display().to_string()))?;

        let plaintext = Zeroizing::new(
            engine::decrypt(credential, &blob, META_AAD).map_err(|_| BxError::MetaCorrupt)?,
        );
        let meta = bincode::deserialize(plaintext.as_slice()).map_err(|_| BxError::MetaCorrupt)?;

        Ok(Self {
            meta,
            root: root.to_path_buf(),
            credential: StoredCredential::from_credential(credential),
        })
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
        let entry = self
            .meta
            .entries
            .iter()
            .find(|entry| entry.original_name == entry_name)
            .ok_or_else(|| BxError::EntryNotFound(entry_name.to_string()))?;
        let blob = fs::read(self.entry_path(&entry.id))?;
        let plaintext = Zeroizing::new(engine::decrypt(
            self.credential.as_credential(),
            &blob,
            entry.id.as_bytes(),
        )?);

        let mut out = File::create(dest)?;
        out.write_all(plaintext.as_slice())?;
        Ok(())
    }

    pub fn remove(&mut self, entry_name: &str) -> BxResult<()> {
        let index = self
            .meta
            .entries
            .iter()
            .position(|entry| entry.original_name == entry_name)
            .ok_or_else(|| BxError::EntryNotFound(entry_name.to_string()))?;
        let entry = self.meta.entries.remove(index);

        if let Err(err) = self.flush_meta() {
            self.meta.entries.insert(index, entry);
            return Err(err);
        }

        fs::remove_file(self.entry_path(&entry.id))?;
        Ok(())
    }

    pub fn list(&self) -> &[EntryMeta] {
        &self.meta.entries
    }

    fn add_entry_bytes(&mut self, name: &str, plaintext: &[u8]) -> BxResult<()> {
        if self
            .meta
            .entries
            .iter()
            .any(|entry| entry.original_name == name)
        {
            return Err(BxError::Encrypt(format!(
                "vault entry already exists: {name}"
            )));
        }

        let size_bytes = u64::try_from(plaintext.len())
            .map_err(|_| invalid_input("entry is too large to record its size"))?;
        let entry = EntryMeta::new(name, size_bytes);
        let blob = engine::encrypt(
            self.credential.as_credential(),
            plaintext,
            entry.id.as_bytes(),
        )?;
        write_blob_atomic(&self.entries_dir(), &self.entry_path(&entry.id), &blob)?;

        self.meta.entries.push(entry.clone());
        if let Err(err) = self.flush_meta() {
            self.meta
                .entries
                .retain(|candidate| candidate.id != entry.id);
            return Err(err);
        }

        Ok(())
    }

    fn flush_meta(&self) -> BxResult<()> {
        let plaintext = bincode::serialize(&self.meta)
            .map(Zeroizing::new)
            .map_err(|err| BxError::Encrypt(err.to_string()))?;
        let blob = engine::encrypt(
            self.credential.as_credential(),
            plaintext.as_slice(),
            META_AAD,
        )?;
        write_blob_atomic(&self.root, &self.root.join(META_FILE), &blob)
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join(ENTRIES_DIR)
    }

    fn entry_path(&self, entry_id: &str) -> PathBuf {
        self.entries_dir().join(format!("{entry_id}.bxenc"))
    }
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

#[cfg(test)]
mod tests {
    use std::fs;

    use bincode::Options;
    use tempfile::tempdir;

    use super::*;
    use crate::vault::meta::entry_id;

    const PASSWORD: &[u8] = b"vault unit password";
    const TEXT_ENTRY: &str = "note.txt";
    const TEXT_BODY: &str = "vault text body";

    fn password() -> Credential<'static> {
        Credential::Password(PASSWORD)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
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
    fn entry_filename_on_disk_is_sha256_not_original_name() -> BxResult<()> {
        let tmp = tempdir()?;
        let root = tmp.path().join("vault");
        let original_name = "plain-name.txt";

        let mut vault = Vault::init(&root, "filename-test", password())?;
        vault.add_text(original_name, TEXT_BODY)?;

        let expected_id = entry_id(original_name);
        assert!(root
            .join(ENTRIES_DIR)
            .join(format!("{expected_id}.bxenc"))
            .exists());
        assert!(!root.join(ENTRIES_DIR).join(original_name).exists());

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
}
