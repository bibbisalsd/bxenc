use std::{error::Error, fs, path::Path};

use bxenc_core::{
    crypto::engine::{self, Credential},
    vault::{
        meta::{entry_id, EntryMeta, VaultMeta, META_AAD_V1},
        store::{Vault, ENTRIES_DIR, META_FILE, STAGE_ENTRIES_DIR},
    },
};
use tempfile::tempdir;

const KEYFILE: [u8; 32] = [19u8; 32];
const ENTRIES: [(&str, &[u8]); 2] = [
    ("alpha.txt", b"alpha body"),
    ("beta.txt", b"beta body with more bytes"),
];

#[test]
fn v1_vault_migrates_to_random_v2_ids_without_data_loss() -> Result<(), Box<dyn Error>> {
    let tmp = tempdir()?;
    let root = tmp.path().join("vault");
    write_v1_vault(&root)?;

    for (name, _) in ENTRIES {
        assert!(root
            .join(ENTRIES_DIR)
            .join(format!("{}.bxenc", entry_id(name)))
            .exists());
    }

    let mut vault = Vault::open(&root, Credential::Keyfile(&KEYFILE))?;
    vault.migrate_v1_to_v2()?;

    assert!(!root.join(STAGE_ENTRIES_DIR).exists());

    let migrated = Vault::open(&root, Credential::Keyfile(&KEYFILE))?;
    assert_eq!(migrated.list().len(), ENTRIES.len());

    for (name, body) in ENTRIES {
        let legacy_id = entry_id(name);
        let migrated_entry = migrated
            .list()
            .iter()
            .find(|entry| entry.original_name == name)
            .expect("migrated entry should be listed");

        assert_eq!(migrated_entry.id.len(), 64);
        assert!(migrated_entry.id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(migrated_entry.id, legacy_id);
        assert!(!root
            .join(ENTRIES_DIR)
            .join(format!("{legacy_id}.bxenc"))
            .exists());
        assert!(root
            .join(ENTRIES_DIR)
            .join(format!("{}.bxenc", migrated_entry.id))
            .exists());

        let output = tmp.path().join(format!("{name}.out"));
        migrated.extract(name, &output)?;
        assert_eq!(fs::read(output)?, body);
    }

    Ok(())
}

fn write_v1_vault(root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(root.join(ENTRIES_DIR))?;

    let mut meta = VaultMeta::new("legacy");
    for (name, body) in ENTRIES {
        let entry = EntryMeta::new(name, body.len() as u64);
        let blob = engine::encrypt(Credential::Keyfile(&KEYFILE), body, entry.id.as_bytes())?;
        fs::write(
            root.join(ENTRIES_DIR).join(format!("{}.bxenc", entry.id)),
            blob,
        )?;
        meta.entries.push(entry);
    }

    let meta_plaintext = bincode::serialize(&meta)?;
    let meta_blob = engine::encrypt(Credential::Keyfile(&KEYFILE), &meta_plaintext, META_AAD_V1)?;
    fs::write(root.join(META_FILE), meta_blob)?;

    Ok(())
}
