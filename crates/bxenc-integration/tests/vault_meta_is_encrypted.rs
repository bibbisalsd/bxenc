use std::{error::Error, fs};

use bincode::Options;
use bxenc_core::{
    crypto::engine::Credential,
    vault::{
        meta::VaultMeta,
        store::{Vault, META_FILE},
    },
};
use tempfile::tempdir;

const KEYFILE: [u8; 32] = [12u8; 32];

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn vault_meta_is_encrypted() -> Result<(), Box<dyn Error>> {
    let tmp = tempdir()?;
    let root = tmp.path().join("vault");
    let vault_name = "metadata-integration-vault";

    let mut vault = Vault::init(&root, vault_name, Credential::Keyfile(&KEYFILE))?;
    vault.add_text("secret-note.txt", "classified metadata should not show up")?;

    let raw = fs::read(root.join(META_FILE))?;
    let decoded = bincode::options()
        .with_limit(4096)
        .deserialize::<VaultMeta>(&raw);

    assert!(root.join(META_FILE).exists());
    assert!(!root.join("vault.meta.json").exists());
    assert!(decoded.is_err());
    assert!(!contains_bytes(&raw, vault_name.as_bytes()));
    assert!(!contains_bytes(&raw, b"secret-note.txt"));

    Ok(())
}
