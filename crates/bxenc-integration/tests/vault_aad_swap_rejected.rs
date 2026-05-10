use std::{error::Error, fs, io, path::Path};

use bxenc_core::{
    crypto::engine::Credential,
    vault::store::{Vault, ENTRIES_DIR},
    BxError,
};
use tempfile::tempdir;

const KEYFILE: [u8; 32] = [14u8; 32];

fn entry_path(root: &Path, id: &str) -> std::path::PathBuf {
    root.join(ENTRIES_DIR).join(format!("{id}.bxenc"))
}

#[test]
fn vault_aad_swap_rejected() -> Result<(), Box<dyn Error>> {
    let tmp = tempdir()?;
    let root = tmp.path().join("vault");

    let mut vault = Vault::init(&root, "aad", Credential::Keyfile(&KEYFILE))?;
    vault.add_text("a.txt", "a body")?;
    vault.add_text("b.txt", "b body")?;

    let a_id = vault
        .list()
        .iter()
        .find(|entry| entry.original_name == "a.txt")
        .map(|entry| entry.id.clone())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing a.txt"))?;
    let b_id = vault
        .list()
        .iter()
        .find(|entry| entry.original_name == "b.txt")
        .map(|entry| entry.id.clone())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing b.txt"))?;

    let a_path = entry_path(&root, &a_id);
    let b_path = entry_path(&root, &b_id);
    let swap_path = root.join(ENTRIES_DIR).join("swap.tmp");
    fs::rename(&a_path, &swap_path)?;
    fs::rename(&b_path, &a_path)?;
    fs::rename(&swap_path, &b_path)?;

    let result = vault.extract("a.txt", &tmp.path().join("a.out"));
    assert!(matches!(result, Err(BxError::Decrypt)));

    Ok(())
}
