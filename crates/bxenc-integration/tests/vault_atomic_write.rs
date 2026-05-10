use std::{error::Error, fs, io::Write};

use bxenc_core::{
    crypto::engine::Credential,
    vault::store::{Vault, META_FILE},
};
use tempfile::{tempdir, NamedTempFile};

const KEYFILE: [u8; 32] = [13u8; 32];

#[test]
fn vault_atomic_write_leaves_original_meta_openable() -> Result<(), Box<dyn Error>> {
    let tmp = tempdir()?;
    let root = tmp.path().join("vault");

    let mut vault = Vault::init(&root, "atomic", Credential::Keyfile(&KEYFILE))?;
    vault.add_text("note.txt", "survives interrupted temp write")?;

    let original_meta = fs::read(root.join(META_FILE))?;
    let mut interrupted = NamedTempFile::new_in(&root)?;
    interrupted.write_all(b"truncated interrupted metadata write")?;
    interrupted.as_file().sync_all()?;

    assert_eq!(fs::read(root.join(META_FILE))?, original_meta);

    let reopened = Vault::open(&root, Credential::Keyfile(&KEYFILE))?;
    assert_eq!(reopened.list().len(), 1);
    assert_eq!(reopened.list()[0].original_name, "note.txt");

    Ok(())
}
