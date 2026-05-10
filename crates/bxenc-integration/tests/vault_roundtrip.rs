use std::{error::Error, fs};

use bxenc_core::{crypto::engine::Credential, vault::store::Vault};
use tempfile::tempdir;

const KEYFILE: [u8; 32] = [11u8; 32];

#[test]
fn vault_roundtrip() -> Result<(), Box<dyn Error>> {
    let tmp = tempdir()?;
    let root = tmp.path().join("vault");
    let src = tmp.path().join("input.txt");
    let file_out = tmp.path().join("file.out");
    let text_out = tmp.path().join("text.out");

    fs::write(&src, b"file body")?;

    let mut vault = Vault::init(&root, "integration", Credential::Keyfile(&KEYFILE))?;
    vault.add_file(&src)?;
    vault.add_text("note.txt", "text body")?;

    assert_eq!(vault.list().len(), 2);

    vault.extract("input.txt", &file_out)?;
    vault.extract("note.txt", &text_out)?;

    assert_eq!(fs::read(file_out)?, b"file body");
    assert_eq!(fs::read_to_string(text_out)?, "text body");

    vault.remove("input.txt")?;
    assert_eq!(vault.list().len(), 1);
    assert_eq!(vault.list()[0].original_name, "note.txt");

    let reopened = Vault::open(&root, Credential::Keyfile(&KEYFILE))?;
    assert_eq!(reopened.list().len(), 1);
    assert_eq!(reopened.list()[0].original_name, "note.txt");

    Ok(())
}
