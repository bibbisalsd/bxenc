use std::io::Cursor;

use bxenc_core::{
    adhoc::{
        decrypt::{decrypt_bytes, decrypt_reader_to_writer},
        encrypt::{encrypt_bytes, encrypt_reader_to_writer},
    },
    crypto::engine::{Credential, MAGIC, MODE_KEYFILE, MODE_PASSWORD},
    BxError, BxResult,
};

const PASSWORD: &[u8] = b"ad hoc test password";
const WRONG_PASSWORD: &[u8] = b"wrong ad hoc test password";
const KEYFILE: [u8; 32] = [42u8; 32];
const PLAINTEXT: &[u8] = b"plain bytes with \0 and\nnewlines\n";

#[test]
fn password_bytes_roundtrip() -> BxResult<()> {
    let blob = encrypt_bytes(Credential::Password(PASSWORD), PLAINTEXT)?;
    let plaintext = decrypt_bytes(Credential::Password(PASSWORD), &blob)?;

    assert_eq!(&blob[0..5], MAGIC);
    assert_eq!(blob[6], MODE_PASSWORD);
    assert_eq!(plaintext.as_slice(), PLAINTEXT);

    Ok(())
}

#[test]
fn keyfile_bytes_roundtrip() -> BxResult<()> {
    let blob = encrypt_bytes(Credential::Keyfile(&KEYFILE), PLAINTEXT)?;
    let plaintext = decrypt_bytes(Credential::Keyfile(&KEYFILE), &blob)?;

    assert_eq!(&blob[0..5], MAGIC);
    assert_eq!(blob[6], MODE_KEYFILE);
    assert_eq!(plaintext.as_slice(), PLAINTEXT);

    Ok(())
}

#[test]
fn reader_writer_roundtrip() -> BxResult<()> {
    let mut input = Cursor::new(PLAINTEXT);
    let mut encrypted = Vec::new();
    encrypt_reader_to_writer(Credential::Keyfile(&KEYFILE), &mut input, &mut encrypted)?;

    let mut encrypted_input = Cursor::new(encrypted);
    let mut output = Vec::new();
    decrypt_reader_to_writer(
        Credential::Keyfile(&KEYFILE),
        &mut encrypted_input,
        &mut output,
    )?;

    assert_eq!(output, PLAINTEXT);

    Ok(())
}

#[test]
fn wrong_password_returns_decrypt_error() -> BxResult<()> {
    let blob = encrypt_bytes(Credential::Password(PASSWORD), PLAINTEXT)?;
    let result = decrypt_bytes(Credential::Password(WRONG_PASSWORD), &blob);

    assert!(matches!(result, Err(BxError::Decrypt)));

    Ok(())
}

#[test]
fn bad_magic_returns_decrypt_error() {
    let result = decrypt_bytes(Credential::Keyfile(&KEYFILE), b"not a bxenc blob");

    assert!(matches!(result, Err(BxError::Decrypt)));
}
