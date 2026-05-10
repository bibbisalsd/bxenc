use std::error::Error;

use bxenc_core::{
    crypto::engine::Credential,
    stego::{acrostic, whitespace},
    {adhoc::decrypt::decrypt_bytes, adhoc::encrypt::encrypt_bytes},
};

const KEYFILE: [u8; 32] = [21u8; 32];

fn carrier(word_count: usize) -> String {
    (0..word_count)
        .map(|index| format!("ciphertext{index}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn whitespace_wraps_ciphertext_without_touching_crypto() -> Result<(), Box<dyn Error>> {
    let plaintext = b"stego layering test";
    let ciphertext = encrypt_bytes(Credential::Keyfile(&KEYFILE), plaintext)?;

    let wrapped = whitespace::encode(&ciphertext)?;
    let unwrapped = whitespace::decode(&wrapped)?;
    let decrypted = decrypt_bytes(Credential::Keyfile(&KEYFILE), &unwrapped)?;

    assert_eq!(decrypted.as_slice(), plaintext);
    Ok(())
}

#[test]
fn acrostic_wraps_small_ciphertext_without_touching_crypto() -> Result<(), Box<dyn Error>> {
    let plaintext = b"small";
    let ciphertext = encrypt_bytes(Credential::Keyfile(&KEYFILE), plaintext)?;

    let wrapped = acrostic::encode(&ciphertext, &carrier((ciphertext.len() + 4) * 8))?;
    let unwrapped = acrostic::decode(&wrapped)?;
    let decrypted = decrypt_bytes(Credential::Keyfile(&KEYFILE), &unwrapped)?;

    assert_eq!(decrypted.as_slice(), plaintext);
    Ok(())
}
