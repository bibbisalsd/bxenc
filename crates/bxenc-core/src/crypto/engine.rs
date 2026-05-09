//! Authenticated encryption engine.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    crypto::kdf,
    error::{BxError, BxResult},
};

pub const MAGIC: &[u8; 5] = b"BXENC";
pub const VERSION: u8 = 0x01;
pub const MODE_PASSWORD: u8 = 0x00;
pub const MODE_KEYFILE: u8 = 0x01;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 47;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug)]
pub enum Credential<'a> {
    Password(&'a [u8]),
    Keyfile(&'a [u8; kdf::KEY_LEN]),
}

struct Header {
    mode: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    bytes: [u8; HEADER_LEN],
}

fn build_header(mode: u8, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[0..5].copy_from_slice(MAGIC);
    header[5] = VERSION;
    header[6] = mode;
    header[7..23].copy_from_slice(salt);
    header[23..47].copy_from_slice(nonce);
    header
}

fn parse_header(blob: &[u8]) -> BxResult<Header> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(BxError::Decrypt);
    }

    if &blob[0..5] != MAGIC {
        return Err(BxError::Decrypt);
    }

    if blob[5] != VERSION {
        return Err(BxError::Decrypt);
    }

    let mode = blob[6];
    if !matches!(mode, MODE_PASSWORD | MODE_KEYFILE) {
        return Err(BxError::Decrypt);
    }

    let mut bytes = [0u8; HEADER_LEN];
    bytes.copy_from_slice(&blob[..HEADER_LEN]);

    let salt = <[u8; SALT_LEN]>::try_from(&blob[7..23]).map_err(|_| BxError::Decrypt)?;
    let nonce = <[u8; NONCE_LEN]>::try_from(&blob[23..47]).map_err(|_| BxError::Decrypt)?;

    Ok(Header {
        mode,
        salt,
        nonce,
        bytes,
    })
}

fn aad_from_header(header: &[u8; HEADER_LEN], entry_aad: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_LEN + entry_aad.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(entry_aad);
    aad
}

fn key_from_credential(
    credential: Credential<'_>,
    salt: &[u8; SALT_LEN],
) -> BxResult<(u8, Zeroizing<[u8; kdf::KEY_LEN]>)> {
    match credential {
        Credential::Password(password) => Ok((MODE_PASSWORD, kdf::derive_key(password, salt)?)),
        Credential::Keyfile(keyfile) => {
            let mut key = Zeroizing::new([0u8; kdf::KEY_LEN]);
            key.copy_from_slice(keyfile);
            Ok((MODE_KEYFILE, key))
        }
    }
}

fn cipher_from_key(key: &[u8]) -> BxResult<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| BxError::Encrypt("invalid key length".to_string()))
}

/// Encrypts bytes using XChaCha20-Poly1305.
///
/// `entry_aad` binds a vault entry ID, `b"vault.meta"`, or an empty byte slice
/// for ad-hoc files to the ciphertext.
pub fn encrypt(
    credential: Credential<'_>,
    plaintext: &[u8],
    entry_aad: &[u8],
) -> BxResult<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    if matches!(credential, Credential::Password(_)) {
        OsRng.fill_bytes(&mut salt);
    }

    let (mode, key) = key_from_credential(credential, &salt)?;
    let header = build_header(mode, &salt, &nonce_bytes);
    let aad = aad_from_header(&header, entry_aad);
    let nonce = XNonce::from(nonce_bytes);
    let cipher = cipher_from_key(key.as_ref())?;

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|err| BxError::Encrypt(err.to_string()))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a blob produced by [`encrypt`].
pub fn decrypt(credential: Credential<'_>, blob: &[u8], entry_aad: &[u8]) -> BxResult<Vec<u8>> {
    let header = parse_header(blob)?;
    let ciphertext = &blob[HEADER_LEN..];

    let key = match (header.mode, credential) {
        (MODE_PASSWORD, Credential::Password(password)) => kdf::derive_key(password, &header.salt)?,
        (MODE_KEYFILE, Credential::Keyfile(keyfile)) => {
            let mut key = Zeroizing::new([0u8; kdf::KEY_LEN]);
            key.copy_from_slice(keyfile);
            key
        }
        _ => return Err(BxError::Decrypt),
    };

    let aad = aad_from_header(&header.bytes, entry_aad);
    let nonce = XNonce::from(header.nonce);
    let cipher = cipher_from_key(key.as_ref()).map_err(|_| BxError::Decrypt)?;

    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| BxError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"still not a cli argument";
    const WRONG_PASSWORD: &[u8] = b"different password";
    const PLAINTEXT: &[u8] = b"vault material";
    const ENTRY_AAD: &[u8] = b"entry_a";
    const OTHER_ENTRY_AAD: &[u8] = b"entry_b";
    const KEYFILE_A: [u8; kdf::KEY_LEN] = [7u8; kdf::KEY_LEN];
    const KEYFILE_B: [u8; kdf::KEY_LEN] = [9u8; kdf::KEY_LEN];

    fn assert_decrypt_error(result: BxResult<Vec<u8>>) {
        assert!(matches!(result, Err(BxError::Decrypt)));
    }

    #[test]
    fn password_mode_roundtrip() -> BxResult<()> {
        let blob = encrypt(Credential::Password(PASSWORD), PLAINTEXT, b"")?;
        let plaintext = decrypt(Credential::Password(PASSWORD), &blob, b"")?;

        assert_eq!(blob.len(), HEADER_LEN + PLAINTEXT.len() + TAG_LEN);
        assert_eq!(&blob[0..5], MAGIC);
        assert_eq!(blob[5], VERSION);
        assert_eq!(blob[6], MODE_PASSWORD);
        assert_eq!(plaintext, PLAINTEXT);
        Ok(())
    }

    #[test]
    fn keyfile_mode_roundtrip() -> BxResult<()> {
        let blob = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;
        let plaintext = decrypt(Credential::Keyfile(&KEYFILE_A), &blob, b"")?;

        assert_eq!(blob.len(), HEADER_LEN + PLAINTEXT.len() + TAG_LEN);
        assert_eq!(&blob[0..5], MAGIC);
        assert_eq!(blob[5], VERSION);
        assert_eq!(blob[6], MODE_KEYFILE);
        assert_eq!(&blob[7..23], &[0u8; SALT_LEN]);
        assert_eq!(plaintext, PLAINTEXT);
        Ok(())
    }

    #[test]
    fn wrong_password_returns_decrypt_error() -> BxResult<()> {
        let blob = encrypt(Credential::Password(PASSWORD), PLAINTEXT, b"")?;

        assert_decrypt_error(decrypt(Credential::Password(WRONG_PASSWORD), &blob, b""));
        Ok(())
    }

    #[test]
    fn wrong_keyfile_returns_decrypt_error() -> BxResult<()> {
        let blob = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;

        assert_decrypt_error(decrypt(Credential::Keyfile(&KEYFILE_B), &blob, b""));
        Ok(())
    }

    #[test]
    fn corrupted_ciphertext_fails_authentication() -> BxResult<()> {
        let mut blob = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;
        let last_index = blob.len() - 1;
        blob[last_index] ^= 0x01;

        assert_decrypt_error(decrypt(Credential::Keyfile(&KEYFILE_A), &blob, b""));
        Ok(())
    }

    #[test]
    fn bad_magic_rejected_before_decryption() {
        let blob = vec![0u8; HEADER_LEN + TAG_LEN];

        assert_decrypt_error(decrypt(Credential::Keyfile(&KEYFILE_A), &blob, b""));
    }

    #[test]
    fn two_encryptions_produce_different_blobs() -> BxResult<()> {
        let first = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;
        let second = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;

        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn header_tampering_fails_authentication() -> BxResult<()> {
        let mut blob = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, b"")?;
        blob[23] ^= 0x01;

        assert_decrypt_error(decrypt(Credential::Keyfile(&KEYFILE_A), &blob, b""));
        Ok(())
    }

    #[test]
    fn entry_aad_mismatch_fails() -> BxResult<()> {
        let blob = encrypt(Credential::Keyfile(&KEYFILE_A), PLAINTEXT, ENTRY_AAD)?;

        assert_decrypt_error(decrypt(
            Credential::Keyfile(&KEYFILE_A),
            &blob,
            OTHER_ENTRY_AAD,
        ));
        Ok(())
    }

    #[test]
    fn mode_byte_mismatch_fails() -> BxResult<()> {
        let blob = encrypt(Credential::Password(PASSWORD), PLAINTEXT, b"")?;

        assert_decrypt_error(decrypt(Credential::Keyfile(&KEYFILE_A), &blob, b""));
        Ok(())
    }
}
