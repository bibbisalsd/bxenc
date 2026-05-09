//! Password key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{BxError, BxResult};

/// Argon2id memory cost in kibibytes.
pub const ARGON2_MEM_COST: u32 = 64 * 1024;
/// Argon2id iteration count.
pub const ARGON2_TIME_COST: u32 = 3;
/// Argon2id lane count.
pub const ARGON2_PARALLELISM: u32 = 1;
/// Symmetric key length for XChaCha20-Poly1305.
pub const KEY_LEN: usize = 32;

pub fn derive_key(password: &[u8], salt: &[u8; 16]) -> BxResult<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(
        ARGON2_MEM_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|err| BxError::Kdf(err.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);

    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|err| BxError::Kdf(err.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SALT_A: [u8; 16] = *b"0123456789abcdef";
    const SALT_B: [u8; 16] = *b"fedcba9876543210";

    #[test]
    fn same_password_same_salt_yields_same_key() -> BxResult<()> {
        let first = derive_key(PASSWORD, &SALT_A)?;
        let second = derive_key(PASSWORD, &SALT_A)?;

        assert_eq!(first.as_ref(), second.as_ref());
        Ok(())
    }

    #[test]
    fn same_password_different_salt_yields_different_key() -> BxResult<()> {
        let first = derive_key(PASSWORD, &SALT_A)?;
        let second = derive_key(PASSWORD, &SALT_B)?;

        assert_ne!(first.as_ref(), second.as_ref());
        Ok(())
    }

    #[test]
    fn output_is_32_bytes() -> BxResult<()> {
        let key = derive_key(PASSWORD, &SALT_A)?;

        assert_eq!(key.as_ref().len(), KEY_LEN);
        Ok(())
    }

    #[test]
    fn zeroize_on_drop() -> BxResult<()> {
        fn assert_zeroizing_key(_value: &Zeroizing<[u8; KEY_LEN]>) {}

        let key = derive_key(PASSWORD, &SALT_A)?;
        assert_zeroizing_key(&key);

        Ok(())
    }
}
