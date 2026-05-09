#[derive(Debug, thiserror::Error)]
pub enum BxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encryption failed: {0}")]
    Encrypt(String),

    #[error("decryption failed - wrong password/keyfile or corrupted data")]
    Decrypt,

    #[error("invalid keyfile: expected 32 bytes, got {0}")]
    InvalidKeyfile(usize),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("vault not found at path: {0}")]
    VaultNotFound(String),

    #[error("vault entry not found: {0}")]
    EntryNotFound(String),

    #[error("vault could not be opened - wrong password or corrupted metadata")]
    MetaCorrupt,

    #[error("acrostic stego input too large: max 256 bytes, got {0}")]
    AcrosticInputTooLarge(usize),

    #[error("stego carrier too short: need {need} words, have {have}")]
    CarrierTooShort { need: usize, have: usize },

    #[error("stego extraction failed: {0}")]
    StegoExtract(String),
}

pub type BxResult<T> = Result<T, BxError>;
