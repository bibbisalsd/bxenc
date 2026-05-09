//! Ad-hoc file decryption.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::{
    crypto::engine::{self, Credential, MAGIC},
    error::{BxError, BxResult},
};

pub fn decrypt_bytes(credential: Credential<'_>, blob: &[u8]) -> BxResult<Zeroizing<Vec<u8>>> {
    if blob.len() < MAGIC.len() || &blob[..MAGIC.len()] != MAGIC {
        return Err(BxError::Decrypt);
    }

    engine::decrypt(credential, blob, b"").map(Zeroizing::new)
}

pub fn decrypt_reader<R>(credential: Credential<'_>, reader: &mut R) -> BxResult<Zeroizing<Vec<u8>>>
where
    R: Read,
{
    let mut blob = Vec::new();
    reader.read_to_end(&mut blob)?;

    decrypt_bytes(credential, &blob)
}

pub fn decrypt_reader_to_writer<R, W>(
    credential: Credential<'_>,
    reader: &mut R,
    writer: &mut W,
) -> BxResult<()>
where
    R: Read,
    W: Write,
{
    let plaintext = decrypt_reader(credential, reader)?;
    writer.write_all(plaintext.as_slice())?;
    Ok(())
}
