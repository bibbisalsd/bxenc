//! Ad-hoc file encryption.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use crate::{
    crypto::engine::{self, Credential},
    BxResult,
};

pub fn encrypt_bytes(credential: Credential<'_>, plaintext: &[u8]) -> BxResult<Vec<u8>> {
    engine::encrypt(credential, plaintext, b"")
}

pub fn encrypt_reader<R>(credential: Credential<'_>, reader: &mut R) -> BxResult<Vec<u8>>
where
    R: Read,
{
    let mut plaintext = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut plaintext)?;

    encrypt_bytes(credential, plaintext.as_slice())
}

pub fn encrypt_reader_to_writer<R, W>(
    credential: Credential<'_>,
    reader: &mut R,
    writer: &mut W,
) -> BxResult<()>
where
    R: Read,
    W: Write,
{
    let blob = encrypt_reader(credential, reader)?;
    writer.write_all(&blob)?;
    Ok(())
}
