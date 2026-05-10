//! Decrypt command handler.

use bxenc_core::{adhoc, BxResult};

use crate::{
    args::DecryptArgs,
    commands::{credential_from_keyfile_or_prompt, read_all, write_all},
};

pub fn run(args: &DecryptArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let blob = read_all(&args.input)?;

    let decoded_blob;
    let blob_slice = if args.base64 {
        use base64::prelude::*;
        let text = String::from_utf8_lossy(&blob);
        // ignore whitespace like newlines often found in copy-pasted base64
        let trimmed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        decoded_blob = BASE64_STANDARD.decode(&trimmed).map_err(|e| {
            bxenc_core::error::BxError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid base64: {}", e),
            ))
        })?;
        decoded_blob.as_slice()
    } else {
        blob.as_slice()
    };

    let plaintext = adhoc::decrypt::decrypt_bytes(credential.as_credential(), blob_slice)?;

    write_all(&args.output, plaintext.as_slice())
}
