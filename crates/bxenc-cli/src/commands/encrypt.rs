//! Encrypt command handler.

use bxenc_core::{adhoc, BxResult};

use crate::{
    args::EncryptArgs,
    commands::{credential_from_keyfile_or_prompt, read_all, write_all},
};

pub fn run(args: &EncryptArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let plaintext = read_all(&args.input)?;
    let blob = adhoc::encrypt::encrypt_bytes(credential.as_credential(), plaintext.as_slice())?;

    write_all(&args.output, &blob)
}
