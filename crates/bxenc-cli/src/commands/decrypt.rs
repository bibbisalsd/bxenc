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
    let plaintext = adhoc::decrypt::decrypt_bytes(credential.as_credential(), blob.as_slice())?;

    write_all(&args.output, plaintext.as_slice())
}
