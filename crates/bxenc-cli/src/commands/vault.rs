//! Vault command handlers.

use std::io::{self, Read};

use bxenc_core::{vault::store::Vault, BxResult};
use zeroize::Zeroizing;

use crate::{
    args::{VaultAddArgs, VaultArgs, VaultCommand, VaultGetArgs, VaultInitArgs, VaultListArgs},
    commands::{credential_from_keyfile_or_prompt, invalid_input},
};

pub fn run(args: &VaultArgs) -> BxResult<()> {
    match &args.command {
        VaultCommand::Init(args) => init(args),
        VaultCommand::Add(args) => add(args),
        VaultCommand::Get(args) => get(args),
        VaultCommand::Remove(args) => remove(args),
        VaultCommand::List(args) => list(args),
    }
}

fn init(args: &VaultInitArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "New password: ", true)?;
    Vault::init(&args.path, &args.name, credential.as_credential())?;
    Ok(())
}

fn add(args: &VaultAddArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let mut vault = Vault::open(&args.path, credential.as_credential())?;

    match (&args.file, &args.text, args.stdin) {
        (Some(file), None, false) => vault.add_file(file),
        (None, Some(name), true) => {
            let mut text = Zeroizing::new(String::new());
            io::stdin().lock().read_to_string(&mut text)?;
            vault.add_text(name, text.as_str())
        }
        _ => Err(invalid_input(
            "vault add requires either --file <path> or --text <name> --stdin",
        )),
    }
}

fn get(args: &VaultGetArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let vault = Vault::open(&args.path, credential.as_credential())?;
    vault.extract(&args.name, &args.output)
}

fn remove(args: &crate::args::VaultRemoveArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let mut vault = Vault::open(&args.path, credential.as_credential())?;
    vault.remove(&args.name)
}

fn list(args: &VaultListArgs) -> BxResult<()> {
    let credential =
        credential_from_keyfile_or_prompt(args.keyfile.as_deref(), "Password: ", false)?;
    let vault = Vault::open(&args.path, credential.as_credential())?;

    for entry in vault.list() {
        println!(
            "{}\t{}\t{}",
            entry.original_name, entry.size_bytes, entry.added_at
        );
    }

    Ok(())
}
