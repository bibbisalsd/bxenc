pub mod decrypt;
pub mod encrypt;
pub mod keygen;
pub mod stego;
pub mod vault;

use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

use bxenc_core::{
    crypto::{engine::Credential, kdf},
    error::{BxError, BxResult},
};
use zeroize::Zeroizing;

use crate::{
    args::Command,
    prompt::{prompt_password, prompt_password_confirm},
};

pub enum CliCredential {
    Password(Zeroizing<String>),
    Keyfile(Zeroizing<[u8; kdf::KEY_LEN]>),
}

impl CliCredential {
    pub fn as_credential(&self) -> Credential<'_> {
        match self {
            Self::Password(password) => Credential::Password(password.as_bytes()),
            Self::Keyfile(keyfile) => Credential::Keyfile(keyfile),
        }
    }
}

pub fn run(command: &Command) -> BxResult<()> {
    match command {
        Command::Encrypt(args) => encrypt::run(args),
        Command::Decrypt(args) => decrypt::run(args),
        Command::Vault(args) => vault::run(args),
        Command::Stego(args) => stego::run(args),
        Command::Keygen(args) => keygen::run(args),
    }
}

pub fn credential_from_keyfile_or_prompt(
    keyfile: Option<&Path>,
    prompt: &str,
    confirm: bool,
) -> BxResult<CliCredential> {
    match keyfile {
        Some(path) => read_keyfile(path).map(CliCredential::Keyfile),
        None if confirm => prompt_password_confirm(prompt).map(CliCredential::Password),
        None => prompt_password(prompt).map(CliCredential::Password),
    }
}

pub fn read_all(path: &Path) -> BxResult<Zeroizing<Vec<u8>>> {
    if is_dash(path) {
        let mut input = Zeroizing::new(Vec::new());
        io::stdin().lock().read_to_end(&mut input)?;
        return Ok(input);
    }

    fs::read(path).map(Zeroizing::new).map_err(BxError::Io)
}

pub fn read_string(path: &Path) -> BxResult<Zeroizing<String>> {
    if is_dash(path) {
        let mut input = Zeroizing::new(String::new());
        io::stdin().lock().read_to_string(&mut input)?;
        return Ok(input);
    }

    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(BxError::Io)
}

pub fn write_all(path: &Path, bytes: &[u8]) -> BxResult<()> {
    if is_dash(path) {
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()?;
        return Ok(());
    }

    fs::write(path, bytes).map_err(BxError::Io)
}

pub fn invalid_input(message: &str) -> BxError {
    BxError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn read_keyfile(path: &Path) -> BxResult<Zeroizing<[u8; kdf::KEY_LEN]>> {
    let bytes = Zeroizing::new(fs::read(path)?);
    if bytes.len() != kdf::KEY_LEN {
        return Err(BxError::InvalidKeyfile(bytes.len()));
    }

    let mut key = Zeroizing::new([0u8; kdf::KEY_LEN]);
    key.copy_from_slice(bytes.as_slice());
    Ok(key)
}

fn is_dash(path: &Path) -> bool {
    path.as_os_str() == "-"
}
