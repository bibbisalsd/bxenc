//! CLI argument definitions.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "bxenc",
    version,
    about = "Secure vault and steganography toolkit"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Vault(VaultArgs),
    Stego(StegoArgs),
    Keygen(KeygenArgs),
}

impl Command {
    pub fn writes_stdout(&self) -> bool {
        match self {
            Self::Decrypt(args) => path_is_dash(&args.output),
            Self::Vault(VaultArgs {
                command: VaultCommand::List(_),
            }) => true,
            Self::Stego(StegoArgs {
                command: StegoCommand::Unwrap(args),
            }) => path_is_dash(&args.output),
            _ => false,
        }
    }
}

fn path_is_dash(path: &Path) -> bool {
    path.as_os_str() == OsStr::new("-")
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    #[arg(long = "in", value_name = "path|-")]
    pub input: PathBuf,

    #[arg(long = "out", value_name = "path")]
    pub output: PathBuf,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    #[arg(long = "in", value_name = "path")]
    pub input: PathBuf,

    #[arg(long = "out", value_name = "path|-")]
    pub output: PathBuf,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    Init(VaultInitArgs),
    Add(VaultAddArgs),
    Get(VaultGetArgs),
    Remove(VaultRemoveArgs),
    List(VaultListArgs),
}

#[derive(Debug, Args)]
pub struct VaultInitArgs {
    #[arg(long, value_name = "dir")]
    pub path: PathBuf,

    #[arg(long)]
    pub name: String,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VaultAddArgs {
    #[arg(long, value_name = "dir")]
    pub path: PathBuf,

    #[arg(long, value_name = "path")]
    pub file: Option<PathBuf>,

    #[arg(long, value_name = "name")]
    pub text: Option<String>,

    #[arg(long)]
    pub stdin: bool,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VaultGetArgs {
    #[arg(long, value_name = "dir")]
    pub path: PathBuf,

    #[arg(long)]
    pub name: String,

    #[arg(long = "out", value_name = "path")]
    pub output: PathBuf,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VaultRemoveArgs {
    #[arg(long, value_name = "dir")]
    pub path: PathBuf,

    #[arg(long)]
    pub name: String,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VaultListArgs {
    #[arg(long, value_name = "dir")]
    pub path: PathBuf,

    #[arg(long, value_name = "path")]
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct StegoArgs {
    #[command(subcommand)]
    pub command: StegoCommand,
}

#[derive(Debug, Subcommand)]
pub enum StegoCommand {
    Wrap(StegoWrapArgs),
    Unwrap(StegoUnwrapArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum StegoMode {
    Whitespace,
    Acrostic,
}

#[derive(Debug, Args)]
pub struct StegoWrapArgs {
    #[arg(long, value_enum)]
    pub mode: StegoMode,

    #[arg(long = "in", value_name = "path")]
    pub input: PathBuf,

    #[arg(long, value_name = "path")]
    pub carrier: Option<PathBuf>,

    #[arg(long = "out", value_name = "path")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct StegoUnwrapArgs {
    #[arg(long, value_enum)]
    pub mode: StegoMode,

    #[arg(long = "in", value_name = "path")]
    pub input: PathBuf,

    #[arg(long = "out", value_name = "path|-")]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long = "out", value_name = "path")]
    pub output: PathBuf,
}
