//! Steganography command handlers.

use bxenc_core::{stego as core_stego, BxResult};

use crate::{
    args::{StegoArgs, StegoCommand, StegoMode, StegoUnwrapArgs, StegoWrapArgs},
    commands::{invalid_input, read_all, read_string, write_all},
};

pub fn run(args: &StegoArgs) -> BxResult<()> {
    match &args.command {
        StegoCommand::Wrap(args) => wrap(args),
        StegoCommand::Unwrap(args) => unwrap(args),
    }
}

fn wrap(args: &StegoWrapArgs) -> BxResult<()> {
    let input = read_all(&args.input)?;
    let encoded = match args.mode {
        StegoMode::Whitespace => core_stego::whitespace::encode(input.as_slice())?,
        StegoMode::Acrostic => {
            let carrier_path = args
                .carrier
                .as_deref()
                .ok_or_else(|| invalid_input("--carrier is required for acrostic mode"))?;
            let carrier = read_string(carrier_path)?;
            core_stego::acrostic::encode(input.as_slice(), carrier.as_str())?
        }
    };

    write_all(&args.output, encoded.as_bytes())
}

fn unwrap(args: &StegoUnwrapArgs) -> BxResult<()> {
    let input = read_string(&args.input)?;
    let decoded = match args.mode {
        StegoMode::Whitespace => core_stego::whitespace::decode(input.as_str())?,
        StegoMode::Acrostic => core_stego::acrostic::decode(input.as_str())?,
    };

    write_all(&args.output, &decoded)
}
