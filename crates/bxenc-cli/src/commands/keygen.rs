//! Key generation command handler.

use bxenc_core::BxResult;

use crate::{args::KeygenArgs, commands::invalid_input};

pub fn run(_args: &KeygenArgs) -> BxResult<()> {
    Err(invalid_input("keygen is implemented in the next milestone"))
}
