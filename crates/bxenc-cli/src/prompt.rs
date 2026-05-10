//! Password prompt helpers.

use std::io::{self, Write};

use bxenc_core::error::{BxError, BxResult};
use zeroize::Zeroizing;

pub fn prompt_password(label: &str) -> BxResult<Zeroizing<String>> {
    eprint!("{label}");
    io::stderr().flush()?;
    readpass::from_tty().map_err(BxError::Io)
}

pub fn prompt_password_confirm(label: &str) -> BxResult<Zeroizing<String>> {
    let password = prompt_password(label)?;
    let confirmation = prompt_password("Confirm password: ")?;

    if password.as_str() != confirmation.as_str() {
        return Err(BxError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passwords do not match",
        )));
    }

    Ok(password)
}
