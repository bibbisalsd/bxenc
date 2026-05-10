//! Key generation command handler.

use std::{fs::OpenOptions, io::Write};

use bxenc_core::{error::BxError, BxResult};
use rand::{rngs::OsRng, RngCore};

use crate::args::KeygenArgs;

pub fn run(args: &KeygenArgs) -> BxResult<()> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(not(unix))]
    {
        eprintln!("Warning: Operating system does not support Unix file permissions.");
        eprintln!("Ensure the keyfile is kept secure and not world-readable.");
    }

    let mut file = options.open(&args.output).map_err(|e| {
        BxError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to create keyfile {}: {}", args.output.display(), e),
        ))
    })?;

    file.write_all(&key).map_err(|e| {
        BxError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to write keyfile: {}", e),
        ))
    })?;

    // key material handled securely by core when read, but zeroize here is also good practice
    zeroize::Zeroize::zeroize(&mut key);

    Ok(())
}
