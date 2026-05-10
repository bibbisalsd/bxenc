use std::time::{SystemTime, UNIX_EPOCH};

const LOADING_LINES: &[&str] = &[
    "loading egirl...",
    "loading femboy.exe...",
    "initializing the bit mines...",
    "summoning the cipher demons...",
    "negotiating with entropy...",
    "compiling conspiracy theories...",
    "defragmenting your secrets...",
    "corrupting your filesystem...",
    "asking entropy for permission...",
    "vibing with the cipher...",
    "touching grass (failed)...",
    "skill issue checking...",
    "manifesting your keyfile...",
    "performing security theater...",
    "gaslighting your plaintext...",
    "certifying this is not a virus...",
    "zeroizing your problems...",
    "isreal.exe finished",
];

pub fn print_startup() {
    eprintln!("bxenc v{}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("{}", loading_line());
}

fn loading_line() -> &'static str {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.subsec_nanos() as usize);
    LOADING_LINES[nanos % LOADING_LINES.len()]
}
