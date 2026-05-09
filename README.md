# bxenc

`bxenc` is a Rust CLI secure vault and steganographic encoding toolkit.

This repository is currently at Milestone 1: workspace scaffold only.

Planned core properties:

- XChaCha20-Poly1305 authenticated encryption.
- Argon2id password key derivation.
- Optional 32-byte raw keyfiles.
- Encrypted vault metadata with atomic writes.
- Vault entry authentication bound to entry identity.
- Zeroize discipline for key material and sensitive buffers.
- Plain stdout, no color or spinner dependencies.

Pre-flight decisions captured before implementation:

- Use `Aead::encrypt` with `Payload` for encryption rather than `encrypt_in_place_detached`.
- Add `sha2` and `hex` for vault entry IDs.
- Use a std-only epoch timestamp string unless Milestone 5 proves RFC 3339 is worth an extra dependency.
- Verify the availability of `readpass` before Milestone 7; fall back to `rpassword` plus `Zeroizing<String>` if needed.
