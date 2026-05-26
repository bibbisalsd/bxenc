# bxenc

`bxenc` is a Rust CLI vault and steganography toolkit. It provides ad-hoc
file encryption, encrypted vault metadata, and ciphertext wrapping modes built
around XChaCha20-Poly1305, Argon2id, authenticated metadata binding, atomic
writes, and explicit limitation documentation.

This repository contains the public `bxenc` source code only.

## Darkroom

Darkroom is a private-source anonymous chat system that uses `bxenc` as part of
its security model for vault protection, bootstrap material, and encrypted
private-message workflows. It is designed around I2P-routed relay behavior and
hybrid private-message key agreement using X25519 and ML-KEM-768.

Darkroom source code is intentionally not published in this repository. The
public overview and portfolio write-up are here:

- https://sean-colon.xyz/project/bxenc

## 1. Overview

`bxenc` provides secure ad-hoc file encryption, managed secure vaults for organizing multiple files, and a steganography layer to hide the existence of encrypted data altogether. It is designed to be cross-platform, robust against corruption, and explicitly memory-safe with zeroize discipline.

## 2. Security Model

What is protected:
- **Confidentiality:** Data is encrypted with `XChaCha20-Poly1305`. Vault metadata is fully encrypted at rest using the same engine.
- **Integrity:** The entire structural header, the entry IDs, and the ciphertext are fully authenticated. Relocating, renaming, or tampering with files will result in immediate authentication failure.
- **Atomic Operations:** Vault metadata writes are atomic (write to temp file, fsync, then rename). The vault is never left in a corrupted half-written state if the process is killed.

What is **not** protected:
- Physical RAM cold-boot attacks.
- OS-level keyloggers or compromised host systems.
- Forensic recovery of overwritten files due to SSD wear-leveling (we recommend using Full-Disk Encryption).

## 3. Install

Ensure you have Rust and Cargo installed, then run:

```bash
cargo build --release
```
The binary will be available at `target/release/bxenc`.

## 4. Quick Start

Encrypt a file:
```bash
bxenc encrypt --in my_secret.txt --out secret.bxenc
```

Decrypt a file:
```bash
bxenc decrypt --in secret.bxenc --out recovered.txt
```

Initialize and use a vault:
```bash
bxenc vault init --path ./my_vault --name "Personal"
bxenc vault add --path ./my_vault --file notes.txt
bxenc vault list --path ./my_vault
bxenc vault get --path ./my_vault --name notes.txt --out recovered_notes.txt
```

## 5. Password vs Keyfile

`bxenc` supports both password-based encryption and raw keyfile-based encryption.

**Password Mode:** Uses `Argon2id` (RFC 9106 recommended interactive parameters) to securely derive a 32-byte key from your password and a random 16-byte salt.
**Keyfile Mode:** Directly uses a 32-byte securely generated key file for encryption, bypassing Argon2id for scripting or automated use cases.

Generate a keyfile:
```bash
bxenc keygen --out my-secret.key
```

## 6. Ad-Hoc Encryption / Decryption

Encrypt a single file (or pipe from stdin using `-`):
```bash
echo -n "secret message" | bxenc encrypt --in - --out secret.bxenc
```

You can also use the `--base64` flag to encode or decode the encrypted binary blob to/from Base64, which is extremely useful for sharing secrets over Discord, SMS, or other text-based messengers.

```bash
# Encrypt and get base64 string
echo -n "secret message" | bxenc encrypt --base64 --in - --out -
```

## 7. Named Vaults

Vaults manage multiple entries. Their metadata (`vault.meta.bxenc`) is fully encrypted on disk. There are no plaintext JSON files indicating filenames, original sizes, or creation dates.

Commands:
- `init`: Create a new vault.
- `add`: Add a file or text (via stdin) to the vault.
- `get`: Extract an entry from the vault.
- `remove`: Delete an entry. This atomically flushes the new metadata before removing the physical file.
- `list`: Show all entries in the vault.

## 8. Steganography Layer

Steganography is a layer on top of encryption to hide the *existence* of the ciphertext. `bxenc` supports two modes:

1. **Whitespace (`--mode whitespace`):** Encodes ciphertext as tabs and spaces. Overhead is 8x. Suitable for any payload size.
2. **Acrostic (`--mode acrostic`):** Encodes ciphertext in the casing of the first letter of words in a carrier text. Has a hard limit of 256 bytes payload.

Wrap an encrypted blob:
```bash
bxenc stego wrap --mode whitespace --in secret.bxenc --out invisible.txt
```

Unwrap back to ciphertext:
```bash
bxenc stego unwrap --mode whitespace --in invisible.txt --out secret.bxenc
```

## 9. Cryptographic Choices

- **`chacha20poly1305`:** XChaCha20-Poly1305 uses a 192-bit random nonce. This makes nonce collisions structurally impossible.
- **`argon2`:** Argon2id (RFC 9106) provides memory-hard, side-channel resistant password hashing.
- **`bincode`:** Compact binary serialization. Eliminates string allocations for field names and values compared to JSON.
- **`readpass`:** A password prompter that natively returns `Zeroizing<String>`, ensuring the prompt buffer is wiped immediately after use.

## 10. Known Limitations

| Threat | bxenc protection | Recommendation |
|---|---|---|
| Attacker reads encrypted files | Protected — XChaCha20-Poly1305 | — |
| Attacker reads vault metadata | Protected — metadata encrypted, same engine | — |
| Vault metadata corruption on power loss | Protected — atomic write-temp-rename | — |
| Vault entry swap / relocation attack | Protected — AAD binding per entry | — |
| Header tampering | Protected — header bytes included in AAD | — |
| Nonce collision (keyfile mode) | Protected — 192-bit XChaCha20 nonce | — |
| **Windows Keyfile Permissions** | **Not protected** — Unix 0600 mode is not supported on Windows | **Ensure the generated keyfile is manually secured or stored on a non-world-readable drive** |
| SSD forensics / wear leveling | Not protected | Full-disk encryption (LUKS/BitLocker/FileVault) |
| RAM cold boot | Partial — keys and sensitive buffers zeroized immediately after use | Cannot fully prevent physical RAM inspection |
| serde/bincode internal allocation residue | Partial — Zeroizing wraps all caller-controlled buffers | Acknowledged sub-limitation; documented here |
| readpass buffer reallocation during long password input | Partial — readpass wraps output in Zeroizing; internal reallocs not recoverable | Use a reasonably long but not extreme password |
| Keylogger / compromised OS | Not protected | OS-level security, outside bxenc's scope |
| Keyfile stolen from filesystem | Not protected if keyfile is on same disk | Store keyfile on a separate device |
| Weak password | Argon2id slows brute force; cannot stop a trivial password | Use a strong passphrase |

## 11. Full-Disk Encryption

Because SSD wear-leveling algorithms write new data to fresh blocks rather than overwriting old blocks, "secure delete" tools are ineffective. If you are concerned about forensic recovery of plaintext files *before* they were encrypted (or after they were extracted), you must use OS-level Full-Disk Encryption (LUKS on Linux, BitLocker on Windows, or FileVault on macOS).

## 12. Cross-Platform Notes

- Windows lacks support for POSIX file permissions. The `bxenc keygen` command will print a warning on Windows to remind users to secure their keyfiles.
- Terminal password prompting works correctly across Windows, macOS, and Linux.
- The `tempfile` crate ensures atomic file replacement works reliably across all supported platforms.

## 13. Contributing

Contributions are welcome! Please run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting pull requests. Ensure all key material and sensitive buffers are wrapped in `Zeroizing`.
