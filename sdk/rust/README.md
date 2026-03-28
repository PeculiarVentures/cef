# CEF Rust SDK

Rust implementation of the CEF (COSE Encrypted Files) post-quantum secure
file exchange format.

## Quick Start

```rust
use cef::{encrypt, decrypt, EncryptOptions, DecryptOptions, Sender, Recipient, FileInput};
use cef::format::pq::{mlkem_keygen, mldsa_keygen};

let sender = mldsa_keygen();
let recip = mlkem_keygen();

let result = encrypt(EncryptOptions {
    files: vec![FileInput {
        name: "secret.pdf".into(),
        data: b"document bytes".to_vec(),
        content_type: None,
    }],
    sender: Sender {
        signing_key: sender.secret_key,
        kid: "alice".into(),
        x5c: None,
        claims: None,
    },
    recipients: vec![Recipient {
        kid: "bob".into(),
        encryption_key: recip.public_key,
        recipient_type: None,
    }],
    timestamp: None,
}).unwrap();

let dec = decrypt(&result.container, DecryptOptions {
    recipient_kid: "bob".into(),
    decryption_key: recip.secret_key,
    verify_key: Some(sender.public_key),
    skip_signature_verification: false,
}).unwrap();

assert_eq!(dec.files[0].original_name, "secret.pdf");
```

## Architecture

The SDK follows the same 3-tier model as the Go and TypeScript SDKs:

| Layer | Module | Description |
|-------|--------|-------------|
| Workflow | `cef` | `encrypt()`, `decrypt()`, `verify()` |
| Format | `cef::format::cose` | COSE_Encrypt, COSE_Sign1 |
| Format | `cef::format::container` | ZIP container, CBOR manifest |
| Format | `cef::format::crypto` | AES-GCM, AES-KW, HKDF-SHA256 |
| Format | `cef::format::pq` | ML-KEM-768, ML-DSA-65 |

## Key Format

The Rust SDK uses **seed-based** key serialization:

- ML-KEM-768: 64-byte seed (decapsulation key), 1184-byte public key
- ML-DSA-65: 32-byte seed (signing key), 1952-byte public key

This differs from the Go and TypeScript SDKs which use expanded key formats
(2400-byte ML-KEM, 4032-byte ML-DSA). The COSE container format is identical
across all SDKs — only the key serialization differs. Cross-SDK interop
requires key format conversion (planned).

## Tests

```sh
cargo test
```

17 tests covering:
- AES-GCM, AES-KW, HKDF-SHA256 primitives (including RFC 5869 and CEF domain vectors)
- ML-KEM-768 key encapsulation round trip
- ML-DSA-65 signing and verification
- Full encrypt/decrypt workflow (single file, multiple files, multiple recipients)
- Signature verification
- Wrong key rejection
- Input validation (empty recipients, empty files)

## Dependencies

All cryptography from RustCrypto:
- `ml-kem` 0.3.0-rc.1 (FIPS 203)
- `ml-dsa` 0.1.0-rc.8 (FIPS 204)
- `aes-gcm` 0.10 (AES-256-GCM)
- `aes-kw` 0.3.0-rc.2 (RFC 3394)
- `hkdf` 0.12 + `sha2` 0.10 (RFC 5869)
- `ciborium` 0.2 (CBOR)
- `zip` 4 (ZIP container)
