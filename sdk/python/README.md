# CEF Python SDK

Python implementation of the CEF (COSE Encrypted Files) post-quantum secure
file exchange format.

## Quick Start

```python
from cef import encrypt, decrypt, FileInput, Sender, Recipient
from cef.pq import mlkem_keygen, mldsa_keygen

sender = mldsa_keygen()
recip = mlkem_keygen()

result = encrypt(
    files=[FileInput("secret.pdf", doc_bytes)],
    sender=Sender(signing_key=sender.secret_key, kid="alice"),
    recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
)

dec = decrypt(result.container, "bob", recip.secret_key,
              verify_key=sender.public_key)

assert dec.files[0].original_name == "secret.pdf"
```

## Architecture

Same 3-tier model as the Go, TypeScript, and Rust SDKs:

| Layer | Module | Description |
|-------|--------|-------------|
| Workflow | `cef` | `encrypt()`, `decrypt()`, `verify()` |
| Format | `cef.cose` | COSE_Encrypt, COSE_Sign1 |
| Format | `cef.container` | ZIP container, CBOR manifest |
| Format | `cef.crypto` | AES-GCM, AES-KW, HKDF-SHA256 |
| Format | `cef.pq` | ML-KEM-768, ML-DSA-65 |

## Key Format

The Python SDK uses the same expanded key format as Go and TypeScript:

- ML-KEM-768: 1184-byte public key, 2400-byte secret key
- ML-DSA-65: 1952-byte public key, 4032-byte secret key

Cross-SDK interop works in all directions with zero key conversion.

## Tests

```sh
cd sdk/python
python3 -m pytest tests/ -v
```

43 tests covering crypto, PQ, COSE, container, and workflow layers.

## Dependencies

- `pqcrypto` — ML-KEM-768, ML-DSA-65 (FIPS 203/204)
- `cryptography` — AES-GCM, AES-KW, HKDF-SHA256
- `cbor2` — CBOR encoding/decoding
