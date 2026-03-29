# CEF SDK API Design — Polyglot

## Design principles

1. **Workflow-first**: `encrypt`, `decrypt`, `verify` are the front door.
2. **One recipient model**: A single `Recipient` type with a `kind` discriminator.
3. **Options, not layers**: Advanced control via options on the same functions, not separate APIs.
4. **Format underneath**: Raw COSE/container primitives available but not the default import.
5. **Integrations alongside**: GoodKey, X.509, timestamps are separate opt-in modules.
6. **Polyglot-native**: Same mental model, idiomatic in each language.

## The three tiers

```
┌─────────────────────────────────────────────┐
│  WORKFLOW API                               │
│  encrypt() / decrypt() / verify()           │
│  This is what 90% of developers use.        │
├─────────────────────────────────────────────┤
│  CORE / FORMAT                              │
│  COSE, Container, Crypto, PQ primitives     │
│  For format implementers and interop.       │
├─────────────────────────────────────────────┤
│  INTEGRATIONS                               │
│  GoodKey, X.509, Timestamps                 │
│  Opt-in modules for specific ecosystems.    │
└─────────────────────────────────────────────┘
```

## Workflow API

### encrypt

```
encrypt(options) → EncryptResult

options:
  files:      [{name, data, ?contentType}]
  sender:     Sender
  recipients: [Recipient]
  ?timestamp: Uint8Array        # pre-built RFC 3161 token
  ?keyWrap:   KeyWrapFunc       # custom wrap callback (advanced)
  ?sign:      SignFunc          # custom sign callback (advanced)
```

### decrypt

```
decrypt(container, options) → DecryptResult

options:
  recipient:  RecipientKey      # who am I?
  ?verify:    VerifySource      # sender pub key, or custom callback
```

### verify

```
verify(container, options) → VerifyResult

options:
  ?senderKey: Uint8Array        # if known
  ?verify:    VerifyFunc        # custom callback
```

## Sender model

```
Sender:
  signingKey: Uint8Array        # ML-DSA-65 secret key
  kid:        string            # key identifier
  ?x5c:       [Uint8Array]      # certificate chain (exclusive with claims)
  ?claims:    {?email, ?name}   # unverified hints (exclusive with x5c)
```

When x5c is present, claims are ignored (spec §5.5).
created_at is auto-set by the SDK as a sender claim.

## Recipient model (unified)

```
Recipient:
  kid:           string
  encryptionKey: Uint8Array     # ML-KEM-768 public key
  ?kind:         "key" | "certificate"   # default: "key"
  ?x5c:          [Uint8Array]   # certificate chain
```

GoodKey adds these kinds via its integration:
  ?kind: "email" | "group" | "policy"

The core SDK only knows about "key" and "certificate".
Integration modules extend the recipient model.

## RecipientKey (for decrypt)

```
RecipientKey:
  kid:           string
  decryptionKey: Uint8Array     # ML-KEM-768 secret key
```

## VerifySource (for decrypt verification)

Either:
  - Uint8Array (raw public key — common case)
  - VerifyFunc callback (custom verification — advanced)
  - null/undefined (skip verification)

## Results

```
EncryptResult:
  container:  Uint8Array        # the .cef file bytes
  fileCount:  number
  signed:     boolean

DecryptResult:
  files:      [{originalName, data, size}]
  signature:  "valid" | "skipped" | "failed"
  sender:     {kid, ?x5c, ?claims}
  ?createdAt: string            # from sender claims

VerifyResult:
  signatureValid:  boolean
  senderKid:       string
  timestampPresent: boolean
```

## Language-specific shapes

### TypeScript

```typescript
// Main API — this is the default import
import { encrypt, decrypt, verify } from '@peculiarventures/cef';

const { container } = await encrypt({
  files: [{ name: 'report.pdf', data: pdfBytes }],
  sender: { signingKey: senderSec, kid: 'alice' },
  recipients: [{ kid: 'bob', encryptionKey: bobPub }],
});

const { files } = await decrypt(container, {
  recipient: { kid: 'bob', decryptionKey: bobSec },
  verify: senderPub,
});

// Core primitives — for format implementers
import { cose, container, crypto } from '@peculiarventures/cef/core';

// GoodKey integration — opt-in
import { createGoodKeyAdapter } from '@peculiarventures/cef/goodkey';

// Utilities — opt-in
import { parseCertificate } from '@peculiarventures/cef/x509';
import { buildTimestampRequest } from '@peculiarventures/cef/timestamp';
```

### Go

```go
// Main API
import "github.com/PeculiarVentures/cef"

result, err := cef.Encrypt(cef.EncryptOptions{
    Files:      []cef.FileInput{{Name: "report.pdf", Data: pdfBytes}},
    Sender:     cef.Sender{SigningKey: senderSec, KID: "alice"},
    Recipients: []cef.Recipient{{KID: "bob", EncryptionKey: bobPub}},
})

dec, err := cef.Decrypt(result.Container, cef.DecryptOptions{
    Recipient: cef.RecipientKey{KID: "bob", DecryptionKey: bobSec},
    Verify:    senderPub,
})

// Core primitives
import "github.com/PeculiarVentures/cef/core/cose"
import "github.com/PeculiarVentures/cef/core/container"

// GoodKey integration
import "github.com/PeculiarVentures/cef/goodkey"

// Utilities
import "github.com/PeculiarVentures/cef/x509"
import "github.com/PeculiarVentures/cef/timestamp"
```

### Rust

```rust
use cef::{encrypt, decrypt, verify, EncryptOptions, DecryptOptions, VerifyOptions};
use cef::{Sender, Recipient, FileInput};
use cef::format::pq::{mlkem_keygen, mldsa_keygen};

let sender = mldsa_keygen();
let recip = mlkem_keygen();

let result = encrypt(EncryptOptions {
    files: vec![FileInput {
        name: "report.pdf".into(),
        data: pdf_bytes,
        content_type: Some("application/pdf".into()),
    }],
    sender: Sender {
        signing_key: sender.secret_key,
        kid: "alice".into(),
        x5c: None,
        claims: Some(SenderClaims {
            email: Some("alice@example.com".into()),
            classification: Some("SECRET".into()),
            ..Default::default()
        }),
    },
    recipients: vec![Recipient {
        kid: "bob".into(),
        encryption_key: recip.public_key,
        recipient_type: None,
    }],
    timestamp: None,
})?;

let dec = decrypt(&result.container, DecryptOptions {
    recipient_kid: "bob".into(),
    decryption_key: recip.secret_key,
    verify_key: Some(sender.public_key),
    skip_signature_verification: false,
})?;

// Format layer available directly
use cef::format::{cose, container, crypto, pq};
```

### Python

```python
from cef import encrypt, decrypt, verify, FileInput, Sender, Recipient
from cef.pq import mlkem_keygen, mldsa_keygen
from cef.container import SenderClaims

sender = mldsa_keygen()
recip = mlkem_keygen()

result = encrypt(
    files=[FileInput("report.pdf", pdf_bytes, content_type="application/pdf")],
    sender=Sender(
        signing_key=sender.secret_key, kid="alice",
        claims=SenderClaims(email="alice@example.com", classification="SECRET"),
    ),
    recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
)

dec = decrypt(result.container, "bob", recip.secret_key,
              verify_key=sender.public_key)

# Format layer available directly
from cef import cose, container, crypto, pq
```

### Java (future)

```java
import com.peculiarventures.cef.CEF;
import com.peculiarventures.cef.EncryptOptions;

var result = CEF.encrypt(EncryptOptions.builder()
    .files(List.of(new FileInput("report.pdf", pdfBytes)))
    .sender(Sender.of(senderSec, "alice"))
    .recipients(List.of(Recipient.key("bob", bobPub)))
    .build());

var dec = CEF.decrypt(result.container(), DecryptOptions.builder()
    .recipient(RecipientKey.of("bob", bobSec))
    .verify(senderPub)
    .build());

// Core primitives: com.peculiarventures.cef.core.*
// GoodKey: com.peculiarventures.cef.goodkey.*
```

## Migration from current API

Current → New mapping:

  simpleEncrypt(opts)           → encrypt(opts)     [renamed, restructured opts]
  simpleDecrypt(container,opts) → decrypt(container,opts) [renamed, restructured opts]
  verifyContainer(container)    → verify(container,opts)

  encryptFiles(files, opts)     → encrypt(files, { keyWrap: ..., sign: ... })
  decryptContainer(bytes, opts) → decrypt(bytes, { recipient: ..., verify: ... })

  format/cose                   → @cef/core or cef/core/cose
  format/container              → @cef/core or cef/core/container
  format/crypto                 → @cef/core or cef/core/crypto
  format/pq                     → @cef/core or cef/core/pq

  goodkey/cert                  → @cef/x509
  goodkey/timestamp             → @cef/timestamp

The key insight: `simple` and `exchange` collapse into one function with
different options. Direct keys → just provide them. Custom backend →
provide keyWrap/sign callbacks.

## What does NOT change

- Wire format (COSE/CBOR/ZIP)
- Cryptographic operations
- Test vectors
- Spec, Security, Comparison docs
- Demo (uses whatever the TS SDK exports)

## Implementation plan

1. Write the new workflow API as a thin wrapper over existing code
2. Re-export from new entry points
3. Update tests to use new API
4. Update demo to use new API
5. Update READMEs
6. Deprecate old entry points (don't remove yet)
