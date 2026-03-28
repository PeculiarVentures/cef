# CEF: COSE Encrypted Files

CEF is a modern encrypted archive and exchange format for securely packaging
and transferring files with protected metadata, multiple recipients, and
strong cryptographic guarantees for confidentiality, integrity, and
authenticity. It is designed to work with a variety of key management
approaches, from user-managed keys and hardware-backed credentials to
enterprise-mediated systems like GoodKey.

Built on IETF standards: COSE (RFC 9052) for encryption and signing, CBOR
(RFC 8949) for serialization, AES-256-GCM for content encryption.
Post-quantum ready (ML-KEM-768, ML-DSA-65).

CEF is not tied to any single identity ecosystem. It supports direct keys
and X.509-based environments today, and its profile and extension model
allows additional recipient and trust frameworks to be incorporated over
time. The goal is to provide a common encrypted container format for
interoperable secure exchange across diverse key management and identity
systems.

## Metadata Privacy

Unlike formats that expose metadata in cleartext manifests, CEF encrypts
the manifest alongside the file payloads. Without a valid recipient key,
an observer cannot determine:

- **Original filenames**: file entries use randomized names
- **Recipient identities**: the manifest listing recipients is encrypted
- **File types and content metadata**: MIME types and other metadata are inside the encrypted manifest

An observer with access to the container can see:

- Number of encrypted entries and their approximate ciphertext sizes
- Recipient key IDs (in each COSE_Encrypt recipient's unprotected header)
- Sender key ID and signature algorithm (in COSE_Sign1)
- Content encryption algorithm (in COSE_Encrypt protected header)
- Whether a signature or timestamp is present

Recipient key IDs are opaque identifiers (typically UUIDs), not names
or emails. However, key IDs may be correlatable across containers if
the same key is used repeatedly. For maximum recipient privacy, backends
should use non-correlatable key identifiers.

## How CEF Can Be Used

**Smart card / CAC card (offline, no server):**
A user encrypts files to a colleague's CAC certificate. The recipient
inserts their card, the card unwraps the CEK via PKCS#11, and the files
are decrypted locally. No network, no key server, no enrollment. The
card is the key management system.

**Cloud KMS (managed keys, no custom infrastructure):**
An application encrypts files using AWS KMS or Azure Key Vault for key
wrapping. Recipients are identified by KMS key ARNs. The KMS handles
key custody and access control. The application only touches the CEF
format layer.

**GoodKey (enterprise key management):**
GoodKey provides multi-provider key custody (smart cards, HSMs, enclaves),
group keys with temporal access control, quorum approval workflows, and
ABAC policy evaluation. The CEF container is the same. GoodKey adds the
management layer on top.

GoodKey supports "encrypt to anyone" by email. The sender specifies an
email address. If the recipient is enrolled, their current key is used.
If they are not enrolled, GoodKey provisions a key pair, wraps the CEK
to it, and marks the recipient as pending. They can decrypt once they
complete enrollment. No pre-enrollment, no key exchange ceremony, no
manual coordination. The sender encrypts and moves on.

Recipients can also be addressed by certificate (PIV/CAC, LDAP directory),
by group (with temporal access control via key versioning), or by direct
key ID.

**Cross-domain transfer (CDS inspection):**
In environments with Cross-Domain Solutions, the CDS is added as a
recipient of the container. The sender's backend includes the CDS key
alongside the intended recipient's key during encryption. The CDS
decrypts the container, inspects for policy compliance (classification,
malware, data loss prevention), and forwards the original container to
the destination network unchanged. End-to-end encryption to the actual
recipient is preserved — the CDS inspects without breaking it.

**Disconnected / denied / disrupted (D3) operations:**
CEF requires no network connectivity for decryption. The recipient's
private key can be local — on a smart card, in a device TPM, in a local
HSM, or provisioned to the device by the backend while connectivity
existed. The sender's backend resolves the recipient's public key and
encrypts. The recipient decrypts using their locally accessible private
key — no callback to a remote service is needed. The post-quantum
default (ML-KEM-768 + ML-DSA-65) provides protection against harvest-
now-decrypt-later attacks in environments where containers may be
captured in transit.

**Legal hold / e-discovery:**
During a litigation hold, the organization's backend adds a legal hold
key as an additional recipient to all new containers. The legal team can
decrypt any container created during the hold period. After the hold is
lifted, new containers no longer include that recipient. Existing
containers are unchanged — the hold key can still decrypt them. The
format supports this naturally through multi-recipient COSE: the hold
key is just another recipient entry.

**Automated pipelines (CI/CD, build artifacts):**
A build system encrypts signed artifacts to deployment environment keys.
The signature proves the build system produced the artifact. The
recipient keys belong to staging and production environments. No human
touches the keys — the SDK callbacks are backed by instance credentials
(AWS IAM role, GCP service account, Kubernetes secret). The container
is the signed, encrypted delivery unit.

**Secure drop / anonymous submission:**
A source encrypts files to a recipient's published ML-KEM public key
(posted on a website, in a key directory, or exchanged out-of-band).
No backend, no enrollment, no account creation. Sender claims are
optional — the source can remain anonymous. The recipient decrypts
locally with their private key.

**In-memory keys (testing and development):**
The Go SDK includes a mock client with in-memory keys for testing. No
external service required. Run `go test ./...` and the full encrypt,
sign, verify, decrypt pipeline works with ML-KEM-768 and ML-DSA-65.

In every case, the `.cef` container is identical. The format layer builds
COSE structures and calls key operation callbacks. What backs those
callbacks is up to the implementation.

## Container Structure

```
container.cef (ZIP archive)
├── META-INF/
│   ├── manifest.cbor.cose        encrypted manifest (COSE_Encrypt)
│   │   ├── version               "0"
│   │   ├── sender                kid + x5c (certificate) or claims (hints)
│   │   ├── recipients[]          key ID, type, extension fields
│   │   └── files{}               original name, SHA-256 hash, size
│   ├── manifest.cose-sign1       detached signature (COSE_Sign1)
│   └── manifest.tst              optional RFC 3161 timestamp
└── encrypted/
    └── <random>.cose             COSE_Encrypt per file
        ├── protected             {algorithm: AES-256-GCM}
        ├── unprotected           {IV: 12 bytes}
        ├── ciphertext            AES-256-GCM encrypted content
        └── recipients[]
            └── {algorithm: ML-KEM-768+A256KW, kid: "..."}
               wrapped CEK (KEM ciphertext + AES-KW)
```

The manifest is itself encrypted. Without a valid recipient key, the
file list, sender identity (kid + claims), recipient identities, and file metadata are
not accessible. The COSE structures do reveal the number of encrypted
entries, their ciphertext sizes, the content encryption algorithm,
recipient key IDs, and the signer's key ID and signature algorithm.
See `spec/SECURITY.md` for the full observable-vs-protected breakdown.

## Example (TypeScript, post-quantum)

```typescript
import { encrypt, decrypt, mlkemKeygen, mldsaKeygen } from '@peculiarventures/cef';

// Generate keys
const sender = mldsaKeygen();    // ML-DSA-65 signing key
const recipient = mlkemKeygen(); // ML-KEM-768 encryption key

// Encrypt files into a .cef container
const { container } = await encrypt({
  files: [{ name: 'secret.pdf', data: documentBytes }],
  sender: { signingKey: sender.secretKey, kid: 'alice' },
  recipients: [{ kid: 'bob', encryptionKey: recipient.publicKey }],
});

// Decrypt and verify
const { files } = await decrypt(container, {
  recipient: { kid: 'bob', decryptionKey: recipient.secretKey },
  verify: sender.publicKey,
});
```

## Example (Go, post-quantum)

```go
import "github.com/PeculiarVentures/cef/sdk/go/cef"

// Encrypt
result, _ := cef.Encrypt(cef.EncryptOptions{
    Files:            []cef.FileInput{{Name: "secret.pdf", Data: docBytes}},
    SenderSigningKey: senderSecretKey,
    SenderKID:        "alice",
    Recipients:       []cef.Recipient{{KID: "bob", EncryptionKey: recipPubKey}},
})

// Decrypt and verify
dec, _ := cef.Decrypt(result.Container, cef.DecryptOptions{
    RecipientKID:           "bob",
    RecipientDecryptionKey: recipSecretKey,
    SenderVerificationKey:  senderPubKey,
})
```

## Example (Rust, post-quantum)

```rust
use cef::{encrypt, decrypt, EncryptOptions, DecryptOptions, Sender, Recipient, FileInput};
use cef::format::pq::{mlkem_keygen, mldsa_keygen};

let sender = mldsa_keygen();
let recip = mlkem_keygen();

let result = encrypt(EncryptOptions {
    files: vec![FileInput { name: "secret.pdf".into(), data: doc_bytes, content_type: None }],
    sender: Sender { signing_key: sender.secret_key, kid: "alice".into(), x5c: None, claims: None },
    recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip.public_key, recipient_type: None }],
    timestamp: None,
}).unwrap();

let dec = decrypt(&result.container, DecryptOptions {
    recipient_kid: "bob".into(),
    decryption_key: recip.secret_key,
    verify_key: Some(sender.public_key),
    skip_signature_verification: false,
}).unwrap();
```

## Repository Structure

```
cef/
├── spec/                      Format specification (language-independent)
│   ├── SPECIFICATION.md       Wire format, CDDL schemas, algorithms
│   ├── SECURITY.md            Threat model and security analysis
│   ├── COMPARISON.md          Comparison with OpenTDF
│   ├── IMPLEMENTING-A-BACKEND.md  Guide for non-GoodKey implementations
│   └── test-vectors/          Interoperability test vectors
│
└── sdk/
    ├── go/                    Go SDK (reference implementation)
    │   ├── cef/               Workflow API: Encrypt/Decrypt/Verify
    │   ├── format/            Format layer (implementable by anyone)
    │   │   ├── crypto/        AES Key Wrap (RFC 3394), HKDF, zeroize
    │   │   ├── cose/          COSE_Encrypt, COSE_Sign1
    │   │   └── container/     ZIP structure, CBOR manifest
    │   └── goodkey/           GoodKey key management integration
    │       ├── exchange/      EncryptFiles, DecryptContainer, VerifyContainer
    │       └── ipc/           GoodKey service client + mock
    │
    ├── typescript/            TypeScript SDK
    │   ├── src/cef.ts         Workflow API: encrypt/decrypt/verify
    │   └── src/format/        Format layer (COSE, container, crypto, PQ)
    │
    └── rust/                  Rust SDK
        ├── src/lib.rs         Workflow API: encrypt/decrypt/verify
        └── src/format/        Format layer (COSE, container, crypto, PQ)
```

## Specification

The format specification in `spec/` is language-independent. It defines the
container structure, CBOR manifest schema (with CDDL), COSE algorithm
profiles, and conformance requirements. Any implementation that produces
containers matching the spec is interoperable.

## SDKs

| Language | Path | Status |
|----------|------|--------|
| Go | `sdk/go/` | Reference implementation (classical + PQ) |
| TypeScript | `sdk/typescript/` | v0 prototyping (classical via WebCrypto, PQ via @noble/post-quantum) |
| Rust | `sdk/rust/` | PQ implementation (ML-KEM-768 + ML-DSA-65 via RustCrypto) |

The Go SDK includes both the format layer (`format/`) and a GoodKey-backed
implementation (`goodkey/`). The format layer has no GoodKey dependency and
can be used with any key management backend.

## Quick Start (Go)

```bash
cd sdk/go
go test ./...
go run ./cmd/cef demo
```

## Interoperability Layers

CEF defines three layers. Implementations may support any subset:

**Core format (universally interoperable):**
- ZIP container with COSE_Encrypt payloads and COSE_Sign1 signature
- AES-256-GCM content encryption
- CBOR manifest with deterministic encoding (RFC 8949 §4.2.1)
- Recipient identification by `kid` (COSE header label 4)
- SHA-256 file hashes verified after decryption
- Optional RFC 3161 timestamp (META-INF/manifest.tst)

**Optional extensions (backward compatible):**
- Recipient type hints (`"key"`, `"email"`, `"group"` in private header -70001)
- Logical key ID, version ID, policy reference in manifest
- Post-quantum algorithms (ML-KEM-768, ML-DSA-65)
- Certificate-backed recipients via `kid` interpreted as SPKI hash,
  certificate fingerprint, or subject key identifier

**GoodKey profile (service-specific):**
- Email-based recipient provisioning
- Group key resolution and rotation
- Quorum approval workflows
- Key versioning with forward and backward temporal enforcement
- ABAC policy evaluation at wrap/unwrap time (planned)

An implementation that handles the core format is fully conforming. The
optional extensions and GoodKey profile add capabilities without breaking
interoperability. The container is the same at every level.

## Access Control Progression

CEF was designed as a foundation for progressively richer access control
models. The container format does not change as the policy model evolves:

1. **Direct keys**. User-managed keys, smart cards, local keystores.
   No server required.
2. **Backend-mediated resolution**. The service resolves recipients by
   email, group, or organizational role. Policy enforcement happens at
   wrap/unwrap time.
3. **Temporal enforcement**. Backends with key versioning can grant
   access to future content only, or revoke access for new containers
   while preserving access to previously received ones.
4. **Attribute-based policy**. Backends that evaluate policies at
   wrap/unwrap time can enforce classification hierarchies, quorum
   requirements, and multi-party authorization.

The format already carries the building blocks for this progression:
protected metadata, recipient structures, versioning hooks (`logical_key_id`,
`version_id`), policy references (`policy_ref`), and profile-specific
resolution semantics (§5.4). Each level is additive, and existing containers
remain readable by simpler implementations.

See `spec/IMPLEMENTING-A-BACKEND.md` for details.

## Algorithms

| Function | Default | COSE ID | Standard |
|----------|---------|---------|----------|
| Key encapsulation | ML-KEM-768 + A256KW | -70010 | FIPS 203 |
| Signing | ML-DSA-65 | -49 | FIPS 204 |
| Content encryption | AES-256-GCM | 3 | FIPS 197 |

Classical fallback (AES-256-KW, ES256, EdDSA) supported. Mixed PQ and
classical recipients in the same container.

## Built on IETF and NIST Standards

CEF uses IETF standards for its cryptographic structures and NIST
standards for its algorithms. The format is open, the specification
is public, and the SDKs are open source.

- COSE encryption and signing (RFC 9052, RFC 9053)
- CBOR serialization (RFC 8949)
- AES-256-GCM authenticated encryption (FIPS 197)
- ML-KEM-768 post-quantum key encapsulation (FIPS 203)
- ML-DSA-65 post-quantum signatures (FIPS 204)
- AES Key Wrap (RFC 3394)
- Open specification, not proprietary
