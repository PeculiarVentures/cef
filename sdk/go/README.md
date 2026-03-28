# CEF Go SDK

Reference implementation of the CEF secure file exchange format, backed by
GoodKey key management.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     APPLICATIONS                        │
│  GoodKey Client · MS Word Add-in · Email · Your App     │
│                         │                               │
│              ┌──────────▼──────────┐                    │
│              │  CEF FORMAT LAYER   │ ← format/          │
│              │  (COSE/CBOR)        │                    │
│              └──────────┬──────────┘                    │
│              ┌──────────▼──────────┐                    │
│              │  GOODKEY EXCHANGE   │ ← goodkey/exchange  │
│              │  EncryptFiles()     │                    │
│              │  DecryptContainer() │                    │
│              │  VerifyContainer()  │                    │
│              └──────────┬──────────┘                    │
└─────────────────────────┼───────────────────────────────┘
                          │ IPC (gRPC)
┌─────────────────────────▼───────────────────────────────┐
│                    GOODKEY SERVICE                       │
│                                                         │
│  • Multi-provider keys   • Wrap/Unwrap CEK              │
│  • User auth             • Sign operations              │
│  • Group management      • Recipient provisioning       │
│  • Approval workflows    • Organization keys             │
└─────────────────────────────────────────────────────────┘
```

The format layer (`format/`) is independent of GoodKey. It implements the
CEF container format using COSE/CBOR with callback-based key operations.
Any key management backend can supply the callbacks.

The GoodKey layer (`goodkey/`) wires the format layer to the GoodKey
service via IPC.

## Packages

```
cef/                 Workflow API: Encrypt, Decrypt (recommended entry point)

format/
├── crypto/          AES Key Wrap (RFC 3394), KDF, zeroize (stdlib only)
├── cose/            COSE_Encrypt, COSE_Sign1, AES-GCM
└── container/       ZIP structure, CBOR manifest

goodkey/
├── exchange/        GoodKey orchestration: EncryptFiles, DecryptContainer
├── ipc/             GoodKey service client + mock
├── config/          CLI configuration
└── progress/        CLI progress indicators

cmd/cef/             CLI
```

Dependency graph (one-way, no cycles):

```
cef ──→ format/cose ──→ format/crypto
      │                │
      └──→ format/container
                       │
goodkey/exchange ──→ format/cose
        │
        ├──→ format/container
        │
        └──→ goodkey/ipc ──→ format/crypto
```

## Security Model

1. **Post-quantum by default**. ML-KEM-768 and ML-DSA-65 protect against HNDL
2. **Keys never leave GoodKey**. Wrap, unwrap, and sign are IPC calls
3. **GoodKey never sees content**. File encryption/decryption is local
4. **Encrypted manifest**. File metadata is opaque without a valid key
5. **COSE_Sign1 signatures**. Sender authentication (verified by default)
6. **Hash enforcement**. Files with invalid hashes are rejected by default
7. **Path traversal protection**. File names sanitized during extraction
8. **Symlink protection**. Output paths checked before writing
9. **Constant-time ICV**. AES Key Unwrap uses `subtle.ConstantTimeCompare`

## Recipient Models

The exchange layer supports multiple ways to address recipients:

**Direct key IDs** (`-r key-id`). The simplest model. You know the
recipient's GoodKey key ID and encrypt directly to it.

**Email addresses** (`-e bob@example.com`). Encrypt to anyone by email.
GoodKey looks up the address. If the recipient is enrolled, their
current encryption key is used. If they are not enrolled, GoodKey
provisions a key pair, wraps the CEK to it, and marks the recipient
as pending. They can decrypt once they complete enrollment. No
pre-enrollment required.

**Certificates** (`-c cert.pem` or `--cert-id cert-123`). Encrypt to
a certificate. The SDK extracts the public key from the certificate
and wraps the CEK. This supports PIV/CAC cards, LDAP directory
lookups, and other X.509-based workflows where the operator thinks
in certificates rather than key IDs.

**Groups** (`-g group-id`). Encrypt to a GoodKey group key. Group
membership is managed by the service. Key versioning provides
temporal access control: members who join after version N have no
access to content encrypted under earlier versions.

```go
result, err := svc.EncryptFiles(ctx, inputFiles, outputPath, &exchange.EncryptOptions{
    Recipients:      []string{"key-001"},           // direct key
    RecipientEmails: []string{"bob@example.com"},   // encrypt to anyone
    RecipientCertFiles: []string{"alice-cert.pem"},  // certificate
    RecipientGroups: []string{"eng-team"},           // group
    SenderKeyID:     "my-signing-key",
})

// result.PendingRecipients contains emails of non-enrolled users
for _, email := range result.PendingRecipients {
    fmt.Printf("Pending: %s (will decrypt after enrollment)\n", email)
}
```

## Quick Start

```go
import "github.com/PeculiarVentures/cef/sdk/go/cef"

// Generate keys
senderPub, senderSec := generateMLDSAKeys()
recipPub, recipSec := generateMLKEMKeys()

// Encrypt
result, err := cef.Encrypt(cef.EncryptOptions{
    Files:            []cef.FileInput{{Name: "report.pdf", Data: pdfBytes}},
    SenderSigningKey: senderSec,
    SenderKID:        "alice",
    Recipients:       []cef.Recipient{{KID: "bob", EncryptionKey: recipPub}},
})

// Decrypt and verify
dec, err := cef.Decrypt(result.Container, cef.DecryptOptions{
    RecipientKID:           "bob",
    RecipientDecryptionKey: recipSec,
    SenderVerificationKey:  senderPub,
})
```

### Advanced: GoodKey Service Integration

For GoodKey-managed keys (HSM, enclave, cloud KMS), use the exchange layer:

```bash
go test ./...
go run ./cmd/cef demo
```

## CLI Examples

```bash
# Encrypt a file for a recipient by key ID
cef encrypt -r key-encrypt-001 -k key-sign-mldsa65 report.pdf

# Encrypt multiple files for multiple recipients
cef encrypt -r key-001 -r key-002 -k my-signing-key doc.pdf slides.pptx

# Encrypt to an email address (requires GoodKey backend)
cef encrypt -e bob@example.com -k key-sign-mldsa65 secrets.zip

# Encrypt to a certificate
cef encrypt -c recipient-cert.pem -k key-sign-p256 contract.pdf

# Encrypt to a GoodKey certificate ID
cef encrypt --cert-id cert-abc123 -k key-sign-mldsa65 data.csv

# Encrypt to a group
cef encrypt -g eng-team -k key-sign-mldsa65 roadmap.md

# Decrypt a container
cef decrypt -r key-encrypt-001 -o ./output/ package.cef

# Verify container structure without decrypting
cef verify package.cef

# List available keys
cef keys

# List available certificates
cef certs

# Show current user profile
cef profile

# Run end-to-end demo with mock keys
cef demo
```

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

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/fxamacker/cbor/v2` | CBOR encoding/decoding |
| `github.com/cloudflare/circl` | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) |

## GoodKey Integration Status

The exchange layer (`goodkey/exchange/`) is designed to work with the
real GoodKey service. Current integration status:

**Works today with the local GoodKey service (IPC gRPC):**
- Key listing, profile, certificates (direct proto match)
- Signing with ML-DSA-65, ECDSA, Ed25519 (via `sign` operation)
- Classical key unwrapping (via `decrypt` operation)
- ML-KEM-768 encryption (local encapsulation, no server round-trip)

**Works today with the GoodKey server REST API:**
- ML-KEM-768 decryption (via `derive` operation with `cipherText` parameter)
- All classical operations

**Requires GoodKey service changes:**
- `LookupRecipient` / `LookupRecipients` RPCs for the encrypt-to-anyone
  flow. The types and exchange logic are implemented in CEF but the RPCs
  are not yet in the GoodKey service proto.
- The local IPC gRPC handler may need to route `derive` operations with
  `cipherText` in the parameters map to `PostQuantumProvider.decapsulate()`.
  This routing exists in the REST API path but may not be wired in the
  local IPC handler.

**Adapter needed:**
The CEF `CEFServiceClient` interface uses `context.Context` and
struct-based requests. The real GoodKey Go client uses positional args
and no context. A thin adapter (~100 lines) bridges these. See
`goodkey/ipc/client.go` for the interface and
`goodkey/ipc/mock_client.go` for a complete implementation.

## API Documentation

Go documentation is generated automatically from doc comments. Once the
repository is public, docs will be available at:

https://pkg.go.dev/github.com/PeculiarVentures/cef/sdk/go

### Workflow API (`cef` package)

| Function | Description |
|----------|-------------|
| `cef.Encrypt(opts)` | Encrypt files into a signed CEF container |
| `cef.Decrypt(container, opts)` | Decrypt and verify a CEF container |
| `cef.Verify(container, opts)` | Verify signature without decrypting |

### Key Types

| Type | Description |
|------|-------------|
| `cef.EncryptOptions` | Files, sender identity, recipients, optional callbacks |
| `cef.DecryptOptions` | Recipient key, sender verification, optional callbacks |
| `cef.VerifyOptions` | Sender verification key |
| `cef.FileInput` | Name + data + optional content type |
| `cef.Recipient` | KID + encryption key + optional type |
| `cef.EncryptResult` | Container bytes, file count, signed flag |
| `cef.DecryptResult` | Decrypted files, signature validity, sender identity |
| `cef.VerifyResult` | Signature validity, sender KID, timestamp present |

### Custom Key Management (HSM, Cloud KMS)

For backends that manage keys externally, provide callbacks instead of raw keys:

```go
result, _ := cef.Encrypt(cef.EncryptOptions{
    Files:      []cef.FileInput{{Name: "secret.pdf", Data: docBytes}},
    SenderKID:  "hsm-signer",
    Recipients: []cef.Recipient{{KID: "hsm-recipient"}},
    KeyWrap:    func(cek []byte, ri *cose.RecipientInfo) ([]byte, error) {
        return myHSM.WrapKey(cek, ri.KeyID)
    },
    Sign: func(data []byte) ([]byte, error) {
        return myHSM.Sign(data)
    },
})
```

### Core Packages

| Package | Description |
|---------|-------------|
| `format/cose` | COSE_Encrypt, COSE_Sign1, AES-256-GCM, AES Key Wrap |
| `format/container` | ZIP container I/O, CBOR manifest serialization |
| `format/crypto` | AES Key Wrap (RFC 3394), ANSI-X9.63-KDF, zeroization |
| `goodkey/exchange` | GoodKey service orchestration |
| `goodkey/cert` | X.509 certificate parsing and validation |
| `goodkey/ipc` | GoodKey service client interface |
