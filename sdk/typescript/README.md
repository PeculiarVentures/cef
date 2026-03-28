# CEF TypeScript SDK

TypeScript implementation of the CEF (COSE Encrypted Files) format for
browser and Node.js environments. Uses the Web Crypto API for classical
cryptographic operations and @noble/post-quantum for ML-KEM-768 and
ML-DSA-65.

⚠️  **v0, prototyping only.** The post-quantum module uses
@noble/post-quantum, which is audited but not FIPS-certified. Use the
Go SDK with CIRCL for production PQ workloads.

## Quick Start

```bash
npm install
npm run build
npm test
```

## Architecture

```
src/
├── format/
│   ├── crypto.ts      AES-KW, AES-GCM, SHA-256 (WebCrypto)
│   ├── cose.ts        COSE_Encrypt, COSE_Sign1
│   ├── container.ts   ZIP (fflate) + CBOR manifest (cbor-x)
│   └── pq.ts          ML-KEM-768, ML-DSA-65 (@noble/post-quantum)
└── index.ts
```

The format layer is backend-neutral. Key operations (wrap, unwrap, sign,
verify) are provided via async callback functions, just like the Go SDK.

## Usage

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

### Custom Key Management (HSM, cloud KMS)

For backends that manage keys externally, provide callbacks:

```typescript
import { encrypt } from '@peculiarventures/cef';

const { container } = await encrypt({
  files: [{ name: 'secret.pdf', data: documentBytes }],
  sender: { signingKey: new Uint8Array(0), kid: 'signer' },
  recipients: [{ kid: 'hsm-key-001', encryptionKey: new Uint8Array(0) }],
  keyWrap: async (cek, recipient) => myHSM.wrap(cek, recipient),
  sign: async (data) => myHSM.sign(data),
});
```

### Package Exports

| Import | Contents |
|--------|----------|
| `@peculiarventures/cef` | Workflow API: `encrypt`, `decrypt`, `verify`, key generation |
| `@peculiarventures/cef/core` | COSE/CBOR primitives, container, crypto, PQ algorithms |
| `@peculiarventures/cef/x509` | X.509 certificate parsing and validation |
| `@peculiarventures/cef/timestamp` | RFC 3161 timestamp request/response utilities |

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
| `cbor-x` | CBOR encoding/decoding |
| `fflate` | ZIP compression |
| `@noble/post-quantum` | ML-KEM-768, ML-DSA-65 (prototyping) |

Classical cryptography (AES-GCM, AES-KW, ECDSA, SHA-256) uses the
Web Crypto API with zero external dependencies.

## Platform Support

Works anywhere Web Crypto is available: modern browsers, Node.js 20+,
Deno, Cloudflare Workers, Bun. The PQ module requires @noble/post-quantum
which is pure JS and works on all platforms.

## Tests

86 tests covering:
- Crypto primitives (AES-KW, AES-GCM, SHA-256)
- COSE_Encrypt (round-trip, multi-recipient, marshal/unmarshal)
- COSE_Sign1 (round-trip, detached payload, tamper detection)
- Container (manifest CBOR, ZIP round-trip, extension fields)
- ML-KEM-768 (encrypt/decrypt, wrong-key rejection)
- ML-DSA-65 (sign/verify, tamper detection)
- Full PQ pipeline (encrypt + sign + verify + decrypt)
- Exchange (multi-file, path traversal, signature enforcement)
- Certificate validation (expiry, key usage, chain, real X.509 via @peculiar/x509)
- RFC 3161 timestamps (DER TSTInfo create/verify/container round-trip)

## GoodKey Integration

The TypeScript SDK is backend-neutral. It uses callback functions
(`wrapCEK`, `unwrapCEK`, `signFn`, `verifyFn`) for all key operations
and never talks to any service directly.

To use the TS SDK with GoodKey, you write a thin adapter that calls
the GoodKey REST API and feeds results into the callbacks. The REST
API uses standard HTTP:

- `POST /key/{id}/operation` with JSON body to create operations
- `PATCH /key/{id}/operation/{opId}/finalize` with data to finalize
- Auth is a bearer token

For ML-KEM-768 decryption, the adapter would:
1. Send the ML-KEM ciphertext as a `derive` operation with `cipherText` parameter
2. Receive the shared secret from the server
3. Derive the KEK locally (SHA-256 with domain separation)
4. Unwrap the CEK with AES-KW locally

This adapter is planned as `src/goodkey/client.ts`. The `goodkey/`
module already provides certificate validation (`cert.ts` via
`@peculiar/x509`) and timestamp handling (`timestamp.ts` via
`@peculiar/asn1-tsp`).

## API Documentation

Generate API docs locally:

```bash
npm run docs
```

This produces HTML documentation in `sdk/typescript/docs/` using [TypeDoc](https://typedoc.org/).

### Workflow API (`@peculiarventures/cef`)

| Function | Description |
|----------|-------------|
| `encrypt(opts)` | Encrypt files into a signed CEF container |
| `decrypt(container, opts)` | Decrypt and verify a CEF container |
| `verify(container, opts?)` | Verify signature without decrypting |
| `mlkemKeygen()` | Generate ML-KEM-768 key pair |
| `mldsaKeygen()` | Generate ML-DSA-65 key pair |

### Key Types

| Type | Description |
|------|-------------|
| `EncryptOptions` | Files, sender identity, recipients, optional timestamp |
| `Sender` | Signing key + kid + optional x5c or claims |
| `Recipient` | Encryption key + kid + optional kind ('key' or 'certificate') |
| `DecryptOptions` | Recipient key + sender verification (public key, callback, or `false`) |
| `EncryptResult` | Container bytes, file count, signed flag |
| `DecryptResult` | Decrypted files, signature status, sender info |

### Core API (`@peculiarventures/cef/core`)

| Function | Description |
|----------|-------------|
| `encrypt(plaintext, recipients, wrapCEK, opts?)` | Low-level COSE_Encrypt |
| `decrypt(msg, recipientIndex, unwrapCEK, opts?)` | Low-level COSE_Decrypt |
| `sign1(algorithm, kid, payload, detached, signFn)` | COSE_Sign1 |
| `verify1(msg, payload, verifyFn)` | Verify COSE_Sign1 |
| `marshalEncrypt(msg)` / `unmarshalEncrypt(data)` | CBOR serialization |
| `marshalSign1(msg)` / `unmarshalSign1(data)` | CBOR serialization |
| `createContainer()` / `readContainer(data)` | ZIP container I/O |
| `marshalManifest(m)` / `unmarshalManifest(data)` | CBOR manifest I/O |
