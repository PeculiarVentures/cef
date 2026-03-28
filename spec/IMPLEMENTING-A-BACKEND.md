# Implementing a CEF Backend

CEF separates the encrypted container format from the key management and
policy layer. The format handles COSE encryption, signing, ZIP packaging,
and CBOR manifest serialization. Your backend provides the key management
and policy enforcement through four callback functions.

This separation is a deliberate architectural choice. The format works
without any backend (direct key exchange, offline, airgap). When a backend
is present, it becomes the **policy enforcement point** — the component
that decides who can encrypt to whom, who can decrypt what, and under
what conditions. This is architecturally equivalent to OpenTDF's Key
Access Server (KAS), but decoupled from the container format.

The backend controls access by controlling key operations:

- **WrapCEK**: The backend decides whether to wrap a CEK for a given
  recipient. It can refuse based on sender identity, recipient policy,
  time-of-day, classification level, or any other business rule.
- **UnwrapCEK**: The backend decides whether to release a CEK to a
  given recipient. It can check policy, require additional
  authentication, log the access, or refuse entirely. Revocation is
  implemented here — if the backend refuses to unwrap, the container
  is effectively revoked even though the encrypted bytes still exist.
- **Sign**: The backend controls which signing keys are available and
  can enforce signing policies (required signatures, key usage
  constraints, audit trail).
- **Verify**: The backend controls trust decisions (which signers are
  accepted, certificate chain validation, timestamp verification).

This means the format supports the full spectrum from zero-backend
(direct PQ key exchange between two parties) to full enterprise DLP
(centralized policy, audit, revocation) — without any change to the
container format itself.

This guide is for implementers building a custom backend. It defines the
callback contract, per-algorithm requirements, container assembly
responsibilities, and testing expectations.

## 1. What the format layer provides

The format layer handles:

- COSE_Encrypt structure building and parsing (RFC 9052)
- COSE_Sign1 structure building and parsing (RFC 9052)
- AES-256-GCM content encryption and decryption
- AES Key Wrap / Unwrap (RFC 3394)
- ZIP container packaging and extraction
- CBOR manifest serialization (deterministic, RFC 8949 §4.2.1)

The format layer does NOT handle:

- Key lookup or resolution (mapping kid to key material)
- Policy evaluation (access control decisions)
- Access revocation (refusing to unwrap after policy change)
- Certificate validation or trust chain verification
- Audit logging
- Recipient enrollment or key directory services

These are responsibilities of your backend. The backend is the policy
enforcement point. Without a backend, CEF is a format for encrypting
files to known public keys. With a backend, CEF becomes a policy-
controlled data protection system where the backend decides every
access decision.

## 2. Callback interface

Your backend provides four callback functions:

```go
// WrapCEKFunc wraps a content encryption key for a recipient.
// Called once per recipient during encryption.
type WrapCEKFunc func(cek []byte, recipient *RecipientInfo) ([]byte, error)

// UnwrapCEKFunc recovers a content encryption key from a recipient structure.
// Called during decryption for the selected recipient entry. MAY be called
// multiple times if the implementation tries more than one matching recipient.
type UnwrapCEKFunc func(wrappedCEK []byte, recipient *Recipient) ([]byte, error)

// SignFunc signs the Sig_structure bytes.
// Called once during encryption to sign the manifest.
type SignFunc func(sigStructure []byte) ([]byte, error)

// VerifyFunc verifies a signature against the Sig_structure bytes.
// Called once during decryption to verify the manifest signature.
type VerifyFunc func(sigStructure, signature []byte) error
```

### 2.1 Callback contract

Callbacks MUST:

- Treat input byte slices as read-only. Do not modify `cek`,
  `wrappedCEK`, `sigStructure`, or `signature` in place.
- Honor `recipient.Algorithm`. The callback MUST perform the operation
  using the algorithm specified in the recipient structure. If the
  algorithm is unsupported, return an error.
- Return an error for unsupported algorithms rather than silently
  substituting another algorithm.
- Return an error for unknown or unresolvable key identifiers.

Callbacks SHOULD:

- Distinguish error types. Recommended sentinel errors or error
  categories:
  - **Key not found**: the kid does not resolve to any known key.
  - **Access denied**: the key exists but policy forbids the operation.
  - **Unsupported algorithm**: the algorithm ID is not implemented.
  - **Invalid recipient**: the recipient structure is malformed.
- Zeroize intermediate secrets (shared secrets, derived KEKs) after use.
  The format layer zeroizes the CEK after encryption/decryption; the
  backend is responsible for secrets it creates during key operations.

Callbacks MUST NOT:

- Modify the returned byte slices after returning them. The format
  layer takes ownership of the returned data.
- Perform additional encryption or signing beyond what the callback
  contract specifies. Side effects (audit logging, metrics) are fine.

## 3. Minimal example

> **Warning**: This example is intentionally minimal. It omits production
> concerns: key lookup by kid, policy enforcement, error handling, key
> zeroization, and trust-chain validation. Do not use this pattern in
> production without addressing those concerns.

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/PeculiarVentures/cef/sdk/go/format/cose"
    gkxcrypto "github.com/PeculiarVentures/cef/sdk/go/format/crypto"
)

func main() {
    // Fixed KEK — in production, resolve from key store by recipient kid.
    kek := make([]byte, 32)
    if _, err := rand.Read(kek); err != nil {
        log.Fatal(err)
    }

    // Fixed signing key — in production, resolve from HSM/key store.
    sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        log.Fatal(err)
    }

    // Wrap: AES Key Wrap the CEK with the recipient's KEK.
    wrapCEK := func(cek []byte, ri *cose.RecipientInfo) ([]byte, error) {
        if ri.Algorithm != cose.AlgA256KW {
            return nil, fmt.Errorf("unsupported algorithm: %d", ri.Algorithm)
        }
        return gkxcrypto.AESKeyWrap(kek, cek)
    }

    // Unwrap: AES Key Unwrap.
    unwrapCEK := func(wrappedCEK []byte, r *cose.Recipient) ([]byte, error) {
        return gkxcrypto.AESKeyUnwrap(kek, wrappedCEK)
    }

    // Sign: ECDSA P-256 over SHA-256.
    signFn := func(sigStructure []byte) ([]byte, error) {
        hash := sha256.Sum256(sigStructure)
        return ecdsa.SignASN1(rand.Reader, sigKey, hash[:])
    }

    // Verify: ECDSA P-256.
    verifyFn := func(sigStructure, signature []byte) error {
        hash := sha256.Sum256(sigStructure)
        if !ecdsa.VerifyASN1(&sigKey.PublicKey, hash[:], signature) {
            return fmt.Errorf("signature verification failed")
        }
        return nil
    }

    // Encrypt
    plaintext := []byte("Hello, CEF!")
    recipients := []cose.RecipientInfo{
        {KeyID: "my-key-001", Algorithm: cose.AlgA256KW},
    }
    msg, err := cose.Encrypt(plaintext, recipients, wrapCEK, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Sign
    msgBytes, err := msg.MarshalCBOR()
    if err != nil {
        log.Fatal(err)
    }
    sig, err := cose.Sign1(cose.AlgES256, "my-signer", msgBytes, true, signFn)
    if err != nil {
        log.Fatal(err)
    }

    // Verify
    sigBytes, err := sig.MarshalCBOR()
    if err != nil {
        log.Fatal(err)
    }
    var sig1 cose.Sign1Message
    if err := sig1.UnmarshalCBOR(sigBytes); err != nil {
        log.Fatal(err)
    }
    if err := cose.Verify1(&sig1, msgBytes, verifyFn); err != nil {
        log.Fatal(err)
    }

    // Decrypt
    var decMsg cose.EncryptMessage
    if err := decMsg.UnmarshalCBOR(msgBytes); err != nil {
        log.Fatal(err)
    }
    decrypted, err := cose.Decrypt(&decMsg, 0, unwrapCEK, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(decrypted)) // "Hello, CEF!"
}
```

## 4. Algorithm-specific requirements

Each key type imposes specific requirements on the wrap/unwrap callback.

### 4.1 AES-256-KW (classical symmetric)

The simplest path. Your `WrapCEKFunc` calls `gkxcrypto.AESKeyWrap(kek, cek)`
with a 32-byte KEK from your key store. Set `RecipientInfo.Algorithm` to
`cose.AlgA256KW` (-5).

Requirements:

- The backend MUST resolve the recipient's kid to a 32-byte KEK.
- The backend MUST return the RFC 3394 wrapped output (40 bytes for a
  32-byte CEK).

### 4.2 ML-KEM-768 (post-quantum)

Your `WrapCEKFunc` performs ML-KEM encapsulation against the recipient's
public key, derives a 256-bit KEK from the shared secret, then wraps
the CEK with AES-256-KW using the derived KEK.

Set `RecipientInfo.Algorithm` to `cose.AlgMLKEM768_A256KW` (-70010).

Requirements:

- The backend MUST use the recipient's ML-KEM-768 public key
  associated with the kid.
- The backend MUST derive the KEK as:
  `KEK = HKDF-SHA256(IKM=shared_secret, salt=empty, info="CEF-ML-KEM-768-A256KW", L=32)` (RFC 5869).
- The backend MUST return `ciphertext || wrappedCEK` as a single
  byte slice (1088 + 40 = 1128 bytes).
- The shared secret MUST be zeroized after KEK derivation.

See `sdk/go/goodkey/ipc/mock_client.go` function `performMLKEMWrap` for
the reference implementation.

### 4.3 ECDH-ES+A256KW (classical key agreement)

Your `WrapCEKFunc` performs ECDH with the recipient's EC public key,
derives a KEK using ANSI-X9.63-KDF (`gkxcrypto.ANSIX963KDF`), then
wraps the CEK with AES-256-KW.

Set `RecipientInfo.Algorithm` to `cose.AlgECDH_ES_A256KW` (-31).

Note: CEF uses a simplified ECDH profile. The ephemeral public key is
not carried in COSE recipient header parameters as in standard COSE
ECDH (RFC 9053 §6.3). Instead, the backend manages ephemeral key
exchange out-of-band. Do not assume RFC-level COSE ECDH-ES
interoperability without verifying your header handling.

## 5. Container assembly

The container package assembles the ZIP archive and manifest structures
but does not by itself guarantee semantic consistency between manifest
metadata, recipient lists, and COSE-level recipients. The orchestration
layer is responsible for ensuring:

- Manifest sender kid matches the COSE_Sign1 signer kid.
- Manifest recipient list aligns with COSE_Encrypt recipients.
- File hashes match actual encrypted content.
- x5c and claims are not both present on the same sender/recipient.

```go
import "github.com/PeculiarVentures/cef/sdk/go/format/container"

c := container.New()
c.SetSender(container.SenderInfo{
    KID: "sign-key",
    Claims: &container.SenderClaims{Email: "sender@example.com"},
})
c.AddRecipient(container.RecipientRef{KID: "recipient-key", Type: "key"})

// Encrypt each file with cose.Encrypt, add to container
c.AddFile("randomname.cose", container.FileMetadata{
    OriginalName:  "document.pdf",
    Hash:          sha256sum[:],
    HashAlgorithm: container.HashAlgSHA256, // -16 (COSE SHA-256)
    Size:          int64(len(plaintext)),
}, encryptedBytes)

// Encrypt manifest, set signature
c.SetEncryptedManifest(encryptedManifestBytes)
c.SetSignature(signatureBytes)

// Write
c.WriteToFile("output.cef")
```

## 6. Verification responsibilities

Signature verification in a production backend is more than calling
`VerifyFunc`. The orchestration layer SHOULD:

1. Identify the signer from the COSE_Sign1 unprotected header (kid)
   or from the manifest sender info.
2. Resolve trust material for that signer (public key, certificate
   chain, trust anchor).
3. Validate the certificate chain (if x5c is present): expiry, key
   usage, revocation status, trust anchor.
4. Enforce any key-usage or policy constraints.
5. Then call the cryptographic verify operation.

The format layer's `VerifyFunc` handles step 5 only. Steps 1-4 are
your backend's responsibility.

## 7. What the backend does NOT need to implement

These are handled by the format layer or orchestration layer, not by
the backend callbacks:

- AES-GCM encryption/decryption — handled by `format/cose`
- CBOR encoding/decoding — handled by `fxamacker/cbor`
- ZIP packaging — handled by `format/container`
- Enc_structure / Sig_structure computation — handled by `format/cose`
- File hash computation and verification — handled by the
  orchestration layer
- Path traversal protection and filename sanitization — handled by
  the orchestration layer
- Decompression bomb limits — handled by the orchestration layer

## 8. Testing your implementation

### 8.1 Positive tests (test vectors)

Use the test vectors in `spec/test-vectors/TEST-VECTORS.md` to verify:

1. Your AES Key Wrap produces the expected output for the given KEK/plaintext.
2. Your Enc_structure computation matches the expected hex.
3. Your COSE_Encrypt CBOR output matches byte-for-byte.
4. Your Sig_structure computation matches the expected hex.
5. Your manifest CBOR uses deterministic encoding (RFC 8949 §4.2.1).

### 8.2 Negative tests (adversarial)

A conforming backend MUST also handle:

1. **Wrong kid**: UnwrapCEKFunc called with a kid that does not resolve
   to any known key. MUST return an error.
2. **Unsupported algorithm**: WrapCEKFunc called with an algorithm ID
   the backend does not implement. MUST return an error.
3. **Corrupted wrapped CEK**: AES Key Unwrap with tampered ciphertext.
   MUST return an integrity error, not corrupt plaintext.
4. **Corrupted signature**: VerifyFunc called with a tampered signature.
   MUST return an error.
5. **Tampered protected headers**: Modified COSE protected header bytes.
   Decryption MUST fail (AAD mismatch).
6. **Multiple recipients, mixed algorithms**: Wrap with both A256KW and
   ML-KEM-768+A256KW recipients in the same container.
7. **Unknown manifest extension fields**: Preserved on round-trip,
   not silently dropped.

### 8.3 Interoperability

Round-trip a container between your backend and the reference SDKs:

1. Encrypt with your backend, decrypt with the Go or TypeScript SDK.
2. Encrypt with a reference SDK, decrypt with your backend.
3. Verify that file hashes, sender info, and recipient lists survive
   the round-trip unchanged.

## 9. Production backend requirements

A production-quality backend implementation SHOULD:

- Resolve keys by kid using a trusted, authenticated mapping (key
  store, HSM inventory, certificate directory).
- Enforce an algorithm allow-list. Reject algorithms not in the
  allow-list rather than falling back.
- Apply policy before unwrap, not after plaintext release. Once the
  CEK is returned to the SDK, the backend has no way to revoke access
  to that container's content.
- Log wrap, unwrap, sign, and verify operations for audit.
- Distinguish key-not-found from access-denied in error responses.
  This matters for debugging and for policy enforcement transparency.
- Zeroize CEKs, shared secrets, and derived KEKs when feasible.
  In garbage-collected runtimes, zeroization is best-effort.
- Validate signing identities and trust chains where applicable
  (see §6 above).
- Avoid reusing stable correlatable kid values if recipient privacy
  matters. Consider per-container or per-session ephemeral identifiers.

## 10. Handling marks and policy claims

The manifest may contain sender-asserted handling marks in the `claims`
block: `classification`, `sci_controls`, `sap_programs`, `dissemination`,
and `releasability`. These are advisory labels — analogous to markings
on an envelope — that describe how the sender intends the contents to
be handled.

### 10.1 Encryption flow (claims as policy input)

When the sender sets handling marks, the backend can use them at two
points:

1. **Key discovery / resolution**: Before encryption, the client asks
   the backend for recipient public keys. The backend MAY expose the
   labels (clearance level, compartments) associated with each key.
   The client or backend can refuse to encrypt to keys whose labels
   do not satisfy the sender's claimed markings. For example, a
   backend could refuse to wrap a CEK to a key not authorized for
   "TOP SECRET" when the sender claims `classification: "TOP SECRET"`.

2. **WrapCEK callback**: The backend's wrap implementation MAY check
   the claimed markings against the recipient key's authorized labels.
   If the recipient key is not policy-authorized for the asserted
   classification, the backend returns an **Access denied** error and
   the CEK is not wrapped for that recipient.

### 10.2 Decryption flow (claims as policy context)

The decrypt flow processes the manifest before individual files:

1. The manifest COSE_Encrypt is unwrapped (the backend's `UnwrapCEK`
   is called for the manifest CEK).
2. The manifest CBOR is decoded, making claims available.
3. File COSE_Encrypt structures are unwrapped (the backend's
   `UnwrapCEK` is called for each file CEK).

Between steps 2 and 3, the backend has the opportunity to read the
sender's handling marks from the decrypted manifest and establish a
policy context for the file unwrap operations. If the recipient's key
is not authorized for the claimed classification, the backend refuses
to unwrap the file CEKs.

Note: the manifest CEK and file CEKs are independent (separate
COSE_Encrypt structures). The backend sees the manifest claims after
unwrapping the manifest but before unwrapping files. This ordering
is built into both SDKs and is not optional.

### 10.3 Important caveats

- Handling marks are sender-asserted and unverified. The backend
  MUST NOT trust them without cross-referencing against the sender's
  identity and the backend's own policy rules.
- The format does not enforce handling marks. Enforcement is entirely
  a backend responsibility.
- A backend that does not implement handling mark checks simply ignores
  the claims. The format works identically with or without them.
- Handling marks are inside the encrypted manifest. They are invisible
  to observers who are not recipients. A CDS operating as a recipient
  can read them after decryption.
