# CEF Threat Model and Security Analysis

**Version**: 0
**Status**: Draft
**Date**: March 2026

## 1. Scope

This document is the threat model for the CEF container format. It
describes the security properties the format provides, the trust
assumptions it makes, what it protects and what it does not, and where
the boundary lies between the core format and profile/backend-specific
enforcement.

## 2. Assets

The following assets are protected by a CEF container:

- **File content**: The plaintext of each file in the container.
- **File metadata**: Original filenames, sizes, MIME types, and the
  mapping between obfuscated ZIP entry names and real filenames.
- **Recipient structure**: Which key IDs and recipient types the
  container is addressed to.
- **Sender identity**: The sender's key identifier (kid) with either a certificate chain (x5c) for verified identity or unverified claims (email, name) for UI hints. x5c and claims are intended to be used exclusively of one another. If both are present, implementations MUST rely on x5c for verified identity and ignore claims.
- **Policy metadata**: Any logical key IDs, version IDs, or policy
  references carried in the manifest or recipient structures.

## 3. Adversary Model

CEF assumes the following adversaries:

**Passive network observer.** Can capture the `.cef` file in transit.
Cannot modify it. Wants to learn file contents or metadata.

**Active network attacker.** Can capture, modify, replay, or inject
`.cef` files. Wants to read content, tamper with files, or impersonate
a sender.

**Unauthorized recipient.** Has access to the `.cef` file but does not
possess, or cannot successfully use, a recipient key authorized for
unwrap under the active backend policy. This includes: not holding a
listed key, holding a revoked key, failing policy evaluation, or
lacking required device posture or quorum approval.

**Compromised storage.** The `.cef` file is stored on untrusted media
(cloud storage, email server, shared drive). The storage operator can
read and copy the file.

CEF does **not** attempt to defend against:

- A compromised SDK or client application (the SDK holds plaintext
  during encrypt/decrypt)
- A compromised key management backend (the backend can unwrap any CEK
  it manages)
- Memory forensics on the client during or after encrypt/decrypt
- Side-channel attacks on the client's AES-GCM or KEM implementation

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  KEY MANAGEMENT BACKEND (policy enforcement point)  │
│                                                     │
│  Controls all key operations: wrap, unwrap, sign,   │
│  verify. Enforces access policy at operation time.  │
│  Implements revocation by refusing to unwrap.       │
│  Provides audit trail for all key operations.       │
│  Examples: GoodKey, smart card, cloud KMS, HSM.     │
├─────────────────────────────────────────────────────┤
│  SDK / CLIENT APPLICATION (trusted for plaintext)   │
│                                                     │
│  Generates CEK and IV. Encrypts/decrypts content.   │
│  Builds COSE structures. Computes hashes.           │
│  Packages/extracts ZIP. Holds plaintext in memory.  │
├─────────────────────────────────────────────────────┤
│  TRANSPORT AND STORAGE (untrusted)                  │
│                                                     │
│  Email, cloud storage, file shares, message queues. │
│  Can read, copy, and store the .cef container.      │
│  Cannot decrypt without a recipient key.            │
└─────────────────────────────────────────────────────┘
```

The trust boundary between the SDK and the backend is the callback
interface (`WrapCEKFunc`, `UnwrapCEKFunc`, `SignFunc`, `VerifyFunc`).
The SDK never sees backend-managed KEKs. The backend does not process
file plaintext through the CEF format itself, but in some deployments
it may receive plaintext CEKs for wrap or unwrap operations. The exact
security boundary varies by backend type. This diagram illustrates the
common abstract model used by service-backed deployments; local-key and
smart-card deployments collapse or relocate some boundaries.

### 4.1 The Backend as Policy Enforcement Point

CEF deliberately separates the container format from the policy layer.
The format defines *how* data is encrypted and structured. The backend
defines *who* can encrypt to whom, *who* can decrypt, and *under what
conditions*.

This separation means the same encrypted container format supports the
full spectrum of deployment models:

- **No backend (direct key exchange)**: Two parties exchange ML-KEM
  public keys out-of-band and encrypt files directly. No policy
  enforcement, no revocation, no audit. Suitable for peer-to-peer
  exchange, air-gapped environments, and disconnected operations.

- **Local key management (smart card, HSM)**: Keys are held in hardware.
  The hardware enforces key usage policies (PIN, biometric, usage count)
  but there is no centralized policy or audit.

- **Service-backed key management (GoodKey, cloud KMS)**: A backend
  service controls all key operations. GoodKey uses Cedar (a formally
  verified authorization policy language) as the decision engine,
  evaluating attribute-based policies at every wrap and unwrap
  operation. Policies can require clearance levels, team membership,
  geographic restrictions, FIDO authentication, ceremony-room
  co-presence, and quorum approval — evaluated conjunctively.
  **Temporal enforcement** is achieved through key versioning: users
  lose access to key versions created after their group removal.
  **Revocation** is implemented by refusing to unwrap — the encrypted
  bytes persist but become inaccessible. Every decision is logged with
  the matched policy version, reason code, and full context snapshot
  for audit and compliance. This is architecturally equivalent to
  OpenTDF's Key Access Server but decoupled from the container format
  and backed by a formally verified policy engine.

- **Federated key management**: Multiple backend services cooperate
  across organizational boundaries. Each organization controls its own
  key operations and policy, but containers are interoperable because
  the format is backend-agnostic.

The format does not prescribe which model is used. A container encrypted
through GoodKey is byte-for-byte identical to one encrypted with direct
key exchange — the difference is entirely in who controlled the key
operations and what policy was evaluated.

## 5. Security Properties Provided by the Core Format

These properties hold for any conforming CEF implementation, regardless
of which backend is used.

### 5.1 Confidentiality

All file content is encrypted with AES-256-GCM. The CEK is randomly
generated per COSE_Encrypt structure (one per file, one for the
manifest). The CEK is wrapped for each recipient via the backend and
never stored in plaintext in the container.

The manifest (filenames, sizes, sender, recipients, policy metadata)
is itself encrypted as a COSE_Encrypt structure. Without a valid
recipient key, the manifest content is not accessible.

### 5.2 Integrity

AES-256-GCM is an AEAD cipher. Any modification to the ciphertext, IV,
or Additional Authenticated Data (AAD) causes decryption to fail. The
AAD is the COSE Enc_structure (RFC 9052 §5.3), which binds the
protected header (including algorithm identifier) to the ciphertext.

Post-decryption, SHA-256 hashes in the manifest provide a second
integrity check on each file's plaintext content. Conforming
implementations reject files with hash mismatches by default.

### 5.3 Authentication

The COSE_Sign1 detached signature covers the encrypted manifest bytes.
A valid signature proves that the entity controlling the signing key
produced the signed encrypted manifest bytes. Conforming implementations
SHOULD verify signatures when present and SHOULD clearly indicate when
a container is unsigned, signature verification is skipped, or
signature verification fails.

The signature does not directly cover plaintext bytes. Instead, it
covers the encrypted manifest, and the manifest contains per-file
SHA-256 hashes. Signature verification combined with successful hash
verification therefore provides integrity protection for the decrypted
file contents.

Authentication strength depends on the backend: a GoodKey-managed
signing key provides service-attested authentication; a smart card
key provides possession-based authentication; an in-memory test key
provides no meaningful authentication.

### 5.4 Recipient Privacy

The manifest is encrypted, so the list of recipients is not visible
without decryption. However, the COSE_Encrypt recipient array in each
encrypted entry contains per-recipient structures with key IDs in the
unprotected header. An observer who can parse the COSE_Encrypt CBOR
can see the `kid` values. These are key identifiers, not names or
emails, but reuse of stable kid values across containers can enable
cross-container correlation by observers, even when the manifest
remains encrypted.

For maximum recipient privacy, backends SHOULD use opaque, non-
correlatable key IDs (e.g., random UUIDs or per-container ephemeral
identifiers rather than email-derived or stable user identifiers).

## 6. Observable Metadata (Not Protected)

Even without decryption, an observer with access to the `.cef` file
can determine:

| Observable | Source |
|-----------|--------|
| Number of encrypted files | ZIP directory entry count |
| Approximate file sizes | COSE_Encrypt ciphertext lengths |
| Presence of a signature | Existence of `manifest.cose-sign1` entry |
| Presence of a timestamp | Existence of `manifest.tst` entry |
| Signer's key ID and algorithm | COSE_Sign1 unprotected and protected headers |
| Recipient key IDs | COSE_Encrypt recipient unprotected headers |
| Key wrap algorithms per recipient | COSE_recipient protected headers |
| Content encryption algorithm | COSE_Encrypt protected header |

Reuse of stable kid values across containers can enable cross-container
correlation by observers, even when the manifest remains encrypted.

The following are **not** observable without decryption:

| Protected | Reason |
|----------|--------|
| Original filenames | Inside encrypted manifest |
| File-to-name mapping | Inside encrypted manifest |
| Sender claims (email, name) | Inside encrypted manifest (unverified hints) |
| MIME types | Inside encrypted manifest |
| Recipient claims | Inside encrypted manifest (unverified hints) |
| Policy references | Inside encrypted manifest |
| Extension fields | Inside encrypted manifest |

## 7. Attacks In Scope

### 7.1 Unauthorized Decryption

**Attack**: Attacker obtains the container and attempts to decrypt
without holding a recipient key.

**Defense**: AES-256-GCM with a 256-bit random CEK. The CEK is wrapped
with the recipient's KEK via the backend. Without the KEK, brute-force
is computationally infeasible (2^256 for AES, 2^192 for ML-KEM-768
against a quantum adversary).

### 7.2 Content Tampering

**Attack**: Attacker modifies the container in transit.

**Defense**: AES-GCM authentication tag detects any modification to
ciphertext, IV, or AAD. SHA-256 hashes detect modification to decrypted
content (defense in depth). COSE_Sign1 detects modification to the
encrypted manifest.

### 7.3 Sender Impersonation

**Attack**: Attacker creates a container that appears to be from a
legitimate sender.

**Defense**: COSE_Sign1 signature over the encrypted manifest. The
attacker cannot produce a valid signature without the sender's signing
key. Conforming implementations SHOULD verify signatures when present.

### 7.4 Harvest Now, Decrypt Later (HNDL)

**Attack**: Attacker captures containers now and waits for a
cryptographically relevant quantum computer.

**Defense**: ML-KEM-768 (FIPS 203) for key encapsulation and ML-DSA-65
(FIPS 204) for signatures provide post-quantum security. AES-256-GCM
provides approximately 128-bit security against quantum adversaries
under Grover-style analysis.

### 7.5 Replay

**Attack**: Attacker re-sends a previously captured container.

**Not defended at the format layer.** CEF containers have no nonce or
sequence number. Applications requiring replay protection must implement
it at the transport or application layer. The optional RFC 3161
timestamp provides temporal evidence but does not prevent replay.

### 7.6 Path Traversal

**Attack**: Malicious container contains filenames like `../../etc/passwd`.

**Defense**: Conforming implementations MUST sanitize filenames during
extraction, rejecting path separators, `..` sequences, null bytes,
and hidden file prefixes. The reference SDKs enforce this.

### 7.7 ZIP Bomb

**Attack**: Container with small compressed size that expands to
exhaust memory.

**Defense**: Conforming implementations SHOULD enforce decompressed
size limits and entry count limits to mitigate archive expansion
attacks. The reference SDKs apply concrete runtime-specific limits.

## 8. Properties Enforced by Backends, Not the Format

The following are **not** enforced by the CEF container format. They
are responsibilities of the key management backend or profile:

| Property | Enforcement point |
|----------|------------------|
| Access revocation | Backend refuses unwrap after revocation |
| Temporal access control | Backend evaluates key version at unwrap time |
| Attribute-based access | Backend evaluates ABAC policy at wrap/unwrap |
| Quorum approval | Backend requires N-of-M approval for key operations |
| Key rotation | Backend resolves logical key ID to current version |
| Recipient provisioning | Backend provisions keys for email recipients |
| Certificate validation | Backend validates X.509 chain and key usage |
| Audit logging | Backend records all key operations |

A minimal backend (e.g., in-memory keys for testing) provides none of
these. A full backend (e.g., GoodKey with HSM) provides all of them.
The CEF format is the same in both cases. The security difference is
entirely in what the backend enforces at operation time.

## 9. Key Material Lifecycle

```
CEK lifecycle:

  1. Generated by SDK (32 random bytes from CSPRNG)
  2. Used to encrypt one COSE_Encrypt structure (one file or manifest)
  3. Wrapped for each recipient via backend callback
  4. Zeroized in SDK memory (best-effort; GC may retain copies)
  5. Never stored in plaintext in the container
  6. Recovered by backend unwrap during decryption
  7. Used to decrypt one COSE_Encrypt structure
  8. Zeroized again

KEK lifecycle:

  Managed entirely by the backend. The SDK never sees KEKs.
  The format does not constrain KEK storage, rotation, or lifecycle.
```

## 10. Limitations and Honest Caveats

- **No streaming encryption.** Files are encrypted whole. Large files
  require proportional memory.
- **No forward secrecy.** Forward secrecy requires ephemeral key
  agreement where both parties contribute fresh randomness to a session
  key — a fundamentally protocol-level property (as in TLS, Signal, or
  MLS). CEF is a file format, not a protocol: the sender encrypts to
  the recipient's static public key. If that private key is later
  compromised, all containers ever encrypted to it are recoverable.
  This is the same limitation as PGP, S/MIME, age, and every other
  encrypt-at-rest format. ML-KEM encapsulation does generate an
  ephemeral ciphertext per container, but the recipient's decapsulation
  key is static — the ephemerality is one-sided and does not provide
  forward secrecy. Key rotation via `logical_key_id` and `version_id`
  limits the blast radius: if old keys are destroyed after rotation,
  containers encrypted to those keys become unrecoverable. However, the
  sender cannot enforce that the recipient actually destroys old keys.
- **CEK in memory.** The CEK exists in application memory during
  encrypt/decrypt. In garbage-collected languages (Go, JavaScript),
  zeroization is best-effort. The runtime may retain copies.
- **Backend trust.** The backend can unwrap any CEK it manages. A
  compromised backend can decrypt any container whose recipients it
  serves. This is inherent in any centralized key management model.
  Smart card backends avoid this by keeping keys on the card.
- **No anti-replay.** The format has no built-in replay protection.
- **COSE recipient key IDs are visible.** The `kid` in each
  COSE_recipient's unprotected header is not encrypted. This reveals
  how many recipients exist and their key identifiers (but not their
  names or emails, which are in the encrypted manifest).
- **PQ algorithms are not FIPS-certified in all SDKs.** The Go SDK
  uses CIRCL (production-grade). The TypeScript SDK uses
  @noble/post-quantum (audited, not FIPS-certified). The spec notes
  ML-KEM COSE algorithm IDs are in the private-use range pending IANA
  assignment.
