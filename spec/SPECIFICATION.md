# CEF: COSE Encrypted Files: Format Specification

**Version**: 0
**Status**: Draft
**Date**: March 2026
**Author**: Peculiar Ventures

## 1. Introduction

This document specifies the CEF (COSE Encrypted Files) format (.cef), a
modern encrypted archive and exchange format for securely packaging and
transferring files with protected metadata, multiple recipients, and strong
cryptographic guarantees for confidentiality, integrity, and authenticity.

CEF is designed to work with a variety of key management approaches, from
user-managed keys and hardware-backed credentials to enterprise-mediated
systems. Key operations (wrap, unwrap, sign, verify) are delegated to the
active backend via callback functions; the container format itself is
independent of any specific key management service or protocol.

The format uses COSE (CBOR Object Signing and Encryption, RFC 9052/9053) for
cryptographic structures and CBOR (RFC 8949) for metadata encoding, packaged
in a standard ZIP archive.

### 1.1 Design Goals

- **Data-centric security**: Protection travels with the data.
- **Backend neutrality**: The container format is independent of the key
  management backend. Smart cards, cloud KMS, HSMs, and enterprise key
  services all use the same container structure.
- **Metadata privacy**: The manifest is encrypted alongside file payloads.
  Without a valid recipient key, file names, recipient identities, and
  content metadata are not observable. The ZIP archive structure still
  reveals the number of encrypted entries and their approximate ciphertext
  sizes.
- **Multi-recipient**: A single container can be decrypted by any authorized
  recipient, with recipient resolution defined by the active backend or
  profile.
- **Authenticated encryption**: AES-256-GCM provides confidentiality and
  integrity in a single operation.
- **Compact metadata**: CBOR encoding minimizes manifest overhead.
- **Post-quantum readiness**: COSE algorithm identifiers support PQ
  algorithms (ML-KEM-768, ML-DSA-65) without format changes.
- **Progressive access control**: The format provides a substrate for
  increasingly sophisticated access control models without changing the
  container identity. The progression is:

  1. **Direct key recipients**. The simplest model. A recipient is
     identified by key ID. The key material is managed by the user
     (smart card, local keystore).
  2. **Profile-mediated resolution**. The backend resolves recipients
     by email, group membership, or organizational role. Policy
     enforcement happens at wrap/unwrap time in the key service.
  3. **Temporal enforcement**. Backends that support key versioning
     (via `version_id`) can enforce forward and backward temporal
     access control: a recipient can be granted access to future
     versions only, or access can be revoked for new content while
     preserving access to previously received containers.
  4. **Attribute-based policy**. Backends that evaluate attribute
     policies at wrap/unwrap time (via `policy_ref`) can enforce
     classification hierarchies, quorum requirements, and
     multi-party authorization without changing the container format.

  Each level builds on the previous. The container format remains the
  same at every level. Only the backend's resolution and enforcement
  logic changes.

### 1.2 Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

CBOR structures use the CDDL notation from RFC 8610.

### 1.3 Relationship to Existing Formats

CEF is built on top of established IETF standards. This section explains
the relationship to those standards and why a new container format is
needed rather than extending an existing one.

**COSE (RFC 9052/9053)**. CEF uses COSE as its cryptographic layer.
Every encrypted file and the manifest are standard COSE_Encrypt
structures. The detached signature is a standard COSE_Sign1. CEF does
not modify or extend the COSE wire format. The relationship is
analogous to how S/MIME uses CMS: COSE is the cryptographic message
format; CEF is the packaging and metadata layer above it.

**CMS (RFC 5652) / S/MIME (RFC 8551)**. CMS provides authenticated
encryption and digital signatures using ASN.1/DER encoding. CEF uses
COSE/CBOR instead of CMS/ASN.1 for several reasons: (1) CBOR is more
compact than DER for structured metadata, (2) COSE has native
algorithm agility including post-quantum algorithm identifiers, and
(3) CBOR tooling is simpler to implement correctly than ASN.1. CEF
does not attempt to replace CMS for email or document signing — it
addresses multi-file container exchange, which CMS does not natively
support without an outer packaging layer.

**ASiC (ETSI EN 319 162)**. The Associated Signature Container format
is the closest existing standard to CEF. Both use ZIP archives with a
META-INF directory containing signatures and metadata. CEF differs
from ASiC in three fundamental ways: (1) the manifest is encrypted,
so file names and metadata are confidential; (2) file names within
the ZIP are randomized, preventing metadata leakage from the archive
directory; and (3) COSE/CBOR replaces CMS/XML, enabling post-quantum
algorithms without format changes. ASiC is a signature container; CEF
is an encryption-first container with signatures.

**PGP/OpenPGP (RFC 9580)**. OpenPGP provides encryption and signing
for messages and files. CEF differs in that it separates key
management from the container format. OpenPGP bundles key discovery,
trust management (Web of Trust), and encrypted content into a single
system. CEF delegates key operations to callbacks, making it
compatible with any key management backend (cloud KMS, HSM, smart
cards, enterprise directories) without format changes. Additionally,
CEF uses COSE structures, which have cleaner algorithm agility for
post-quantum migration than OpenPGP's packet-based approach.

**JOSE (RFC 7516/7515) / JWE+JWS**. JOSE provides encryption (JWE)
and signing (JWS) for single messages using JSON encoding. CEF
addresses multi-file containers with an encrypted manifest, which
JOSE does not natively support. JOSE's JSON encoding is also
significantly less compact than CBOR for binary metadata (file hashes,
certificate chains). CEF uses the same identity conventions as JOSE
(kid, x5c) for compatibility with existing key management
infrastructure.

**Why a new format?** No existing standard combines all of the
following properties: (1) encrypted manifest protecting file metadata,
(2) per-file encryption with per-recipient key wrapping, (3) support
for post-quantum algorithms via COSE, (4) backend-neutral key
management via callbacks, and (5) compact CBOR metadata encoding.
CEF assembles these properties from existing IETF building blocks
(COSE, CBOR, ZIP, RFC 3161) rather than inventing new cryptographic
primitives.

## 2. Container Structure

A .cef file is a ZIP archive (PKZIP 2.0 or later) containing the following
entries:

```
container.cef (ZIP)
├── META-INF/manifest.cbor.cose      REQUIRED
├── META-INF/manifest.cose-sign1     RECOMMENDED
├── META-INF/manifest.tst            OPTIONAL
└── encrypted/<n>.cose            one per encrypted file
```

### 2.1 Entry: META-INF/manifest.cbor.cose

A COSE_Encrypt structure (CBOR tag 96) containing the encrypted manifest.
The plaintext is a CBOR-encoded Manifest object (§3).

This entry MUST be present.

### 2.2 Entry: META-INF/manifest.cose-sign1

A COSE_Sign1 structure (CBOR tag 18) containing a detached signature over
the encrypted manifest bytes (the raw content of manifest.cbor.cose).

This entry SHOULD be present. If absent, the container is unsigned and
recipient software SHOULD warn the user.

### 2.3 Entry: META-INF/manifest.tst

An optional RFC 3161 timestamp token (TimeStampResp or TimeStampToken,
DER-encoded) over the COSE_Sign1 signature bytes. The timestamp proves
that the signature existed at a specific point in time, which is
required in some regulated environments (eIDAS, legal document exchange).

If present, implementations SHOULD verify the timestamp against a
trusted TSA certificate. If absent, no temporal proof is available
but the container is otherwise valid.

### 2.4 Entry: encrypted/<name>.cose

Each encrypted file is stored as a COSE_Encrypt structure. The `<name>` is
a random hex string (32 characters recommended) with a `.cose` extension.
The mapping from obfuscated names to original filenames is in the manifest.

Implementations MUST ignore unrecognized ZIP entries.

## 3. Manifest

The manifest is a CBOR map with the following structure:

```cddl
Manifest = {
    version:    tstr,           ; "0"
    files:      { + tstr => FileMetadata },
    sender:     SenderInfo,
    recipients: [ * RecipientRef ]
}

FileMetadata = {
    original_name:   tstr,        ; Original filename (basename only)
    hash:            bstr,        ; Hash of plaintext content
    hash_algorithm:  int,         ; COSE algorithm ID (RFC 9053 §2.1)
    size:            uint,        ; Original file size in bytes
    ? content_type:  tstr         ; MIME type
}

SenderInfo = {
    kid:       tstr,              ; Key identifier (required, verified via signature)
    ? x5c:     [+ bstr],          ; X.509 certificate chain (optional, verified identity)
    ? claims: {                   ; Unverified hints (optional, for UI display only)
        ? email:          tstr,
        ? name:           tstr,
        ? created_at:     tdate,  ; Sender-asserted creation time (RFC 3339)
        ? classification: tstr,   ; e.g. "TOP SECRET", "SECRET"
        ? sci_controls:  [* tstr], ; SCI codewords
        ? sap_programs:  [* tstr], ; SAP identifiers
        ? dissemination: [* tstr], ; e.g. "NOFORN", "ORCON"
        ? releasability:  tstr    ; e.g. "REL TO USA, FVEY"
    }
}

RecipientRef = {
    kid:       tstr,              ; Key identifier (required)
    ? type:    tstr,              ; "key" | "email" | "certificate" | "group"
    ? x5c:    [+ bstr],           ; X.509 certificate chain (optional)
    ? claims: {                   ; Unverified hints (optional)
        ? email:    tstr,
        ? name:     tstr,
        ? group_id: tstr
    }

    ; Extension fields (optional). These enable future key management
    ; capabilities without requiring a format version change.
    ? logical_key_id: tstr,       ; Stable named key (e.g., "case-123")
    ? version_id:     tstr,       ; Key material version (e.g., "v3")
    ? policy_ref:     tstr,       ; Policy or attribute reference
}
```

### 3.1 Version

The `version` field MUST be "0" for this specification. Implementations
SHOULD reject manifests with unrecognized major versions.

### 3.2 Extension Fields

The `RecipientRef` structure includes optional extension fields
(`logical_key_id`, `version_id`, `policy_ref`) that are reserved for
future key management capabilities such as logical named keys, key
material versioning, and policy-based access control.

Implementations MUST observe the following rules:

- **Writers** MAY emit any combination of extension fields. Extension
  fields that are not populated MUST be omitted (not set to empty strings).
- **Readers** MUST ignore extension fields they do not understand. An
  unrecognized field MUST NOT cause the implementation to reject the
  manifest.
- **Round-trip preservation**: Implementations that read and re-write a
  manifest (e.g., during re-encryption) MUST preserve all extension
  fields, including fields they do not understand. Unknown fields MUST
  NOT be silently dropped.
- **Interoperability**: The presence or absence of extension fields MUST
  NOT affect whether a container can be decrypted. Extension fields are
  advisory metadata for the key management service and do not alter
  the cryptographic operations.

The same rules apply to any future fields added to the manifest or
recipient structures. The CBOR map encoding permits additive extension
without breaking existing parsers.

### 3.3 File Hashes

The `hash` field contains the digest of the original plaintext file.
The `hash_algorithm` field identifies the algorithm as an integer from
the IANA COSE Algorithms registry (RFC 9053 §2.1). The value **-16**
denotes SHA-256. Implementations MUST support SHA-256 (-16).
Implementations MAY support additional algorithms (e.g., SHA-384 = -43,
SHA-512 = -44). Implementations MUST verify the hash after decryption
using constant-time comparison to prevent timing side-channels, and
SHOULD report hash mismatches to the user.

The `created_at` claim is a sender-asserted RFC 3339 timestamp indicating
when the container was created. Like all claims, this value is NOT
cryptographically verified — it is set by the sender's clock and MUST
NOT be trusted for access control or audit purposes. For verified proof
of time, use the RFC 3161 timestamp token (stored as
`META-INF/manifest.tst`), which is signed by a trusted Time Stamp
Authority.

The `classification` claim is a sender-asserted classification label
(e.g., "TOP SECRET", "SECRET", "CONFIDENTIAL"). The related claims
`sci_controls`, `sap_programs`, `dissemination`, and `releasability`
carry additional handling marks following IC/DoD marking conventions.

These claims are analogous to markings on an envelope — they tell the
recipient (human or automated) how the sender intends the contents to
be handled. Like all claims, these values are unverified. The format
carries them; the format does not enforce them.

Security enforcement happens at the key management layer: when the
sender's backend receives an encrypt request with claimed markings, it
checks whether the sender's key is authorized to assert that
classification and whether each recipient key is cleared for those
markings. When a decrypt request arrives, the backend checks whether
the requesting key is policy-authorized for the container's claimed
markings. A Cross-Domain Solution operating as a recipient can read
these claims from the decrypted manifest and apply its transfer rules.

Implementations MUST NOT treat handling marks as authoritative without
independent verification against the sender's identity and the
backend's own policy rules.

### 3.4 Original Filenames

The `original_name` field contains only the filename (no directory path).
Implementations MUST use `filepath.Base()` or equivalent to prevent path
traversal attacks. Filenames containing path separators, "..", or other
dangerous patterns SHOULD be sanitized or rejected.

### 3.5 Truncation Detection

After decrypting the manifest, implementations MUST verify that every
file entry in the manifest has a corresponding encrypted file in the ZIP
container. If any file listed in the manifest is absent from the
container, the implementation MUST reject the container with an error
indicating possible truncation. This prevents an attacker from stripping
files from a container while leaving the manifest and signature intact.

## 4. Cryptographic Structures

### 4.1 Content Encryption (COSE_Encrypt)

Each encrypted payload (manifest and files) is a COSE_Encrypt message:

```cddl
COSE_Encrypt_Tagged = #6.96(COSE_Encrypt)

COSE_Encrypt = [
    protected:   bstr .cbor { 1: 3 },       ; alg: A256GCM
    unprotected: { 5: bstr .size 12 },      ; iv: 12-byte nonce
    ciphertext:  bstr,                       ; AES-256-GCM ciphertext
    recipients:  [ + COSE_recipient ]
]
```

**Protected header**: MUST contain algorithm identifier 3 (A256GCM). AES-256 provides approximately 128-bit security against quantum adversaries (Grover's algorithm).

**Unprotected header**: MUST contain a 12-byte IV (header label 5).
The IV MUST be generated using a cryptographically secure random number
generator. IV reuse with the same key is a catastrophic failure.

**Ciphertext**: AES-256-GCM authenticated ciphertext. The Additional
Authenticated Data (AAD) is the Enc_structure per RFC 9052 §5.3:

```cddl
Enc_structure = [
    context:      "Encrypt",
    protected:    bstr,         ; serialized protected header
    external_aad: bstr          ; empty if not provided
]
```

### 4.2 Key Encapsulation (COSE_recipient)

Each recipient in the COSE_Encrypt message has a COSE_recipient structure:

```cddl
COSE_recipient = [
    protected:   bstr .cbor { 1: alg_id },    ; see algorithm table below
    unprotected: {
        4: bstr,                             ; kid: key ID
        ? -70001: tstr,                      ; GK recipient type
    },
    ciphertext:  bstr                        ; encapsulated/wrapped CEK
]
```

**Algorithm**: The protected header MUST contain one of the following:

| Value | Name | Description | Default |
|-------|------|-------------|---------|
| -70010 | ML-KEM-768+A256KW | ML-KEM-768 KEM + AES-256 Key Wrap | YES |
| -70011 | ML-KEM-1024+A256KW | ML-KEM-1024 KEM + AES-256 Key Wrap | |
| -5 | A256KW | AES-256 Key Wrap (classical fallback) | |
| -31 | ECDH-ES+A256KW | ECDH-ES + AES-256 Key Wrap (classical) | |

Implementations MUST support ML-KEM-768+A256KW (-70010) and A256KW (-5).
New containers SHOULD use ML-KEM-768+A256KW by default for post-quantum
security. A256KW SHOULD be used as a fallback when the recipient's key
does not support ML-KEM.

Note: The ML-KEM+A256KW algorithm identifiers are provisional, pending
final assignment from draft-ietf-jose-pqc-kem. Implementations MUST be
prepared to update these values when IANA assigns permanent identifiers.

**ML-KEM key encapsulation flow**: For ML-KEM recipients, the ciphertext
field contains `ct || wrappedCEK` where:

1. `ct` is the ML-KEM ciphertext (1088 bytes for ML-KEM-768).
2. The shared secret `ss` from ML-KEM encapsulation is used to derive a
   32-byte KEK using HKDF-SHA256 (RFC 5869):
   - IKM: `ss` (ML-KEM shared secret, 32 bytes)
   - salt: empty (zero-length byte string)
   - info: `"CEF-ML-KEM-768-A256KW"` (domain separation label)
   - L: 32 bytes

   The domain label binds the derivation to this protocol and algorithm
   pair, preventing cross-protocol key reuse.
3. The CEK is wrapped with AES-256 Key Wrap using the derived KEK.
4. `wrappedCEK` is the 40-byte AES Key Wrap output (32-byte CEK + 8-byte ICV).
5. The shared secret `ss` and derived KEK MUST be zeroized after use.

The total ciphertext for ML-KEM-768+A256KW is 1128 bytes (1088 + 40).

**Key sizes for validation**: Implementations MUST validate key sizes on
input. The following sizes are normative for the supported algorithms:

| Key Type | Bytes | Description |
|----------|-------|-------------|
| ML-KEM-768 encapsulation (public) key | 1184 | Standard encoding per FIPS 203 |
| ML-KEM-768 ciphertext | 1088 | Per FIPS 203 §7.2 |
| ML-KEM-768 shared secret | 32 | Per FIPS 203 §7.2 |
| ML-DSA-65 verifying (public) key | 1952 | Standard encoding per FIPS 204 |
| ML-DSA-65 signature | 3309 | Per FIPS 204 §7.2 |

Private (decapsulation/signing) key serialization is out of scope. The
format specifies only the public key and ciphertext sizes that appear in
or are derived from the container. Private key encoding is an
implementation and backend concern — different libraries use different
internal representations (seeds, expanded keys) for the same algorithm.

**Classical key wrap flow**: For A256KW recipients, the ciphertext field
contains the 40-byte AES Key Wrap output directly.

**Key ID (label 4)**: A byte string containing the key identifier.
This identifies the key used for encapsulation/wrapping and is used by the
recipient to select the correct decapsulation/unwrap operation. The COSE
Key ID is the UTF-8 encoding of the manifest `kid` text string.
Implementations MUST encode the `kid` as UTF-8 bytes in the COSE
unprotected header and as a text string in the manifest. When matching
a recipient, implementations MUST compare the COSE `kid` bytes against
the UTF-8 encoding of the manifest `kid` string.

**Mixed recipients**: A single COSE_Encrypt message MAY contain recipients
with different algorithms. This allows a container to have both ML-KEM-768
and A256KW recipients simultaneously, enabling gradual PQ migration.

### 4.3 CEF Private Headers

The following private header labels are in the -70000 range (per RFC 9052
§3.1, private-use labels are defined in RFC 9052 §3.1):

| Label | Name | Type | Description |
|-------|------|------|-------------|
| -70001 | GK Recipient Type | tstr | "key", "email", "certificate", or "group" |

These headers are OPTIONAL and are used by the key management service for
recipient resolution. Third-party implementations MAY ignore them.

### 4.4 Signing (COSE_Sign1)

The manifest signature is a COSE_Sign1 structure with a detached payload:

```cddl
COSE_Sign1_Tagged = #6.18(COSE_Sign1)

COSE_Sign1 = [
    protected:   bstr .cbor { 1: alg_id },    ; see algorithm table below
    unprotected: { 4: bstr },               ; kid: signer key ID
    payload:     nil,                        ; detached (MUST be CBOR null)
    signature:   bstr                        ; signature bytes
]
```

The detached payload MUST be encoded as CBOR null (major type 7, value
22), NOT as an empty byte string (h''). Implementations that encode the
detached payload as empty bytes will produce containers that fail
signature verification in other implementations. This was identified as
a real interop bug between the Go and TypeScript SDKs.

The signature is computed over the Sig_structure1 (RFC 9052 §4.4):

```cddl
Sig_structure1 = [
    context:        "Signature1",
    body_protected: bstr,                    ; serialized protected header
    external_aad:   bstr,                    ; empty
    payload:        bstr                     ; encrypted manifest bytes
]
```

The payload for the Sig_structure is the **encrypted manifest bytes**
(the raw COSE_Encrypt CBOR), not the plaintext manifest. This allows
signature verification without decryption.

**Algorithms**:

| Value | Name | Description | Default |
|-------|------|-------------|---------|
| -49 | ML-DSA-65 | FIPS 204, ~192-bit PQ security | YES |
| -48 | ML-DSA-44 | FIPS 204, ~128-bit PQ security | |
| -50 | ML-DSA-87 | FIPS 204, ~256-bit PQ security | |
| -7 | ES256 | ECDSA P-256 (classical fallback) | |
| -35 | ES384 | ECDSA P-384 (classical) | |
| -8 | EdDSA | Ed25519/Ed448 (classical) | |

Implementations MUST support ML-DSA-65 (-49) and ES256 (-7).
New containers SHOULD use ML-DSA-65 by default for post-quantum security.
ES256 SHOULD be used when the signer's key does not support ML-DSA.

Note: The ML-DSA algorithm identifiers (-48, -49, -50) were early-allocated
by IANA on 2025-04-24 as TEMPORARY registrations per RFC 7120, referencing
draft-ietf-cose-dilithium-06. The temporary registrations expire 2026-04-24
and will become permanent when the draft is published as an RFC.

## 5. Key Management Protocol

Key operations (wrap, unwrap, sign, verify) are delegated to an external key management service. The container format
is independent of the key management protocol, but the typical flow is:

### 5.1 Encryption

1. Generate a random 32-byte CEK.
2. Generate a random 12-byte IV.
3. Encrypt the plaintext with AES-256-GCM using the CEK and IV.
4. For each recipient, wrap the CEK:
   - When recipient key material is available locally (e.g., ML-KEM
     public key), the CEK MAY be wrapped entirely on the client.
   - When using a key management service, the CEK MAY be provided
     to the service for wrapping, depending on the trust model and
     deployment architecture.
5. Build the COSE_Encrypt structure.
6. Build the COSE_Sign1 detached signature.
7. Package into a ZIP container.

### 5.2 Decryption

1. Read the ZIP container.
2. Optionally verify the COSE_Sign1 signature.
3. Parse the encrypted manifest (COSE_Encrypt).
4. Find the recipient matching the user's key ID. If multiple
   recipients match the same kid, the implementation SHOULD attempt
   each until one succeeds.
5. Unwrap the CEK:
   - When the recipient's secret key is available locally (e.g.,
     ML-KEM secret key), unwrapping MAY be performed on the client.
   - When using a key management service, the wrapped CEK MAY be
     sent to the service for unwrapping.
6. Decrypt the manifest with AES-256-GCM.
7. For each file, repeat steps 3-6.
8. Verify file hashes against manifest (see §3).

### 5.3 Key Hierarchy

The key management service manages key ownership at multiple levels:

| Level | Description | Use Case |
|-------|-------------|----------|
| User | Individual user keys | Direct recipient |
| Group | Shared team/role keys | Team-based access |
| Organization | Org-wide keys | Org-level encryption |

All key types use the same COSE_recipient structure. The recipient type
header (-70001) indicates the resolution method but does not affect the
cryptographic operations.

### 5.4 Profiles and Resolution Semantics

The CEF core format defines how recipients are referenced in the COSE
structure (by `kid` in the unprotected header) and how content is
encrypted and signed. It does not define how recipient references are
resolved to actual key material. That is the responsibility of the
key management service, and different services may resolve recipients
differently.

The following concepts are intentionally profile-specific:

- **Recipient resolution**: How a `kid` is obtained from a recipient's
  identity (email, certificate, directory lookup) depends on the key
  management service. The `claims` block may carry hints (email, name)
  to help the service resolve the recipient, but these claims are
  unverified and MUST NOT be trusted for access control.

- **`group` resolution**: A `claims.group_id` refers to a shared key
  managed by the service. The semantics of group membership, key
  rotation, and temporal access control are determined by the service,
  not by the format.

- **Recipient provisioning**: Whether recipients must be pre-enrolled,
  can be auto-provisioned, or must be resolved from a directory is
  service-specific.

The core format requirement is only this: every COSE_recipient MUST
have a `kid` (COSE header label 4) that identifies the key material.
How the `kid` is obtained is outside the scope of the format specification.

Implementations that support only direct key ID recipients (type `"key"`)
are fully conforming. The `"email"`, `"certificate"`, and `"group"` types
are defined for services that provide those resolution capabilities.

### 5.5 Identity Model

CEF follows the IETF convention of separating key identifiers from
identity claims. This is the same approach used by JOSE (RFC 7515),
COSE (RFC 9052), and CMS (RFC 5652):

- **`kid`**: Key identifier. Required. This is the cryptographic
  identity used for signature verification and key unwrapping. It is
  the only field the format trusts.

- **`x5c`**: X.509 certificate chain. Optional. When present, it
  provides a verified identity binding (the certificate's subject is
  bound to the key by a CA). Recipients SHOULD validate the chain
  against their trust store.

- **`claims`**: Unverified hints. Optional. Contains self-asserted
  metadata like email addresses and display names. These are for UI
  display only and MUST NOT be used for access control decisions.
  Implementations SHOULD clearly label these as unverified when
  displaying them to users.

When `x5c` is present, `claims` SHOULD NOT be included. The
certificate's subject and Subject Alternative Name (SAN) fields
provide verified identity information that supersedes any
self-asserted claims. Including both creates ambiguity: if the
certificate says `CN=Alice` but claims says `name: "Bob"`, which
should the recipient trust? The answer is always the certificate.
Implementations that encounter both `x5c` and `claims` MUST use
the identity from the certificate and ignore the claims.

This separation ensures that the manifest structure cannot mislead
a recipient about the sender's identity. A sender can claim any email
address in the `claims` block, but the signature is verified against
the `kid`, and if an `x5c` chain is present, the identity is
established by the certificate, not by the claim.

This design supports both self-managed keys and directory-resolved
credentials without adding certificate-specific semantics to the core
format. Backends that resolve recipients via certificates (e.g.,
PIV/CAC cards, LDAP directories, or certificate transparency logs)
define their own mapping from `kid` to certificate and public key
material.

### 5.6 Access Control Progression

CEF was designed as a substrate for progressively richer access control
models without requiring changes to the core container format. The format
provides building blocks at each level of the progression:

**Level 1: Direct recipient keys.** The simplest model. Each recipient
is identified by a key ID, and the backend resolves that to key material.
Smart cards, local keystores, and cloud KMS all operate at this level.
No service infrastructure required.

**Level 2: Profile-mediated policy enforcement.** The key management
service evaluates access policy at wrap/unwrap time. The container
carries optional metadata that the service can use for policy decisions:
`logical_key_id` for stable named keys, `version_id` for key material
versioning, and `policy_ref` for referencing external policy documents
or attribute sets. The format does not interpret these fields. The
service does.

**Level 3: Attribute-based access control.** Services that support
ABAC can evaluate attribute hierarchies (e.g., clearance levels where
higher levels satisfy lower ones) and independent labels (region,
program, team membership) during wrap/unwrap. The `policy_ref` field
provides the binding between the container and the policy definition.
Quorum approval can be layered on top of attribute satisfaction.

CEF does not require a specific policy language at the core format
layer. Profiles and backends may use a structured policy language to
govern recipient resolution, unwrap authorization, temporal access
rules, and other policy-driven behavior. Current GoodKey-oriented
profiles use Cedar as the policy expression language. In those
profiles, Cedar concepts map naturally onto GoodKey primitives:
principals may represent users, devices, services, or groups;
resources may represent logical keys, wrapped objects, containers,
or versioned key series; actions may include wrap, unwrap,
decrypt, rekey, approve, or delegate; and context may include time,
network, quorum state, environment, region, or device posture. This
allows the core container format to remain stable and interoperable
while enabling richer policy evaluation and enforcement through
profile-specific implementations.

Each level is a superset of the previous one. A container created at
Level 1 can be consumed by a Level 3 service without modification.
the service simply evaluates more policy during unwrap. Conversely, a
container created with Level 3 metadata can be consumed by a Level 1
implementation that ignores the extension fields (per §3.2).

### 5.7 Temporal Enforcement

Profiles that support key versioning (via `version_id`) can implement
temporal access control without changes to the container format:

**Forward enforcement**: A new key version is created after a date.
Containers encrypted to the new version cannot be decrypted by holders
of the old version. This enforces "access starts after" semantics.

**Backward enforcement**: An old key version is revoked or retired.
The service refuses to unwrap CEKs bound to the retired version. This
enforces "access ends after" semantics.

**Rotation**: The service resolves `logical_key_id` to the current
`version_id` at encryption time, binding the container to a specific
key generation. Future policy changes take effect at the service layer
without re-encrypting the container.

These are service-layer capabilities enabled by the format's extension
fields. Implementations that do not support key versioning ignore
`version_id` and operate without temporal constraints.

## 6. Security Considerations

### 6.1 Key Material

The CEK is generated by the SDK and exists in application memory during
encryption. After wrapping for all recipients, the SDK SHOULD zeroize the
CEK. In garbage-collected languages, zeroization is best-effort.

The key service never receives the plaintext content, only the CEK for
wrap/unwrap operations.

### 6.2 IV Uniqueness

AES-GCM security depends on IV uniqueness per key. Since each encryption
operation generates a fresh random CEK, IV collision between different
CEKs is not a security concern. However, implementations MUST use a
cryptographically secure random number generator for IV generation.

### 6.3 Authenticated Encryption

AES-256-GCM provides both confidentiality and integrity. The COSE
Enc_structure binds the protected header to the ciphertext via the AAD.
Tampering with the protected header, IV, or ciphertext will cause
decryption to fail.

### 6.4 Signature Scope

The COSE_Sign1 signature covers the **encrypted** manifest, not the
plaintext. This means:

- Signature can be verified without decryption (useful for gateways).
- The signature does not prove the signer knew the plaintext content.
- Replacing the encrypted manifest invalidates the signature.

The signature, combined with verification of file hashes in the
manifest, provides integrity protection for the decrypted file
contents. The chain is: signature → encrypted manifest → decrypted
manifest (which contains per-file SHA-256 hashes) → file content.
An attacker cannot modify file content without either breaking the
AES-256-GCM authentication or invalidating the manifest hash.

### 6.5 AES Key Wrap Integrity

AES Key Wrap (RFC 3394) includes an integrity check value (ICV).
Implementations MUST verify the ICV using constant-time comparison to
prevent timing side-channels.

### 6.6 Recipient Privacy

The manifest is encrypted, so the list of recipients is not visible to
unauthorized parties. The COSE_recipient structures in the encrypted
manifest and file payloads contain key IDs in unprotected headers.
Key identifiers may enable correlation across containers if the same
key is reused. For maximum recipient privacy, backends SHOULD use
ephemeral or per-container key identifiers.

### 6.7 Path Traversal

The `original_name` field in file metadata could contain path traversal
sequences. Implementations MUST sanitize filenames during extraction to
prevent writing outside the intended output directory.

### 6.8 Container Integrity (ZIP)

The ZIP archive is not itself authenticated — the cryptographic
integrity comes from COSE_Encrypt (AES-256-GCM) and COSE_Sign1.
However, implementations MUST defend against malformed ZIP input:

- MUST reject duplicate entry names within the archive.
- MUST validate that the central directory is consistent with local
  file headers.
- SHOULD enforce size limits to prevent decompression bombs (zip bombs).
  A reasonable default is 1 GB per file and 10 GB total.
- MUST ignore extra fields in ZIP entries unless specifically understood.
- MUST NOT process entries outside the expected paths (`META-INF/*`
  and `encrypted/*`).

### 6.9 Hash Algorithm Downgrade

Implementations MUST NOT accept hash algorithms weaker than SHA-256.
The `hash_algorithm` field in FileMetadata uses COSE algorithm
identifiers. If future algorithms are added, implementations MUST
reject any algorithm with a security level below 128 bits.

### 6.10 Deterministic CBOR

Writers MUST use deterministic CBOR encoding (RFC 8949 §4.2.1) for
the manifest. Deterministic encoding ensures that:

- Signatures are reproducible across implementations.
- Test vectors can be validated byte-for-byte.
- Content-addressing schemes (if used) produce consistent hashes.

Deterministic encoding requires minimum-width integer encoding: integers
MUST be encoded in the smallest CBOR integer representation that can hold
the value. Algorithm identifiers (e.g., 3, -49, -70010) and file sizes
MUST use the minimum number of bytes. Implementations SHOULD NOT encode
integers wider than i64 in the manifest; all defined fields fit within
the i64 range.

### 6.11 Manifest and File Recipient Sets

Implementations MUST NOT assume that the recipient sets in the
manifest COSE_Encrypt and individual file COSE_Encrypt structures
are identical. A container MAY have different recipient sets for
different files, though the current specification uses a single
recipient set for all entries.

## 7. IANA Considerations

### 7.1 Media Type Registration

This specification defines the following media type for CEF containers:

    Type name: application
    Subtype name: cef
    Required parameters: none
    Optional parameters: none
    Encoding considerations: binary
    Security considerations: See Section 6
    Interoperability considerations: See Section 10
    Published specification: This document
    Applications that use this media type: File exchange applications
      requiring post-quantum encryption with metadata privacy
    File extension: .cef
    Macintosh file type code: none
    Person & email address to contact for further information:
      Ryan Hurst <ryan@peculiarventures.com>

The file extension `.cef` SHOULD be used for CEF container files.
Implementations SHOULD register the `application/cef` media type
with the operating system for file association.

### 7.2 Registered Algorithms (IANA COSE Algorithms Registry)

This specification uses the following COSE algorithm identifiers:

| Value | Name | Reference |
|-------|------|-----------|
| 3 | A256GCM | RFC 9053 §4.1 |
| -5 | A256KW | RFC 9053 §6.2 |
| -7 | ES256 | RFC 9053 §2.1 |
| -8 | EdDSA | RFC 9053 §2.2 |
| -31 | ECDH-ES+A256KW | RFC 9053 §6.1.3 |
| -35 | ES384 | RFC 9053 §2.1 |
| -42 | RSA-OAEP-256 | RFC 9053 §5 |
| -48 | ML-DSA-44 | draft-ietf-cose-dilithium |
| -49 | ML-DSA-65 | draft-ietf-cose-dilithium |
| -50 | ML-DSA-87 | draft-ietf-cose-dilithium |

### 7.3 Provisional Algorithms (Private-Use, Pending IANA Assignment)

| Value | Name | Reference | Status |
|-------|------|-----------|--------|
| -70010 | ML-KEM-768+A256KW | draft-ietf-jose-pqc-kem | Private-use, awaiting IANA |
| -70011 | ML-KEM-1024+A256KW | draft-ietf-jose-pqc-kem | Private-use, awaiting IANA |

These values are in the COSE private-use range (per
RFC 9052 §3.1) and are used until draft-ietf-jose-pqc-kem receives
IANA-assigned algorithm identifiers. When permanent values are assigned,
implementations MUST migrate to the IANA-assigned values. During the
transition, implementations SHOULD accept both the private-use and
IANA-assigned values.

**Open item**: Track draft-ietf-jose-pqc-kem for IANA early allocation
of ML-KEM-768+A256KW and ML-KEM-1024+A256KW algorithm identifiers.
Update `AlgMLKEM768_A256KW` and `AlgMLKEM1024_A256KW` constants in
`pkg/cose/cose.go` when assigned.

The private header label -70001 is in the private-use
range per RFC 9052 §3.1 and does not require IANA registration.

## 8. Versioning

### 8.1 Format Version

The manifest `version` field identifies the format version. The current
version is `"0"`, indicating a draft specification.

Implementations MUST reject manifests with an unrecognized version.
When this specification is finalized, the version will advance to `"1"`.
Implementations SHOULD NOT attempt to process containers with a version
they do not recognize.

### 8.2 Algorithm Agility

The COSE algorithm identifier in the protected header determines the
cryptographic algorithms used. Implementations MUST support:

- Content encryption: algorithm 3 (A256GCM)
- Key encapsulation: algorithm -70010 (ML-KEM-768+A256KW) and -5 (A256KW)
- Signing: algorithm -49 (ML-DSA-65) and -7 (ES256)

Additional algorithms MAY be supported without a version change, as
COSE's algorithm negotiation is header-driven. The default algorithms
for new containers are ML-KEM-768+A256KW and ML-DSA-65. Classical
algorithms are used when interoperating with keys that do not support
post-quantum cryptography.

## 9. Error Handling

Implementations SHOULD distinguish between the following error categories:

| Category | Description | Example |
|----------|-------------|---------|
| FORMAT | Container structure error | Missing manifest, invalid ZIP |
| CBOR | CBOR decoding failure | Truncated data, wrong types |
| COSE | COSE structure invalid | Wrong tag, missing headers |
| CRYPTO | Cryptographic operation failure | GCM auth fail, key unwrap ICV fail |
| AUTH | Authentication/authorization | Key not found, operation denied |
| POLICY | Policy violation | Key usage mismatch, expired key |
| IO | File system error | Permission denied, disk full |

Implementations MUST NOT leak key material or plaintext in error messages.
Error messages SHOULD identify the failing component without revealing
cryptographic state.

## 10. Conformance

### 10.1 Container Writer

A conforming container writer MUST:

1. Generate a 32-byte CEK using a CSPRNG.
2. Generate a 12-byte IV using a CSPRNG.
3. Encrypt content with AES-256-GCM using the Enc_structure as AAD.
4. Wrap the CEK using AES-256 Key Wrap (RFC 3394) for each recipient.
5. Build a valid COSE_Encrypt (tag 96) with the required headers.
6. Encode the manifest as CBOR and encrypt it as a COSE_Encrypt.
7. Package the result as a ZIP archive with the required entry names.
8. Zeroize the CEK after wrapping for all recipients.

A conforming container writer SHOULD:

1. Produce a COSE_Sign1 detached signature over the encrypted manifest.
2. Use random 32-character hex strings for obfuscated filenames.
3. Include SHA-256 hashes of all plaintext files in the manifest.

### 10.2 Container Reader

A conforming container reader MUST:

1. Parse the ZIP archive and locate the required entries.
2. Parse the COSE_Encrypt structure and validate CBOR tag 96.
3. Identify the matching recipient by key ID.
4. Unwrap the CEK using AES-256 Key Unwrap (RFC 3394).
5. Use constant-time comparison for the Key Unwrap integrity check.
6. Verify the AES-GCM authentication tag during decryption.
7. Verify SHA-256 hashes of decrypted files against the manifest.
8. Sanitize filenames to prevent path traversal.
9. Zeroize the CEK after decryption.

A conforming container reader SHOULD:

1. Verify the COSE_Sign1 signature when present.
2. Reject containers with unrecognized major versions.
3. Ignore unrecognized ZIP entries and manifest fields.

### 10.3 Test Vectors

Conforming implementations MUST pass the following test vectors:

1. **RFC 3394 §4.1**: 128-bit KEK, 128-bit key data → known ciphertext.
2. **RFC 3394 §4.6**: 256-bit KEK, 256-bit key data → known ciphertext.
3. **COSE_Encrypt round-trip**: Encrypt with known CEK/IV/plaintext, marshal
   to CBOR, unmarshal, decrypt, verify plaintext matches.
4. **COSE_Sign1 round-trip**: Sign payload, marshal, unmarshal, verify.
5. **Container round-trip**: Create .cef with known content, read back,
   decrypt, verify file hashes and content.

Test vector hex values are available in the Go test suite
(`pkg/cose/cose_vectors_test.go`). Run with `-v` to print hex dumps:

```
go test -v -run TestVector ./pkg/cose/
```

## 11. References

- FIPS 197: Advanced Encryption Standard (AES)
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
- RFC 8610: Concise Data Definition Language (CDDL)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 9052: CBOR Object Signing and Encryption (COSE): Structures and Process
- RFC 9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms
- RFC 9360: COSE Header Parameters for X.509 Certificates
- draft-ietf-cose-dilithium: ML-DSA for JOSE and COSE
- draft-ietf-jose-pqc-kem: Post-Quantum KEMs for JOSE and COSE

## Appendix A: Example COSE_Encrypt (Post-Quantum Default)

```
96([                            / COSE_Encrypt /
    h'a10103',                  / protected: {1: 3} (A256GCM) /
    {5: h'000102030405060708090a0b'},  / unprotected: {iv} /
    h'...',                     / ciphertext /
    [                           / recipients /
        [                       / ML-KEM-768 recipient (PQ) /
            h'a1013a00011179',  / protected: {1: -70010} (ML-KEM-768+A256KW) /
            {                   / unprotected /
                4: h'6b65792d656e63727970742d6d6c6b656d373638',
                                / kid: "a1b2c3d4e5f60001" /
                -70001: "key"   / GK recipient type /
            },
            h'...'              / ct || wrappedCEK (1128 bytes) /
        ],
        [                       / Classical fallback recipient /
            h'a10124',          / protected: {1: -5} (A256KW) /
            {                   / unprotected /
                4: h'6b65792d656e63727970742d303031',
                                / kid: "f7e8d9c0b1a20002" /
                -70001: "key"   / GK recipient type /
            },
            h'...'              / wrappedCEK (40 bytes) /
        ]
    ]
])
```

This example shows a container with mixed PQ and classical recipients.
The ML-KEM-768 recipient's ciphertext is 1128 bytes (1088-byte ML-KEM
ciphertext + 40-byte AES-wrapped CEK). The classical recipient's
ciphertext is 40 bytes (AES-wrapped CEK only).

## Appendix B: Example COSE_Sign1 (Post-Quantum Default)

```
18([                            / COSE_Sign1 /
    h'a1013830',               / protected: {1: -49} (ML-DSA-65) /
    {                           / unprotected /
        4: h'6b65792d7369676e2d6d6c647361363035'
                                / kid: "0a1b2c3d4e5f0003" /
    },
    nil,                        / payload: detached /
    h'...'                      / ML-DSA-65 signature (3309 bytes) /
])
```

The payload for signature computation is the raw bytes of
`META-INF/manifest.cbor.cose`, allowing verification without decryption.

ML-DSA-65 signatures are 3309 bytes (compared to ~72 bytes for ES256).
This is a tradeoff for post-quantum security.

## Appendix C: ZIP Entry Summary

| Path | Content | Required |
|------|---------|----------|
| `META-INF/manifest.cbor.cose` | COSE_Encrypt (tag 96) containing CBOR manifest | REQUIRED |
| `META-INF/manifest.cose-sign1` | COSE_Sign1 (tag 18) detached signature | RECOMMENDED |
| `META-INF/manifest.tst` | RFC 3161 timestamp token (DER-encoded) | OPTIONAL |
| `encrypted/<random>.cose` | COSE_Encrypt (tag 96) containing file payload | One per file |
