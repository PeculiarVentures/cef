# Secure Data Encryption Formats: CEF and OpenTDF

## Policy Enforcement Models

Every data-centric encryption system must answer one question: how is access policy enforced? There are two fundamental approaches, and most real systems use one or both.

**Service-mediated enforcement.** A trusted key service evaluates policy at the time of a key operation. The service can grant or deny access based on current state: who the requester is, whether their clearance is still valid, whether they've been removed from a group. Revocation is immediate: update the policy, and the next request is denied. The cost is that the service must be reachable. No connectivity, no access.

**Key-intrinsic enforcement.** Policy is encoded into the key structure or ciphertext itself. Only a holder of the right key material can decrypt. No service needed at decryption time. Works offline, in disconnected environments, in contested networks. The cost is that revocation is harder: a person who already holds key material retains access to data encrypted under those keys. You can rotate keys to lock them out of future data, but you cannot retroactively revoke access to past data without re-encryption.

Neither approach alone is sufficient. Service-mediated enforcement excels at instant revocation. Key-intrinsic enforcement excels at offline resilience. The most secure architectures use both, deliberately, where each works best.

---

## Enforcement Model and Use of Policy Services

CEF does not require a policy service, but it can use one.

The CEF format defines how content is encrypted, packaged, and signed. It does not define how access decisions are made. Instead, access control is delegated to whatever key management backend is used to perform wrap and unwrap operations.

In deployments using a service such as GoodKey, that backend acts as a policy enforcement point (PEP). It evaluates policy at the time of key operations and decides whether to release or wrap the content encryption key. In this mode, CEF behaves as a service-mediated system: access depends on successful interaction with the backend, and revocation can be enforced immediately.

In deployments using local keys, smart cards, or other non-service-backed mechanisms, no policy service is involved. Access is determined solely by possession and use of the appropriate key material. In this mode, CEF behaves as a key-intrinsic system and supports offline decryption without any network dependency.

These two modes can coexist within the same ecosystem. Some recipients may rely on a backend service for policy evaluation, while others use hardware-backed or locally managed keys. The container format remains unchanged.

By contrast, OpenTDF is designed around a policy service as part of its decryption model. A Key Access Service (KAS) evaluates policy and participates in the key release process during decryption. Access decisions are therefore always mediated by a service, even when policy information is carried within the container.

This difference reflects a design choice. CEF separates the encrypted container from the enforcement mechanism, allowing both service-mediated and key-intrinsic models. OpenTDF integrates policy evaluation and key release into a single system centered on the KAS.

---

## CEF (GoodKey File Exchange)

**Enforcement model:** Primarily service-mediated. The GoodKey service evaluates policy at wrap/unwrap time. With centrally managed keys (cloud HSM, enclave, KMS), access control is evaluated on every operation and revocation is immediate. With smart card keys, enforcement shifts to physical possession, offline capable, but no centralized revocation.

GoodKey provides temporal enforcement through key versioning. Group keys rotate through versions. When a member joins, they receive the current version onward. When a member is removed, the key rotates and they never receive the new version. A member who joins at version 3 has no access to data encrypted under versions 1 and 2. GoodKey never issued those versions to them. A member removed before version 3 retains versions 1 and 2 from before their removal but is locked out of version 3 onward.

**Format:** ZIP archive with COSE_Encrypt (RFC 9052) encrypted payloads, COSE_Sign1 detached signature, and an encrypted CBOR manifest. Multiple files per container. All metadata (file list, recipients, sender) is encrypted.

**Cryptography:** Post-quantum by default. ML-KEM-768 (FIPS 203) for key encapsulation, ML-DSA-65 (FIPS 204) for signing, AES-256-GCM for content. Classical fallback available. Mixed PQ and classical recipients in the same container.

**Key management:** GoodKey supports multiple key providers per key: smart cards (PKCS#11, PIV), AWS Nitro Enclaves (with remote attestation and published PCR hashes), cloud HSM, cloud KMS, software keystores. Quorum approval (N-of-M) for key operations. ABAC (attribute-based access control) evaluated at the service layer is planned, enabling attribute-based policy decisions at wrap/unwrap time without requiring changes to the container format.

In GoodKey's planned ABAC model, policy is evaluated at the service layer during wrap/unwrap operations. Policies may combine hierarchical attributes, such as clearance levels where higher levels satisfy lower ones, with independent labels such as region, program, or team membership. Quorum can then be applied as an approval requirement on top of attribute satisfaction, enabling both classification-style access control and multi-party authorization. Cedar is the assumed policy expression language for GoodKey profiles, though CEF itself remains policy-language agnostic at the format layer.

**Use case:** Secure file exchange between identified parties. Recipients known at encryption time. Strong key custody across multiple provider types. PQ protection against HNDL. Offline capability via smart cards where centralized policy isn't required.

---

## OpenTDF (Trusted Data Format)

**Enforcement model:** Service-mediated with key-intrinsic policy binding. The KAS evaluates ABAC policy at rewrap time (service-mediated), but the policy is also bound to the wrapped key via HMAC(DEK, policy). This binding lets the KAS verify that the policy hasn't been tampered with since encryption, but the actual access decision is still made by the KAS at rewrap time. Revocation takes effect at the next rewrap request.

**Format:** ZIP archive with a plaintext JSON manifest and a single encrypted payload. The manifest contains key access objects, policy, integrity information, and optional assertions. Supports segmented payloads with per-segment integrity hashes for streaming large files.

**Cryptography:** Currently classical in the reference platform and documentation. RSA-2048/4096 and ECDH P-256/P-384/P-521 for key wrapping. AES-256-GCM for content. The protocol is designed to be crypto-agile and may adopt post-quantum algorithms without format changes.

**Key management:** KAS supports pluggable key storage: the reference platform supports a software-managed mode and can also externalize private-key operations to third-party KMS/HSM systems. Federation across multiple independent KAS instances. DEK splitting (XOR) across KAS instances for multi-party authorization. No equivalent temporal key-versioning model is evident in the current OpenTDF documentation.

**Use case:** Enterprise data governance with ABAC. Classification hierarchies. Multi-organization data sharing where no single entity controls all keys. NATO ZTDF builds on this. Large file streaming.

---

## Enforcement Model Comparison

| | CEF | OpenTDF |
|-|-----|---------|
| Enforcement model | Service-mediated (GoodKey) | Service-mediated (KAS) + key-intrinsic policy binding |
| Policy location | Server-side | In container (HMAC-bound) + server-side |
| Offline decrypt | Smart card keys only | No |
| Offline creation | Smart card keys only | Yes (policy binding only) |
| Revocation (forward) | Immediate (cloud keys) | Next rewrap |
| Revocation (backward) | Key versioning (service-enforced) | None |
| Connectivity required | For cloud keys, yes | Always (for decrypt) |

Both systems are fundamentally service-mediated. A key service makes the access decision. OpenTDF adds a key-intrinsic tamper-detection layer via HMAC policy binding, which lets the KAS verify that the policy wasn't altered after encryption, but the KAS still decides whether to release the key. CEF's smart card path moves closer to key-intrinsic enforcement (physical possession = access), but without attribute-based policy in the key structure.

---

## Format Comparison

| | CEF | OpenTDF (Base) | OpenTDF (NanoTDF) |
|-|-----|---------------|-------------------|
| Serialization | COSE/CBOR (IETF RFC 9052, 8949) | Custom JSON schema | Custom binary |
| Container | ZIP | ZIP | None (binary blob) |
| Manifest encrypted | Yes | No | Policy encrypted, header not |
| Multi-file | Yes | No | No |
| Streaming | No | Yes (segmented) | No |
| PQ algorithms | ML-KEM-768, ML-DSA-65 (default) | Currently none; crypto-agile | Currently none |
| Built on IETF standards | Yes (COSE, CBOR) | No (custom JSON) | No (custom binary) |
| Policy in format | No | Yes (HMAC-bound) | Yes (GMAC/ECDSA-bound) |

**Metadata privacy:** OpenTDF's manifest.json is plaintext in the ZIP. Anyone who opens the file can see the KAS URLs, policy attributes, and key identifiers. CEF encrypts the entire manifest, so the file list, sender, recipients, and all metadata are opaque without a valid recipient key.

**Standards alignment:** OpenTDF's JSON schema for KeyAccessObject, EncryptionInformation, and IntegrityInformation is well-documented but proprietary. CEF builds on COSE_Encrypt and COSE_Sign1, which have multiple independent implementations and formal CDDL schemas.

**Policy binding:** OpenTDF cryptographically binds policy to key-access information and validates that binding at rewrap time. The access policy is tied to the wrapped key in the container itself, and the KAS verifies this binding independently before rewrapping. CEF has no equivalent in the container format. Policy is evaluated at the GoodKey service layer. ABAC support at the service layer is planned, which will enable attribute-based policy decisions at wrap/unwrap time.

---

## Cryptography Comparison

| | CEF | OpenTDF |
|-|-----|---------|
| Content encryption | AES-256-GCM | AES-256-GCM |
| Key encapsulation | ML-KEM-768 (default), AES-256-KW (fallback) | RSA-2048/4096, ECDH P-256/P-384 |
| Signing | ML-DSA-65 (default), ES256 (fallback) | HMAC-SHA256 (policy binding) |
| PQ status | Default (FIPS 203/204) | Currently classical; format is crypto-agile |
| HNDL protection | Yes | No |
| Mixed PQ/classical | Yes (per recipient) | N/A |

OpenTDF containers created with the current reference platform wrap their DEK with RSA or ECDH. If an adversary captures these containers and later obtains a cryptographically relevant quantum computer, they can recover the DEK and decrypt the payload. CEF defaults to ML-KEM-768, which provides post-quantum security from day one. OpenTDF's crypto-agile design could adopt PQ algorithms in the future.

---

## Key Management Comparison

| | CEF (GoodKey) | OpenTDF (KAS) |
|-|---------------|---------------|
| Key custody (default) | Per-key provider selection | Software-managed (reference platform) |
| Key custody (maximum) | HSM, enclave, or smart card | External HSM via KEY_MODE_REMOTE |
| Offline key ops | Yes (smart card) | No |
| Multi-party auth | Quorum (N-of-M approval) | Key splitting (XOR across KAS instances) |
| Federation | Single service, multiple providers | Multiple independent KAS instances |
| Temporal key control | Key versioning + rotation | Not evident in current docs |
| Remote attestation | Yes (Nitro Enclaves, published PCR) | Not specified |
| ABAC | Planned (service-mediated) | Yes (core design, service-mediated) |

GoodKey and OpenTDF KAS both support pluggable key storage with HSM-grade custody as an option, but arrive there differently. GoodKey selects the provider per key (one user's signing key on a smart card, another's encryption key in CloudHSM). OpenTDF selects the key mode per KAS deployment, with software-managed as the reference platform default.

GoodKey's key versioning provides temporal access control: forward enforcement (revoked members locked out of new versions) and backward enforcement (new members don't receive old versions). OpenTDF's published model emphasizes policy evaluation and rewrap-time authorization rather than temporal key versioning.

---

## Use Cases

| Scenario | Best fit |
|----------|---------|
| Send confidential files to specific people/teams | CEF |
| Enterprise data governance with ABAC classification | OpenTDF |
| Post-quantum protection required today | CEF |
| Multi-organization federated key management | OpenTDF |
| Multi-file document bundles | CEF |
| Large file streaming (>1GB) | OpenTDF |
| Immediate revocation of cloud-managed keys | CEF |
| Temporal forward + backward enforcement | CEF |
| Metadata privacy (encrypted manifest) | CEF |
| Offline decrypt (smart card) | CEF |
| Offline creation (policy binding) | OpenTDF |
| Built on IETF standards (COSE, CBOR, ZIP) | CEF |
| Cryptographic policy binding in container | OpenTDF |

---

## Complementary, Not Competitive

These systems address different operational contexts.

CEF is the right choice when you know your recipients, want multiple key custody options (smart card through cloud HSM), need PQ protection today, and can use the GoodKey service for policy enforcement during key operations. The smart card path gives offline capability where centralized policy isn't needed. Key versioning provides temporal access control in both directions.

OpenTDF is the right choice when you need federated ABAC across organizational boundaries, where multiple KAS instances each independently evaluate policy, and where the policy itself must be cryptographically bound to the key material. The deployment complexity (Kubernetes, IdP, attribute service) is justified by the governance model it enables.

A deployed architecture could use both: CEF for file exchange between identified partners with PQ protection, OpenTDF for enterprise document governance under ABAC policy. The choice depends on whether the primary requirement is strong key custody with PQ and temporal control (CEF) or federated attribute-based policy with cryptographic binding (OpenTDF).
