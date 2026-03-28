// Package cose implements COSE encryption and signing structures for the
// CEF secure file exchange format.
//
// This package implements:
//   - COSE_Encrypt (RFC 9052 §5.1) — multi-recipient authenticated encryption
//   - COSE_Sign1  (RFC 9052 §4.2) — single-signer signatures
//   - AES-256-GCM content encryption (RFC 9053 §4.1)
//   - AES Key Wrap / Unwrap (RFC 3394)
//   - ANSI-X9.63-KDF for ECDH key derivation (RFC 9053 §6)
//
// All structures are serialized using CBOR (RFC 8949) via fxamacker/cbor/v2.
//
// This package is the format layer only. It does not perform private key
// operations directly. Instead, it accepts callback functions (WrapCEKFunc,
// UnwrapCEKFunc, SignFunc, VerifyFunc) that the caller provides. Any key
// management backend that can wrap/unwrap/sign can supply these callbacks.
//
// This is the sole COSE/CBOR implementation in the project. There is no
// secondary dependency on veraison/go-cose or any other COSE library.
package cose

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	gkxcrypto "github.com/PeculiarVentures/cef/sdk/go/format/crypto"
	cbor "github.com/fxamacker/cbor/v2"
)

// Deterministic CBOR encoding per RFC 8949 §4.2.1.
// COSE requires deterministic serialization of protected headers
// because those bytes are included in Sig_structure and Enc_structure.
var (
	deterministicEncMode cbor.EncMode
	defaultDecMode       cbor.DecMode
)

func init() {
	var err error
	deterministicEncMode, err = cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		IndefLength:   cbor.IndefLengthForbidden,
		TagsMd:        cbor.TagsAllowed,
	}.EncMode()
	if err != nil {
		panic("cose: failed to create deterministic CBOR encoder: " + err.Error())
	}

	defaultDecMode, err = cbor.DecOptions{
		MaxArrayElements: 65536,
		MaxMapPairs:      65536,
	}.DecMode()
	if err != nil {
		panic("cose: failed to create CBOR decoder: " + err.Error())
	}
}

// ---------------------------------------------------------------------------
// COSE Algorithm Identifiers (IANA COSE Algorithms Registry)
// https://www.iana.org/assignments/cose/cose.xhtml
//
// CEF defaults to post-quantum algorithms (ML-KEM, ML-DSA) for all new
// containers. Classical algorithms are supported for backward compatibility
// with existing keys and recipients.
// ---------------------------------------------------------------------------

const (
	// Content encryption algorithms.
	AlgA256GCM int64 = 3 // AES-GCM mode w/ 256-bit key, 128-bit tag

	// Key wrap algorithms (classical).
	AlgA256KW int64 = -5 // AES Key Wrap w/ 256-bit key

	// Key agreement with key wrap (classical).
	AlgECDH_ES_A256KW int64 = -31 // ECDH-ES + A256KW

	// Key transport (classical, legacy).
	AlgRSA_OAEP_256 int64 = -42 // RSAES-OAEP w/ SHA-256

	// Direct key agreement.
	AlgDirect int64 = -6 // Direct use of CEK

	// Post-quantum KEM + key wrap.
	// ML-KEM encapsulates a shared secret; the shared secret is used to
	// wrap the CEK with AES-256-KW. The key management service performs the ML-KEM operation
	// and returns the wrapped CEK.
	//
	// These use private-use values (< -65536 per RFC 9052) until
	// draft-ietf-jose-pqc-kem receives IANA-assigned identifiers.
	// TODO: Update to permanent values when IANA assignment completes.
	AlgMLKEM768_A256KW  int64 = -70010 // ML-KEM-768 + A256KW (private-use, pending IANA)
	AlgMLKEM1024_A256KW int64 = -70011 // ML-KEM-1024 + A256KW (private-use, pending IANA)

	// Signature algorithms (classical).
	AlgES256 int64 = -7  // ECDSA w/ SHA-256 (P-256)
	AlgES384 int64 = -35 // ECDSA w/ SHA-384 (P-384)
	AlgES512 int64 = -36 // ECDSA w/ SHA-512 (P-521)
	AlgEdDSA int64 = -8  // EdDSA (Ed25519, Ed448)
	AlgPS256 int64 = -37 // RSASSA-PSS w/ SHA-256

	// Post-quantum signature algorithms.
	// IANA early-allocated 2025-04-24 per draft-ietf-cose-dilithium-06.
	// Temporary registrations expire 2026-04-24; permanent when RFC published.
	AlgMLDSA44 int64 = -48 // ML-DSA-44 (FIPS 204, ~128-bit PQ security)
	AlgMLDSA65 int64 = -49 // ML-DSA-65 (FIPS 204, ~192-bit PQ security)
	AlgMLDSA87 int64 = -50 // ML-DSA-87 (FIPS 204, ~256-bit PQ security)
)

// Default algorithms. CEF defaults to post-quantum for HNDL protection.
// Classical algorithms are used when the recipient's key doesn't support PQ.
const (
	// DefaultKeyWrapAlgorithm is ML-KEM-768 + A256KW.
	// ML-KEM-768 provides NIST Level 3 (~192-bit) post-quantum security.
	// AES-256 provides 128-bit security against Grover's algorithm.
	// The key service performs ML-KEM encapsulation.
	DefaultKeyWrapAlgorithm = AlgMLKEM768_A256KW

	// DefaultSignatureAlgorithm is ML-DSA-65.
	// ML-DSA-65 provides NIST Level 3 (~192-bit) post-quantum security.
	// The key service performs ML-DSA signing.
	DefaultSignatureAlgorithm = AlgMLDSA65

	// FallbackKeyWrapAlgorithm is AES-256-KW for classical-only keys.
	FallbackKeyWrapAlgorithm = AlgA256KW

	// FallbackSignatureAlgorithm is ES256 for classical-only keys.
	FallbackSignatureAlgorithm = AlgES256
)

// ---------------------------------------------------------------------------
// COSE Header Labels (RFC 9052 §3.1)
// ---------------------------------------------------------------------------

const (
	HeaderAlgorithm   int64 = 1
	HeaderContentType int64 = 3
	HeaderKeyID       int64 = 4
	HeaderIV          int64 = 5
	HeaderCounterSig  int64 = 11
	HeaderX5Chain     int64 = 33 // RFC 9360
	HeaderEphemeralKey int64 = -1
	HeaderStaticKeyID  int64 = -3
)

// CEF private header labels. Per RFC 9052 §3.1, private-use
// labels are negative integers less than -65536. We use the -70000 range.
const (
	// HeaderGKRecipientType identifies the recipient resolution method.
	// Values: "key" (key ID), "email" (email lookup), "group" (group key).
	HeaderGKRecipientType int64 = -70001


)

// ---------------------------------------------------------------------------
// Header types
// ---------------------------------------------------------------------------

// ProtectedHeader is a CBOR map that is integrity-protected (serialized to
// a byte string and included in AAD/Sig_structure computation).
type ProtectedHeader map[int64]interface{}

// UnprotectedHeader is a CBOR map that is not integrity-protected.
type UnprotectedHeader map[int64]interface{}

// ---------------------------------------------------------------------------
// COSE_Encrypt (RFC 9052 §5.1)
// ---------------------------------------------------------------------------

// EncryptMessage represents a COSE_Encrypt structure.
//
//	COSE_Encrypt = [
//	    protected   : bstr,
//	    unprotected : map,
//	    ciphertext  : bstr / nil,
//	    recipients  : [+ COSE_recipient]
//	]
type EncryptMessage struct {
	Protected    ProtectedHeader
	Unprotected  UnprotectedHeader
	Ciphertext   []byte
	Recipients   []Recipient
	RawProtected []byte // Original serialized protected header bytes for AAD computation.
}

// Recipient represents a COSE_recipient structure.
//
//	COSE_recipient = [
//	    protected   : bstr,
//	    unprotected : map,
//	    ciphertext  : bstr / nil   // the wrapped CEK
//	]
type Recipient struct {
	Protected   ProtectedHeader
	Unprotected UnprotectedHeader
	Ciphertext  []byte
}

// RecipientInfo describes a recipient for encryption. The exchange layer
// resolves these to actual keys via the key management service.
//
// KeyID is the concrete key material identifier used for this operation.
// The optional fields below allow callers to carry richer identity
// information that future key services can use for resolution, versioning,
// and policy-based access decisions.
type RecipientInfo struct {
	KeyID     string // Key identifier (kid)
	Algorithm int64  // Key wrapping algorithm (e.g., AlgA256KW)
	PublicKey []byte // Recipient's public key (SPKI DER), if available
	Type      string // "key", "email", "certificate", or "group"

	// Extension fields — optional, not used by current implementations.
	LogicalKeyID string // Stable named key (e.g., "case-123", "document-key")
	VersionID    string // Key material version (e.g., "v3")
	PolicyRef    string // Policy or attribute reference for resolution
}

// EncryptOpts configures the COSE_Encrypt operation.
type EncryptOpts struct {
	// ContentAlgorithm is the content encryption algorithm. Default: AlgA256GCM.
	ContentAlgorithm int64

	// ExternalAAD is additional authenticated data not carried in the
	// COSE structure (RFC 9052 §5.3).
	ExternalAAD []byte
}

// WrapCEKFunc wraps a Content Encryption Key for a given recipient.
// Returns the encrypted/wrapped CEK bytes. In practice, this
// callback delegates to a key management service.
type WrapCEKFunc func(cek []byte, recipient *RecipientInfo) ([]byte, error)

// UnwrapCEKFunc recovers a Content Encryption Key from a recipient structure.
// Returns the plaintext CEK. In practice, this callback delegates
// to a key management service.
type UnwrapCEKFunc func(wrappedCEK []byte, recipient *Recipient) ([]byte, error)

// Encrypt creates a COSE_Encrypt message.
//
// It generates a random CEK, encrypts the plaintext with AES-256-GCM, and
// wraps the CEK for each recipient via the wrapCEK callback.
func Encrypt(plaintext []byte, recipients []RecipientInfo, wrapCEK WrapCEKFunc, opts *EncryptOpts) (*EncryptMessage, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("cose: at least one recipient required")
	}
	if opts == nil {
		opts = &EncryptOpts{}
	}
	if opts.ContentAlgorithm == 0 {
		opts.ContentAlgorithm = AlgA256GCM
	}

	// Generate CEK with explicit length check.
	cek := make([]byte, 32)
	n, err := rand.Read(cek)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("cose: CEK generation failed: read %d/32 bytes: %w", n, err)
	}
	defer zeroize(cek)

	// Generate IV (12 bytes for AES-GCM per NIST SP 800-38D §8.2).
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cose: IV generation failed: %w", err)
	}

	protected := ProtectedHeader{HeaderAlgorithm: opts.ContentAlgorithm}
	unprotected := UnprotectedHeader{HeaderIV: iv}

	// Propagate marshal errors from Enc_structure.
	protectedBytes, err := marshalProtected(protected)
	if err != nil {
		return nil, fmt.Errorf("cose: protected header: %w", err)
	}

	aad, err := buildEncStructure(protectedBytes, opts.ExternalAAD)
	if err != nil {
		return nil, fmt.Errorf("cose: Enc_structure: %w", err)
	}

	// Validate key length before encryption.
	ciphertext, err := encryptAESGCM(cek, iv, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("cose: content encryption: %w", err)
	}

	// Wrap CEK for each recipient.
	coseRecipients := make([]Recipient, len(recipients))
	for i, ri := range recipients {
		wrapped, err := wrapCEK(cek, &ri)
		if err != nil {
			return nil, fmt.Errorf("cose: wrap CEK for recipient %d (%s): %w", i, ri.KeyID, err)
		}

		rProtected := ProtectedHeader{HeaderAlgorithm: ri.Algorithm}
		rUnprotected := UnprotectedHeader{HeaderKeyID: []byte(ri.KeyID)}

		if ri.Type != "" {
			rUnprotected[HeaderGKRecipientType] = ri.Type
		}

		coseRecipients[i] = Recipient{
			Protected:   rProtected,
			Unprotected: rUnprotected,
			Ciphertext:  wrapped,
		}
	}

	return &EncryptMessage{
		Protected:   protected,
		Unprotected: unprotected,
		Ciphertext:  ciphertext,
		Recipients:  coseRecipients,
	}, nil
}

// Decrypt decrypts a COSE_Encrypt message.
//
// recipientIndex identifies which recipient's wrapped CEK to use.
// unwrapCEK recovers the plaintext CEK via the key management service callback.
func Decrypt(msg *EncryptMessage, recipientIndex int, unwrapCEK UnwrapCEKFunc, opts *EncryptOpts) ([]byte, error) {
	if opts == nil {
		opts = &EncryptOpts{}
	}
	if recipientIndex < 0 || recipientIndex >= len(msg.Recipients) {
		return nil, fmt.Errorf("cose: recipient index %d out of range [0, %d)", recipientIndex, len(msg.Recipients))
	}

	recipient := msg.Recipients[recipientIndex]

	// Validate content encryption algorithm.
	algRaw, ok := msg.Protected[HeaderAlgorithm]
	if !ok {
		return nil, fmt.Errorf("cose: missing algorithm in protected header")
	}
	if ToInt64(algRaw) != AlgA256GCM {
		return nil, fmt.Errorf("cose: unsupported content algorithm %d (expected A256GCM)", ToInt64(algRaw))
	}

	cek, err := unwrapCEK(recipient.Ciphertext, &recipient)
	if err != nil {
		return nil, fmt.Errorf("cose: unwrap CEK: %w", err)
	}
	defer zeroize(cek)

	ivRaw, ok := msg.Unprotected[HeaderIV]
	if !ok {
		return nil, fmt.Errorf("cose: missing IV in unprotected headers")
	}
	iv, ok := ivRaw.([]byte)
	if !ok {
		return nil, fmt.Errorf("cose: IV is not a byte string (got %T)", ivRaw)
	}

	// Use original protected bytes if available (from unmarshal),
	// otherwise re-serialize (for freshly constructed messages).
	protectedBytes := msg.RawProtected
	if protectedBytes == nil {
		var err2 error
		protectedBytes, err2 = marshalProtected(msg.Protected)
		if err2 != nil {
			return nil, fmt.Errorf("cose: protected header: %w", err2)
		}
	}
	aad, err := buildEncStructure(protectedBytes, opts.ExternalAAD)
	if err != nil {
		return nil, fmt.Errorf("cose: Enc_structure: %w", err)
	}

	plaintext, err := decryptAESGCM(cek, iv, msg.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("cose: content decryption: %w", err)
	}

	return plaintext, nil
}

// ---------------------------------------------------------------------------
// COSE_Sign1 (RFC 9052 §4.2)
// ---------------------------------------------------------------------------

// Sign1Message represents a COSE_Sign1 structure.
//
//	COSE_Sign1 = [
//	    protected   : bstr,
//	    unprotected : map,
//	    payload     : bstr / nil,
//	    signature   : bstr
//	]
type Sign1Message struct {
	Protected    ProtectedHeader
	Unprotected  UnprotectedHeader
	Payload      []byte // nil for detached signatures
	Signature    []byte
	RawProtected []byte // Original serialized protected header bytes for Sig_structure.
}

// SignFunc produces a raw signature over the Sig_structure bytes.
type SignFunc func(sigStructure []byte) ([]byte, error)

// VerifyFunc verifies a raw signature over the Sig_structure bytes.
type VerifyFunc func(sigStructure, signature []byte) error

// Sign1 creates a COSE_Sign1 message.
//
// If detached is true, the payload is excluded from the serialized message
// (the verifier must supply it externally).
func Sign1(algorithm int64, keyID string, payload []byte, detached bool, signFn SignFunc) (*Sign1Message, error) {
	protected := ProtectedHeader{HeaderAlgorithm: algorithm}
	unprotected := UnprotectedHeader{HeaderKeyID: []byte(keyID)}

	protectedBytes, err := marshalProtected(protected)
	if err != nil {
		return nil, fmt.Errorf("cose: protected header: %w", err)
	}

	// Propagate Sig_structure marshal errors.
	sigStructure, err := buildSigStructure(protectedBytes, nil, payload)
	if err != nil {
		return nil, fmt.Errorf("cose: Sig_structure: %w", err)
	}

	signature, err := signFn(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("cose: signing: %w", err)
	}

	msg := &Sign1Message{
		Protected:   protected,
		Unprotected: unprotected,
		Signature:   signature,
	}
	if !detached {
		msg.Payload = payload
	}
	return msg, nil
}

// Verify1 verifies a COSE_Sign1 message.
//
// For detached signatures (Payload is nil), externalPayload must be provided.
func Verify1(msg *Sign1Message, externalPayload []byte, verifyFn VerifyFunc) error {
	payload := msg.Payload
	if len(payload) == 0 {
		// Detached payload: COSE_Sign1 with nil or empty payload means
		// the actual payload is supplied externally.
		payload = externalPayload
	}
	if len(payload) == 0 {
		return fmt.Errorf("cose: no payload for verification (detached payload not provided)")
	}

	// Use original protected bytes if available (from unmarshal),
	// otherwise re-serialize (for freshly constructed messages).
	protectedBytes := msg.RawProtected
	if protectedBytes == nil {
		var err error
		protectedBytes, err = marshalProtected(msg.Protected)
		if err != nil {
			return fmt.Errorf("cose: protected header: %w", err)
		}
	}

	sigStructure, err := buildSigStructure(protectedBytes, nil, payload)
	if err != nil {
		return fmt.Errorf("cose: Sig_structure: %w", err)
	}

	return verifyFn(sigStructure, msg.Signature)
}

// ---------------------------------------------------------------------------
// CBOR Serialization (Tags: 96 = COSE_Encrypt, 18 = COSE_Sign1)
// ---------------------------------------------------------------------------

// MarshalCBOR serializes a COSE_Encrypt message to CBOR with tag 96.
func (m *EncryptMessage) MarshalCBOR() ([]byte, error) {
	protectedBytes, err := marshalProtected(m.Protected)
	if err != nil {
		return nil, err
	}

	var recipientArrays []cbor.RawMessage
	for i, r := range m.Recipients {
		rBytes, err := marshalRecipient(&r)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		recipientArrays = append(recipientArrays, rBytes)
	}

	arr := []interface{}{
		protectedBytes,
		map[int64]interface{}(m.Unprotected),
		m.Ciphertext,
		recipientArrays,
	}

	return deterministicEncMode.Marshal(cbor.Tag{Number: 96, Content: arr})
}

// UnmarshalCBOR deserializes a COSE_Encrypt message from CBOR.
func (m *EncryptMessage) UnmarshalCBOR(data []byte) error {
	inner, err := unwrapTag(data, 96)
	if err != nil {
		return err
	}

	var arr []cbor.RawMessage
	if err := defaultDecMode.Unmarshal(inner, &arr); err != nil {
		return fmt.Errorf("cose: decode COSE_Encrypt array: %w", err)
	}
	if len(arr) != 4 {
		return fmt.Errorf("cose: COSE_Encrypt requires 4 elements, got %d", len(arr))
	}

	// [0] protected header (bstr)
	var protectedBytes []byte
	if err := defaultDecMode.Unmarshal(arr[0], &protectedBytes); err != nil {
		return fmt.Errorf("cose: decode protected: %w", err)
	}
	m.Protected, err = unmarshalProtected(protectedBytes)
	if err != nil {
		return err
	}
	m.RawProtected = protectedBytes // Preserve original bytes for AAD.

	// [1] unprotected header (map)
	m.Unprotected, err = unmarshalHeaderMap(arr[1])
	if err != nil {
		return fmt.Errorf("cose: decode unprotected: %w", err)
	}

	// [2] ciphertext (bstr / nil)
	if err := defaultDecMode.Unmarshal(arr[2], &m.Ciphertext); err != nil {
		m.Ciphertext = nil // CBOR nil
	}

	// [3] recipients (array)
	var recipientRaws []cbor.RawMessage
	if err := defaultDecMode.Unmarshal(arr[3], &recipientRaws); err != nil {
		return fmt.Errorf("cose: decode recipients: %w", err)
	}
	m.Recipients = make([]Recipient, len(recipientRaws))
	for i, rr := range recipientRaws {
		if err := unmarshalRecipient(rr, &m.Recipients[i]); err != nil {
			return fmt.Errorf("cose: recipient %d: %w", i, err)
		}
	}
	return nil
}

// MarshalCBOR serializes a COSE_Sign1 message to CBOR with tag 18.
func (m *Sign1Message) MarshalCBOR() ([]byte, error) {
	protectedBytes, err := marshalProtected(m.Protected)
	if err != nil {
		return nil, err
	}

	var payload interface{} = m.Payload
	if m.Payload == nil {
		payload = nil
	}

	arr := []interface{}{
		protectedBytes,
		map[int64]interface{}(m.Unprotected),
		payload,
		m.Signature,
	}

	return deterministicEncMode.Marshal(cbor.Tag{Number: 18, Content: arr})
}

// UnmarshalCBOR deserializes a COSE_Sign1 message from CBOR.
func (m *Sign1Message) UnmarshalCBOR(data []byte) error {
	inner, err := unwrapTag(data, 18)
	if err != nil {
		return err
	}

	var arr []cbor.RawMessage
	if err := defaultDecMode.Unmarshal(inner, &arr); err != nil {
		return fmt.Errorf("cose: decode COSE_Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return fmt.Errorf("cose: COSE_Sign1 requires 4 elements, got %d", len(arr))
	}

	var protectedBytes []byte
	if err := defaultDecMode.Unmarshal(arr[0], &protectedBytes); err != nil {
		return fmt.Errorf("cose: decode protected: %w", err)
	}
	m.Protected, err = unmarshalProtected(protectedBytes)
	if err != nil {
		return err
	}
	m.RawProtected = protectedBytes // Preserve original bytes for Sig_structure.

	m.Unprotected, err = unmarshalHeaderMap(arr[1])
	if err != nil {
		return fmt.Errorf("cose: decode unprotected: %w", err)
	}

	if err := defaultDecMode.Unmarshal(arr[2], &m.Payload); err != nil {
		m.Payload = nil
	}

	if err := defaultDecMode.Unmarshal(arr[3], &m.Signature); err != nil {
		return fmt.Errorf("cose: decode signature: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// AES-256-GCM (RFC 9053 §4.1)
// ---------------------------------------------------------------------------

func encryptAESGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	// Validate key length.
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM requires 32-byte key, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("AES-GCM requires 12-byte nonce, got %d", len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func decryptAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM requires 32-byte key, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// ---------------------------------------------------------------------------
// AES Key Wrap / Unwrap (RFC 3394)
//
// Canonical implementations live in pkg/crypto for shared use by both the
// format layer (this package) and key management implementations.
// ---------------------------------------------------------------------------

// AESKeyWrap implements RFC 3394 AES Key Wrap.
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	return gkxcrypto.AESKeyWrap(kek, plaintext)
}

// AESKeyUnwrap implements RFC 3394 AES Key Unwrap.
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	return gkxcrypto.AESKeyUnwrap(kek, ciphertext)
}

// ---------------------------------------------------------------------------
// ANSI-X9.63-KDF (RFC 9053 §6)
// ---------------------------------------------------------------------------

// ANSIX963KDF derives a key using ANSI-X9.63-KDF with SHA-256.
func ANSIX963KDF(sharedSecret, sharedInfo []byte, keyLen int) ([]byte, error) {
	return gkxcrypto.ANSIX963KDF(sharedSecret, sharedInfo, keyLen)
}

// Internal: CBOR header encoding / structure builders
// ---------------------------------------------------------------------------

// marshalProtected encodes a protected header map to a CBOR byte string.
// An empty header is encoded as a zero-length byte string (h'').
func marshalProtected(h ProtectedHeader) ([]byte, error) {
	if len(h) == 0 {
		return []byte{}, nil
	}
	return deterministicEncMode.Marshal(map[int64]interface{}(h))
}

// unmarshalProtected decodes a CBOR byte string to a header map.
func unmarshalProtected(data []byte) (ProtectedHeader, error) {
	if len(data) == 0 {
		return ProtectedHeader{}, nil
	}
	return decodeHeaderMap(data)
}

// unmarshalHeaderMap decodes a CBOR map (as RawMessage) to a header map.
func unmarshalHeaderMap(raw cbor.RawMessage) (UnprotectedHeader, error) {
	m := make(map[interface{}]interface{})
	if err := defaultDecMode.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return normalizeHeaderMap(m), nil
}

// decodeHeaderMap decodes CBOR bytes to a header map.
func decodeHeaderMap(data []byte) (ProtectedHeader, error) {
	m := make(map[interface{}]interface{})
	if err := defaultDecMode.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("cose: decode header map: %w", err)
	}
	result := make(ProtectedHeader)
	for k, v := range m {
		if key, ok := tryInt64(k); ok {
			result[key] = v
		}
	}
	return result, nil
}

// normalizeHeaderMap converts interface{}-keyed maps to int64-keyed maps.
// This handles the uint64→int64 conversion that CBOR round-trips produce.
func normalizeHeaderMap(m map[interface{}]interface{}) map[int64]interface{} {
	result := make(map[int64]interface{}, len(m))
	for k, v := range m {
		if key, ok := tryInt64(k); ok {
			result[key] = v
		}
		// Non-integer keys are silently skipped per COSE spec
		// (header labels are always integers).
	}
	return result
}

// tryInt64 attempts to convert a value to int64, returning false if not an integer.
func tryInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case uint32:
		return int64(n), true
	default:
		return 0, false
	}
}

// ToInt64 converts various integer types to int64.
// Exported for use by the exchange layer when reading algorithm IDs
// from COSE headers after CBOR round-trip.
func ToInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case uint32:
		return int64(n)
	default:
		return 0 // non-integer keys are mapped to 0 (will be overwritten)
	}
}

// buildEncStructure builds the Enc_structure for AAD (RFC 9052 §5.3).
//
//	Enc_structure = [
//	    context      : "Encrypt",
//	    protected    : bstr,
//	    external_aad : bstr
//	]
//
// Returns error instead of silently dropping it.
func buildEncStructure(protectedBytes, externalAAD []byte) ([]byte, error) {
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	return deterministicEncMode.Marshal([]interface{}{"Encrypt", protectedBytes, externalAAD})
}

// buildSigStructure builds the Sig_structure1 (RFC 9052 §4.4).
//
//	Sig_structure1 = [
//	    context        : "Signature1",
//	    body_protected : bstr,
//	    external_aad   : bstr,
//	    payload        : bstr
//	]
//
// Returns error instead of silently dropping it.
func buildSigStructure(protectedBytes, externalAAD, payload []byte) ([]byte, error) {
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	return deterministicEncMode.Marshal([]interface{}{"Signature1", protectedBytes, externalAAD, payload})
}

// marshalRecipient encodes a COSE_recipient to CBOR.
func marshalRecipient(r *Recipient) (cbor.RawMessage, error) {
	protectedBytes, err := marshalProtected(r.Protected)
	if err != nil {
		return nil, err
	}
	return deterministicEncMode.Marshal([]interface{}{
		protectedBytes,
		map[int64]interface{}(r.Unprotected),
		r.Ciphertext,
	})
}

// unmarshalRecipient decodes a COSE_recipient from CBOR.
func unmarshalRecipient(data cbor.RawMessage, r *Recipient) error {
	var arr []cbor.RawMessage
	if err := defaultDecMode.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("decode recipient: %w", err)
	}
	if len(arr) < 3 {
		return fmt.Errorf("recipient requires 3 elements, got %d", len(arr))
	}

	var protectedBytes []byte
	if err := defaultDecMode.Unmarshal(arr[0], &protectedBytes); err != nil {
		return fmt.Errorf("decode recipient protected: %w", err)
	}
	var err error
	r.Protected, err = unmarshalProtected(protectedBytes)
	if err != nil {
		return err
	}

	r.Unprotected, err = unmarshalHeaderMap(arr[1])
	if err != nil {
		return err
	}

	if err := defaultDecMode.Unmarshal(arr[2], &r.Ciphertext); err != nil {
		r.Ciphertext = nil
	}
	return nil
}

// unwrapTag decodes a CBOR tag and returns the inner content as bytes.
// If the data is untagged, returns it directly.
func unwrapTag(data []byte, expectedTag uint64) ([]byte, error) {
	var tagged cbor.Tag
	if err := defaultDecMode.Unmarshal(data, &tagged); err == nil {
		if tagged.Number != expectedTag {
			return nil, fmt.Errorf("cose: expected CBOR tag %d, got %d", expectedTag, tagged.Number)
		}
		return deterministicEncMode.Marshal(tagged.Content)
	}
	return data, nil // untagged
}


// ---------------------------------------------------------------------------
// Zeroization
// ---------------------------------------------------------------------------

func zeroize(b []byte) {
	gkxcrypto.Zeroize(b)
}

// FindRecipientIndex returns the index of the recipient with the given key ID.
func FindRecipientIndex(msg *EncryptMessage, keyID string) (int, error) {
	for i, r := range msg.Recipients {
		kidRaw, ok := r.Unprotected[HeaderKeyID]
		if !ok {
			continue
		}
		var kid string
		switch v := kidRaw.(type) {
		case string:
			kid = v
		case []byte:
			kid = string(v)
		default:
			continue
		}
		if kid == keyID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("cose: recipient with kid %q not found", keyID)
}
