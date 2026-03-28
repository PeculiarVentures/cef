package exchange

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	gkxcrypto "github.com/PeculiarVentures/cef/sdk/go/format/crypto"
)

// Domain separation label for ML-KEM KEK derivation.
// Must match the TypeScript SDK and the spec.
const domainLabel = "CEF-ML-KEM-768-A256KW"

// ParseSPKIPublicKey extracts the raw public key bytes from a
// DER-encoded SubjectPublicKeyInfo structure.
func parseSPKIPublicKey(spkiDER []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		// For PQ keys, x509.ParsePKIXPublicKey may not recognize the OID.
		// Fall back to manual ASN.1 parsing of the BIT STRING payload.
		return parseSPKIRaw(spkiDER)
	}

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return elliptic.Marshal(k.Curve, k.X, k.Y), nil
	case ed25519.PublicKey:
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// parseSPKIRaw is a minimal ASN.1 parser that extracts the BIT STRING
// from an SPKI structure. Used for PQ keys whose OIDs are not in the
// Go standard library.
func parseSPKIRaw(der []byte) ([]byte, error) {
	// SPKI = SEQUENCE { SEQUENCE { OID, ... }, BIT STRING }
	// We need the BIT STRING content (skip the leading unused-bits byte).
	// This is a simplified parser that works for ML-KEM/ML-DSA SPKI.
	if len(der) < 10 {
		return nil, fmt.Errorf("SPKI too short")
	}

	// Find the BIT STRING (tag 0x03) after the AlgorithmIdentifier SEQUENCE
	pos := 0
	// Skip outer SEQUENCE tag+length
	if der[pos] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE at offset 0")
	}
	pos++
	_, pos = parseASN1Length(der, pos)

	// Skip inner SEQUENCE (AlgorithmIdentifier)
	if der[pos] != 0x30 {
		return nil, fmt.Errorf("expected AlgorithmIdentifier SEQUENCE")
	}
	pos++
	innerLen, pos := parseASN1Length(der, pos)
	pos += innerLen

	// Now at BIT STRING
	if der[pos] != 0x03 {
		return nil, fmt.Errorf("expected BIT STRING, got 0x%02x", der[pos])
	}
	pos++
	bsLen, pos := parseASN1Length(der, pos)

	// Skip unused bits byte
	if der[pos] != 0x00 {
		return nil, fmt.Errorf("BIT STRING has unused bits: %d", der[pos])
	}
	pos++
	bsLen--

	if pos+bsLen > len(der) {
		return nil, fmt.Errorf("BIT STRING extends beyond DER")
	}
	return der[pos : pos+bsLen], nil
}

func parseASN1Length(der []byte, pos int) (int, int) {
	if der[pos] < 0x80 {
		return int(der[pos]), pos + 1
	}
	numBytes := int(der[pos] & 0x7F)
	pos++
	length := 0
	for i := 0; i < numBytes; i++ {
		length = length<<8 | int(der[pos])
		pos++
	}
	return length, pos
}

// mlkemEncapsulate performs ML-KEM-768 encapsulation with the given
// raw public key (1184 bytes). Returns (cipherText, sharedSecret).
func mlkemEncapsulate(rawPK []byte) (cipherText, sharedSecret []byte, err error) {
	var pk mlkem768.PublicKey
	if err := pk.Unpack(rawPK); err != nil {
		return nil, nil, fmt.Errorf("ML-KEM-768 unpack public key: %w", err)
	}
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	pk.EncapsulateTo(ct, ss, nil)
	return ct, ss, nil
}

// deriveMLKEMKEK derives a 256-bit KEK from an ML-KEM shared secret
// using HKDF-SHA256 (RFC 5869) with domain separation.
func deriveMLKEMKEK(sharedSecret []byte) ([]byte, error) {
	return gkxcrypto.HKDFSHA256(sharedSecret, nil, []byte(domainLabel), 32)
}

// verifySignature verifies a signature using the given algorithm name
// and SPKI-encoded public key. All public keys are SPKI DER, matching
// the real GoodKey server's GetPublicKey response.
func verifySignature(algName string, spkiDER []byte, message, signature []byte) error {
	switch algName {
	case "ML_DSA_65":
		rawPK, err := parseSPKIPublicKey(spkiDER)
		if err != nil {
			return fmt.Errorf("parse ML-DSA-65 public key: %w", err)
		}
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(rawPK); err != nil {
			return fmt.Errorf("ML-DSA-65 unpack: %w", err)
		}
		if !mldsa65.Verify(&pk, message, nil, signature) {
			return fmt.Errorf("ML-DSA-65 signature verification failed")
		}
		return nil

	case "ECDSA_P256_SHA256":
		pub, err := x509.ParsePKIXPublicKey(spkiDER)
		if err != nil {
			return fmt.Errorf("parse ECDSA public key: %w", err)
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ECDSA public key, got %T", pub)
		}
		h := sha256.Sum256(message)
		// ECDSA signature is ASN.1 encoded r,s
		if !ecdsa.VerifyASN1(ecPub, h[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	case "ED_25519":
		pub, err := x509.ParsePKIXPublicKey(spkiDER)
		if err != nil {
			return fmt.Errorf("parse Ed25519 public key: %w", err)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected Ed25519 public key, got %T", pub)
		}
		if !ed25519.Verify(edPub, message, signature) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported signature algorithm: %s", algName)
	}
}

// aesKeyWrap wraps from the crypto package (re-exported for internal use).
var aesKeyWrap = gkxcrypto.AESKeyWrap
var aesKeyUnwrap = gkxcrypto.AESKeyUnwrap
var zeroize = gkxcrypto.Zeroize

// Unused import guard
