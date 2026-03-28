// Package crypto provides shared cryptographic primitives used by both the
// CEF format layer (pkg/cose) and key management implementations.
//
// This package contains:
//   - AES Key Wrap / Unwrap (RFC 3394)
//   - ANSI-X9.63-KDF with SHA-256 (RFC 9053 §6)
//   - Zeroization utilities
//
// These are standard algorithms, not CEF-specific. They are separated into
// their own package so that format-layer code and key service implementations
// can both use them without creating circular dependencies.
package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"runtime"
)

// AESKeyWrap implements RFC 3394 AES Key Wrap.
// Accepts 16, 24, or 32-byte KEKs (AES-128/192/256).
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, fmt.Errorf("keywrap: KEK must be 16, 24, or 32 bytes, got %d", len(kek))
	}
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, fmt.Errorf("keywrap: plaintext must be ≥16 bytes and a multiple of 8, got %d", len(plaintext))
	}

	n := len(plaintext) / 8
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("keywrap: %w", err)
	}

	// Initial Value per RFC 3394 §2.2.3.1.
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], r[i])
			block.Encrypt(b[:], b[:])

			copy(a[:], b[:8])
			t := uint64(n*j + i + 1)
			for k := 7; k >= 0; k-- {
				a[k] ^= byte(t)
				t >>= 8
			}
			copy(r[i], b[8:])
		}
	}

	out := make([]byte, 8+n*8)
	copy(out[:8], a[:])
	for i := 0; i < n; i++ {
		copy(out[8+i*8:], r[i])
	}
	return out, nil
}

// AESKeyUnwrap implements RFC 3394 AES Key Unwrap.
// Uses constant-time comparison for the integrity check value.
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, fmt.Errorf("keyunwrap: KEK must be 16, 24, or 32 bytes, got %d", len(kek))
	}
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, fmt.Errorf("keyunwrap: ciphertext must be ≥24 bytes and a multiple of 8, got %d", len(ciphertext))
	}

	n := (len(ciphertext) / 8) - 1
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("keyunwrap: %w", err)
	}

	var a [8]byte
	copy(a[:], ciphertext[:8])

	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[8+i*8:8+(i+1)*8])
	}

	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			for k := 7; k >= 0; k-- {
				a[k] ^= byte(t)
				t >>= 8
			}

			copy(b[:8], a[:])
			copy(b[8:], r[i])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[i], b[8:])
		}
	}

	// Constant-time integrity check value verification.
	expected := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	if subtle.ConstantTimeCompare(a[:], expected[:]) != 1 {
		return nil, fmt.Errorf("keyunwrap: integrity check failed")
	}

	out := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(out[i*8:], r[i])
	}
	return out, nil
}

// ANSIX963KDF derives a key using ANSI-X9.63-KDF with SHA-256.
func ANSIX963KDF(sharedSecret, sharedInfo []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("kdf: keyLen must be positive")
	}

	h := sha256.New()
	hashLen := h.Size()
	reps := (keyLen + hashLen - 1) / hashLen

	result := make([]byte, 0, reps*hashLen)
	counter := make([]byte, 4)

	for i := 1; i <= reps; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))
		h.Reset()
		h.Write(sharedSecret)
		h.Write(counter)
		if len(sharedInfo) > 0 {
			h.Write(sharedInfo)
		}
		result = append(result, h.Sum(nil)...)
	}

	return result[:keyLen], nil
}

// Zeroize overwrites a byte slice with zeros. Uses runtime.KeepAlive
// to prevent the compiler from optimizing away the writes.
//
// LIMITATION: Go's garbage collector may have copied the slice contents
// during heap operations. True zeroization guarantees require mlock'd
// memory via syscall, which is out of scope for this SDK.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// HKDFSHA256 implements HKDF (RFC 5869) with SHA-256.
//
// Uses crypto/hmac from the Go standard library for HMAC-SHA256.
//
// Parameters:
//   - ikm: input keying material (e.g., ML-KEM shared secret)
//   - salt: optional salt (nil uses a zero-filled hash-length salt)
//   - info: context/application-specific info (e.g., domain label)
//   - length: desired output length in bytes (max 255 * 32 = 8160)
func HKDFSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: invalid output length %d", length)
	}

	// Extract: PRK = HMAC-SHA256(salt, IKM)
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	// Expand: OKM = T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
	var okm []byte
	var prev []byte
	for i := 1; len(okm) < length; i++ {
		expander := hmac.New(sha256.New, prk)
		expander.Write(prev)
		expander.Write(info)
		expander.Write([]byte{byte(i)})
		t := expander.Sum(nil)
		okm = append(okm, t...)
		prev = t
	}

	return okm[:length], nil
}
