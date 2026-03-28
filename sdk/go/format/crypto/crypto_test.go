
package crypto

import "testing"

func TestHKDFSHA256_RFC5869_TC1(t *testing.T) {
	// RFC 5869 Test Case 1
	ikm := make([]byte, 22)
	for i := range ikm { ikm[i] = 0x0b }
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}

	okm, err := HKDFSHA256(ikm, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
		0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
		0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
		0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
		0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
		0x58, 0x65,
	}

	if len(okm) != 42 {
		t.Fatalf("OKM length: want 42, got %d", len(okm))
	}
	for i := range expected {
		if okm[i] != expected[i] {
			t.Fatalf("OKM mismatch at byte %d: want 0x%02x, got 0x%02x", i, expected[i], okm[i])
		}
	}
}

func TestHKDFSHA256_CEFDomain(t *testing.T) {
	// CEF-specific: derive KEK from a known shared secret
	// This vector is shared with the TS test suite for interop.
	ss := make([]byte, 32)
	for i := range ss { ss[i] = byte(i) }
	info := []byte("CEF-ML-KEM-768-A256KW")

	kek, err := HKDFSHA256(ss, nil, info, 32)
	if err != nil {
		t.Fatal(err)
	}

	// Print for cross-SDK verification
	t.Logf("CEF HKDF KEK: %x", kek)

	if len(kek) != 32 {
		t.Fatalf("KEK length: want 32, got %d", len(kek))
	}
}
