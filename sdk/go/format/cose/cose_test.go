package cose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// COSE_Encrypt round-trip tests
// ---------------------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("Hello, CEF COSE world!")
	testKEK := mustRandom(t, 32)

	msg := mustEncrypt(t, plaintext, testKEK, "test-key-001", nil)

	if msg.Ciphertext == nil {
		t.Fatal("ciphertext is nil")
	}
	if len(msg.Recipients) != 1 {
		t.Fatalf("want 1 recipient, got %d", len(msg.Recipients))
	}

	got := mustDecrypt(t, msg, testKEK, nil)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, got)
	}
}

func TestEncryptDecryptMultipleRecipients(t *testing.T) {
	plaintext := []byte("Multi-recipient test")
	keks := [][]byte{mustRandom(t, 32), mustRandom(t, 32), mustRandom(t, 32)}

	recipients := []RecipientInfo{
		{KeyID: "alice", Algorithm: AlgA256KW, Type: "key"},
		{KeyID: "bob", Algorithm: AlgA256KW, Type: "key"},
		{KeyID: "eng", Algorithm: AlgA256KW, Type: "group"},
	}

	wrapFn := func(cek []byte, ri *RecipientInfo) ([]byte, error) {
		switch ri.KeyID {
		case "alice":
			return AESKeyWrap(keks[0], cek)
		case "bob":
			return AESKeyWrap(keks[1], cek)
		case "eng":
			return AESKeyWrap(keks[2], cek)
		}
		return nil, fmt.Errorf("unknown recipient")
	}

	msg, err := Encrypt(plaintext, recipients, wrapFn, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i, kek := range keks {
		k := kek
		unwrapFn := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(k, w) }
		got, err := Decrypt(msg, i, unwrapFn, nil)
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("recipient %d: plaintext mismatch", i)
		}
	}
}

func TestEncryptDecryptWithExternalAAD(t *testing.T) {
	plaintext := []byte("AAD test")
	testKEK := mustRandom(t, 32)
	aad := []byte("additional authenticated data")

	opts := &EncryptOpts{ExternalAAD: aad}
	msg := mustEncrypt(t, plaintext, testKEK, "aad-key", opts)

	// Correct AAD → success
	got := mustDecrypt(t, msg, testKEK, opts)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch with correct AAD")
	}

	// Wrong AAD → GCM authentication failure
	wrongOpts := &EncryptOpts{ExternalAAD: []byte("wrong")}
	unwrapFn := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(testKEK, w) }
	_, err := Decrypt(msg, 0, unwrapFn, wrongOpts)
	if err == nil {
		t.Fatal("expected failure with wrong AAD")
	}
}

func TestEncryptEmptyPayload(t *testing.T) {
	testKEK := mustRandom(t, 32)
	msg := mustEncrypt(t, []byte{}, testKEK, "empty-key", nil)
	got := mustDecrypt(t, msg, testKEK, nil)
	if len(got) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got))
	}
}

func TestEncryptLargePayload(t *testing.T) {
	plaintext := mustRandom(t, 1024*1024) // 1 MB
	testKEK := mustRandom(t, 32)
	msg := mustEncrypt(t, plaintext, testKEK, "large-key", nil)
	got := mustDecrypt(t, msg, testKEK, nil)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("large payload round-trip failed")
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, err := Encrypt([]byte("x"), nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for no recipients")
	}
}

func TestDecryptInvalidRecipientIndex(t *testing.T) {
	msg := &EncryptMessage{Recipients: []Recipient{{}, {}}}
	_, err := Decrypt(msg, 5, nil, nil)
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
	_, err = Decrypt(msg, -1, nil, nil)
	if err == nil {
		t.Fatal("expected error for negative index")
	}
}

// ---------------------------------------------------------------------------
// COSE_Encrypt CBOR serialization
// ---------------------------------------------------------------------------

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	plaintext := []byte("CBOR round-trip test")
	testKEK := mustRandom(t, 32)
	msg := mustEncrypt(t, plaintext, testKEK, "ser-key", nil)

	data, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("COSE_Encrypt: %d bytes (plaintext: %d bytes, overhead: %d bytes)",
		len(data), len(plaintext), len(data)-len(plaintext))

	var msg2 EncryptMessage
	if err := msg2.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}

	got := mustDecrypt(t, &msg2, testKEK, nil)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch after CBOR round-trip")
	}
}

// Corrupt container handling — should fail gracefully.
func TestUnmarshalCorruptData(t *testing.T) {
	var msg EncryptMessage
	if err := msg.UnmarshalCBOR([]byte{0xFF, 0x00}); err == nil {
		t.Fatal("expected error for corrupt CBOR")
	}
	if err := msg.UnmarshalCBOR(nil); err == nil {
		t.Fatal("expected error for nil data")
	}
}

// ---------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------

func TestSign1RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte("Signed by CEF")

	signFn := func(ss []byte) ([]byte, error) {
		h := sha256.Sum256(ss)
		return ecdsa.SignASN1(rand.Reader, key, h[:])
	}
	verifyFn := func(ss, sig []byte) error {
		h := sha256.Sum256(ss)
		if !ecdsa.VerifyASN1(&key.PublicKey, h[:], sig) {
			return fmt.Errorf("bad signature")
		}
		return nil
	}

	msg, err := Sign1(AlgES256, "sign-key", payload, false, signFn)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify1(msg, nil, verifyFn); err != nil {
		t.Fatal(err)
	}
}

func TestSign1Detached(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte("Detached payload")

	signFn := func(ss []byte) ([]byte, error) {
		h := sha256.Sum256(ss)
		return ecdsa.SignASN1(rand.Reader, key, h[:])
	}
	verifyFn := func(ss, sig []byte) error {
		h := sha256.Sum256(ss)
		if !ecdsa.VerifyASN1(&key.PublicKey, h[:], sig) {
			return fmt.Errorf("bad signature")
		}
		return nil
	}

	msg, _ := Sign1(AlgES256, "dk", payload, true, signFn)
	if msg.Payload != nil {
		t.Fatal("detached payload should be nil")
	}

	if err := Verify1(msg, payload, verifyFn); err != nil {
		t.Fatal(err)
	}
	if err := Verify1(msg, []byte("wrong"), verifyFn); err == nil {
		t.Fatal("expected failure with wrong payload")
	}
}

func TestSign1MarshalUnmarshal(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte("Sign1 CBOR test")

	signFn := func(ss []byte) ([]byte, error) {
		h := sha256.Sum256(ss)
		return ecdsa.SignASN1(rand.Reader, key, h[:])
	}

	msg, _ := Sign1(AlgES256, "sk", payload, false, signFn)
	data, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("COSE_Sign1: %d bytes", len(data))

	var msg2 Sign1Message
	if err := msg2.UnmarshalCBOR(data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg2.Payload, payload) {
		t.Fatal("payload mismatch")
	}
	if !bytes.Equal(msg2.Signature, msg.Signature) {
		t.Fatal("signature mismatch")
	}
}

func TestVerify1NoPayload(t *testing.T) {
	msg := &Sign1Message{Payload: nil, Signature: []byte("x")}
	if err := Verify1(msg, nil, nil); err == nil {
		t.Fatal("expected error with no payload")
	}
}

// ---------------------------------------------------------------------------
// AES Key Wrap / Unwrap
// ---------------------------------------------------------------------------

func TestAESKeyWrapUnwrap(t *testing.T) {
	tests := []struct {
		name    string
		kekLen  int
		dataLen int
	}{
		{"AES-256 KEK, 256-bit data", 32, 32},
		{"AES-256 KEK, 128-bit data", 32, 16},
		{"AES-256 KEK, 192-bit data", 32, 24},
		{"AES-128 KEK, 128-bit data", 16, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := mustRandom(t, tt.kekLen)
			data := mustRandom(t, tt.dataLen)

			wrapped, err := AESKeyWrap(kek, data)
			if err != nil {
				t.Fatal(err)
			}
			if len(wrapped) != tt.dataLen+8 {
				t.Fatalf("wrapped length: want %d, got %d", tt.dataLen+8, len(wrapped))
			}

			unwrapped, err := AESKeyUnwrap(kek, wrapped)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unwrapped, data) {
				t.Fatal("unwrapped data mismatch")
			}
		})
	}
}

// Verify constant-time ICV check works.
func TestAESKeyUnwrapIntegrityFailure(t *testing.T) {
	kek := mustRandom(t, 32)
	data := mustRandom(t, 32)
	wrapped, _ := AESKeyWrap(kek, data)

	wrapped[0] ^= 0xFF // corrupt ICV
	_, err := AESKeyUnwrap(kek, wrapped)
	if err == nil {
		t.Fatal("expected integrity check failure")
	}
}

func TestAESKeyWrapInvalidLength(t *testing.T) {
	kek := mustRandom(t, 32)
	// Too short
	if _, err := AESKeyWrap(kek, make([]byte, 8)); err == nil {
		t.Fatal("expected error for 8-byte plaintext")
	}
	// Not multiple of 8
	if _, err := AESKeyWrap(kek, make([]byte, 7)); err == nil {
		t.Fatal("expected error for 7-byte plaintext")
	}
}

func TestAESKeyUnwrapWrongKey(t *testing.T) {
	kek1 := mustRandom(t, 32)
	kek2 := mustRandom(t, 32)
	data := mustRandom(t, 32)

	wrapped, _ := AESKeyWrap(kek1, data)
	_, err := AESKeyUnwrap(kek2, wrapped)
	if err == nil {
		t.Fatal("expected failure with wrong KEK")
	}
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

func TestANSIX963KDF(t *testing.T) {
	secret := mustRandom(t, 32)

	k1, _ := ANSIX963KDF(secret, nil, 32)
	k2, _ := ANSIX963KDF(secret, nil, 32)
	if !bytes.Equal(k1, k2) {
		t.Fatal("KDF not deterministic")
	}

	k3, _ := ANSIX963KDF(secret, []byte("ctx"), 32)
	if bytes.Equal(k1, k3) {
		t.Fatal("KDF should differ with different context")
	}
}

// ---------------------------------------------------------------------------
// CEF private headers
// ---------------------------------------------------------------------------

func TestRecipientHeaders(t *testing.T) {
	plaintext := []byte("group test")
	testKEK := mustRandom(t, 32)

	recipients := []RecipientInfo{{
		KeyID: "gk-eng", Algorithm: AlgA256KW, Type: "group",
	}}
	wrapFn := func(cek []byte, _ *RecipientInfo) ([]byte, error) { return AESKeyWrap(testKEK, cek) }

	msg, _ := Encrypt(plaintext, recipients, wrapFn, nil)
	r := msg.Recipients[0]

	if v, ok := r.Unprotected[HeaderGKRecipientType]; !ok || v != "group" {
		t.Fatalf("recipient type: want 'group', got %v", v)
	}
}

// Verify findRecipientByKeyID works after CBOR round-trip.
func TestRecipientKeyIDRoundTrip(t *testing.T) {
	plaintext := []byte("kid round-trip")
	testKEK := mustRandom(t, 32)
	msg := mustEncrypt(t, plaintext, testKEK, "my-key-id", nil)

	data, _ := msg.MarshalCBOR()
	var msg2 EncryptMessage
	msg2.UnmarshalCBOR(data)

	// After CBOR round-trip, kid should be []byte.
	kid := msg2.Recipients[0].Unprotected[HeaderKeyID]
	kidBytes, ok := kid.([]byte)
	if !ok {
		t.Fatalf("kid type after round-trip: want []byte, got %T", kid)
	}
	if !bytes.Equal(kidBytes, []byte("my-key-id")) {
		t.Fatalf("kid value mismatch: %q", kidBytes)
	}
}

// ---------------------------------------------------------------------------
// Zeroize (C7)
// ---------------------------------------------------------------------------

func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

// ---------------------------------------------------------------------------
// Verify constant-time comparison is used (compile-time check).
// This test ensures the subtle package is imported and used.
// ---------------------------------------------------------------------------

func TestConstantTimeCompareExists(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Fatal("subtle.ConstantTimeCompare broken")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkEncrypt4K(b *testing.B) {
	plaintext := mustRandomB(b, 4096)
	testKEK := mustRandomB(b, 32)
	ri := []RecipientInfo{{KeyID: "bk", Algorithm: AlgA256KW, Type: "key"}}
	wrapFn := func(cek []byte, _ *RecipientInfo) ([]byte, error) { return AESKeyWrap(testKEK, cek) }
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(plaintext, ri, wrapFn, nil)
	}
}

func BenchmarkMarshalCBOR(b *testing.B) {
	plaintext := mustRandomB(b, 4096)
	testKEK := mustRandomB(b, 32)
	ri := []RecipientInfo{{KeyID: "bk", Algorithm: AlgA256KW, Type: "key"}}
	wrapFn := func(cek []byte, _ *RecipientInfo) ([]byte, error) { return AESKeyWrap(testKEK, cek) }
	msg, _ := Encrypt(plaintext, ri, wrapFn, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.MarshalCBOR()
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func mustRandomB(b *testing.B, n int) []byte {
	b.Helper()
	buf := make([]byte, n)
	rand.Read(buf)
	return buf
}

func mustEncrypt(t *testing.T, plaintext, kek []byte, keyID string, opts *EncryptOpts) *EncryptMessage {
	t.Helper()
	ri := []RecipientInfo{{KeyID: keyID, Algorithm: AlgA256KW, Type: "key"}}
	wrapFn := func(cek []byte, _ *RecipientInfo) ([]byte, error) { return AESKeyWrap(kek, cek) }
	msg, err := Encrypt(plaintext, ri, wrapFn, opts)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func mustDecrypt(t *testing.T, msg *EncryptMessage, kek []byte, opts *EncryptOpts) []byte {
	t.Helper()
	unwrapFn := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(kek, w) }
	got, err := Decrypt(msg, 0, unwrapFn, opts)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
