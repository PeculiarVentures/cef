package cose

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/PeculiarVentures/cef/sdk/go/format/container"
	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Interoperability Test Vectors
//
// These tests use fixed keys, IVs, and plaintexts to produce deterministic
// CBOR output. Any conforming implementation of the CEF COSE profile MUST
// produce identical COSE_Encrypt and COSE_Sign1 structures for these inputs.
//
// The test vectors can be extracted as hex dumps for use in other languages
// (Python, Rust, JavaScript) by running:
//
//   go test -v -run TestVector ./pkg/cose/
//
// ---------------------------------------------------------------------------

// Fixed test materials (DO NOT use these keys in production).
var (
	vectorKEK = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	vectorCEK = mustHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	vectorIV  = mustHex("000102030405060708090a0b")

	vectorPlaintext = []byte("CEF test vector payload.")
	vectorKeyID     = "test-vector-key-001"
)

// TestVectorAESKeyWrap verifies AES Key Wrap with a fixed CEK and KEK.
// Third-party implementations MUST produce the same wrapped output.
func TestVectorAESKeyWrap(t *testing.T) {
	wrapped, err := AESKeyWrap(vectorKEK, vectorCEK)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("=== AES-256 Key Wrap Test Vector ===")
	t.Logf("KEK:         %x", vectorKEK)
	t.Logf("Plaintext:   %x", vectorCEK)
	t.Logf("Wrapped CEK: %x", wrapped)
	t.Logf("Wrapped len: %d bytes", len(wrapped))

	// Verify unwrap.
	unwrapped, err := AESKeyUnwrap(vectorKEK, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, vectorCEK) {
		t.Fatal("unwrap mismatch")
	}
}

// TestVectorCOSEEncryptStructure verifies the COSE_Encrypt CBOR structure
// using a fixed CEK, IV, and plaintext. Since AES-GCM is deterministic for
// a given (key, nonce, plaintext, AAD), the output is reproducible.
//
// This test manually constructs the COSE_Encrypt to bypass random CEK/IV
// generation and verify the exact CBOR encoding.
func TestVectorCOSEEncryptStructure(t *testing.T) {
	// Step 1: Build protected header {1: 3} (A256GCM).
	protectedMap := map[int64]interface{}{HeaderAlgorithm: AlgA256GCM}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Protected header (CBOR): %x", protectedBytes)

	// Step 2: Build Enc_structure for AAD.
	aad, err := buildEncStructure(protectedBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Enc_structure (AAD):     %x", aad)

	// Step 3: Encrypt with fixed key and IV.
	ciphertext, err := encryptAESGCM(vectorCEK, vectorIV, vectorPlaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Ciphertext:              %x", ciphertext)
	t.Logf("Ciphertext len:          %d bytes (plaintext: %d, overhead: %d)",
		len(ciphertext), len(vectorPlaintext), len(ciphertext)-len(vectorPlaintext))

	// Step 4: Wrap CEK.
	wrappedCEK, err := AESKeyWrap(vectorKEK, vectorCEK)
	if err != nil {
		t.Fatal(err)
	}

	// Step 5: Build COSE_recipient.
	recipientProtected, _ := cbor.Marshal(map[int64]interface{}{HeaderAlgorithm: AlgA256KW})

	// Step 6: Assemble COSE_Encrypt.
	msg := &EncryptMessage{
		Protected:   ProtectedHeader{HeaderAlgorithm: AlgA256GCM},
		Unprotected: UnprotectedHeader{HeaderIV: vectorIV},
		Ciphertext:  ciphertext,
		Recipients: []Recipient{{
			Protected:   ProtectedHeader{HeaderAlgorithm: AlgA256KW},
			Unprotected: UnprotectedHeader{HeaderKeyID: []byte(vectorKeyID)},
			Ciphertext:  wrappedCEK,
		}},
	}

	cborData, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("")
	t.Logf("=== COSE_Encrypt Test Vector ===")
	t.Logf("Plaintext:    %q", vectorPlaintext)
	t.Logf("CEK:          %x", vectorCEK)
	t.Logf("IV:           %x", vectorIV)
	t.Logf("KEK:          %x", vectorKEK)
	t.Logf("Key ID:       %q", vectorKeyID)
	t.Logf("CBOR (hex):   %x", cborData)
	t.Logf("CBOR length:  %d bytes", len(cborData))

	// Step 7: Verify the CBOR starts with tag 96 (0xd8 0x60).
	if len(cborData) < 2 || cborData[0] != 0xd8 || cborData[1] != 0x60 {
		t.Fatalf("expected CBOR tag 96, got %x %x", cborData[0], cborData[1])
	}

	// Step 8: Verify round-trip.
	var msg2 EncryptMessage
	if err := msg2.UnmarshalCBOR(cborData); err != nil {
		t.Fatal(err)
	}

	// Step 9: Decrypt.
	unwrapFn := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(vectorKEK, w) }
	decrypted, err := Decrypt(&msg2, 0, unwrapFn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, vectorPlaintext) {
		t.Fatal("decrypted plaintext mismatch")
	}

	// Log the recipient protected header for interop verification.
	t.Logf("Recipient protected:  %x", recipientProtected)
	t.Logf("Wrapped CEK:          %x", wrappedCEK)
}

// TestVectorCOSESign1Structure verifies the COSE_Sign1 CBOR structure
// with a fixed payload. The signature itself is non-deterministic (ECDSA
// uses random k), so we verify the Sig_structure is correct and the
// serialization format is valid.
func TestVectorCOSESign1Structure(t *testing.T) {
	payload := []byte("CEF Sign1 test vector payload.")
	keyID := "test-signer-key"

	// Build the Sig_structure that would be signed.
	protectedMap := map[int64]interface{}{HeaderAlgorithm: AlgES256}
	protectedBytes, _ := cbor.Marshal(protectedMap)

	sigStructure, err := buildSigStructure(protectedBytes, nil, payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("=== COSE_Sign1 Test Vector (Sig_structure only) ===")
	t.Logf("Payload:         %q", payload)
	t.Logf("Protected:       %x", protectedBytes)
	t.Logf("Sig_structure:   %x", sigStructure)
	t.Logf("Sig_struct len:  %d bytes", len(sigStructure))
	t.Logf("Key ID:          %q", keyID)
	t.Logf("")
	t.Logf("To verify interop: compute the Sig_structure from the same inputs")
	t.Logf("and confirm the hex matches. Then sign with your ECDSA P-256 key")
	t.Logf("and verify the COSE_Sign1 structure round-trips correctly.")

	// Create a Sign1 with a dummy signature (for structure verification).
	dummySig := bytes.Repeat([]byte{0xAA}, 64) // Fixed 64-byte dummy.
	msg := &Sign1Message{
		Protected:   ProtectedHeader{HeaderAlgorithm: AlgES256},
		Unprotected: UnprotectedHeader{HeaderKeyID: []byte(keyID)},
		Payload:     payload,
		Signature:   dummySig,
	}

	cborData, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("COSE_Sign1 CBOR (dummy sig): %x", cborData)
	t.Logf("COSE_Sign1 length:           %d bytes", len(cborData))

	// Verify tag 18 (0xd2).
	if cborData[0] != 0xd2 {
		t.Fatalf("expected CBOR tag 18 (0xd2), got %x", cborData[0])
	}

	// Verify round-trip.
	var msg2 Sign1Message
	if err := msg2.UnmarshalCBOR(cborData); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg2.Payload, payload) {
		t.Fatal("payload mismatch")
	}
	if !bytes.Equal(msg2.Signature, dummySig) {
		t.Fatal("signature mismatch")
	}
}

// TestVectorEncStructure verifies the Enc_structure AAD computation
// produces a deterministic output for given protected header bytes.
func TestVectorEncStructure(t *testing.T) {
	// A256GCM protected header: {1: 3}
	protectedBytes, _ := cbor.Marshal(map[int64]interface{}{int64(1): int64(3)})

	aad, err := buildEncStructure(protectedBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("=== Enc_structure Test Vector ===")
	t.Logf("Protected header: %x", protectedBytes)
	t.Logf("Enc_structure:    %x", aad)
	t.Logf("Enc_struct len:   %d bytes", len(aad))

	// Verify this is a valid CBOR array: ["Encrypt", h'...', h'']
	var arr []interface{}
	if err := cbor.Unmarshal(aad, &arr); err != nil {
		t.Fatalf("Enc_structure is not valid CBOR: %v", err)
	}
	if len(arr) != 3 {
		t.Fatalf("Enc_structure should have 3 elements, got %d", len(arr))
	}
	if arr[0] != "Encrypt" {
		t.Fatalf("context should be 'Encrypt', got %v", arr[0])
	}
}

// TestVectorSigStructure verifies the Sig_structure1 computation.
func TestVectorSigStructure(t *testing.T) {
	protectedBytes, _ := cbor.Marshal(map[int64]interface{}{int64(1): int64(-7)})
	payload := []byte("test payload")

	sigStruct, err := buildSigStructure(protectedBytes, nil, payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("=== Sig_structure1 Test Vector ===")
	t.Logf("Protected: %x", protectedBytes)
	t.Logf("Payload:   %x", payload)
	t.Logf("SigStruct: %x", sigStruct)

	var arr []interface{}
	if err := cbor.Unmarshal(sigStruct, &arr); err != nil {
		t.Fatal(err)
	}
	if arr[0] != "Signature1" {
		t.Fatalf("context should be 'Signature1', got %v", arr[0])
	}
}

// ---------------------------------------------------------------------------
// Manifest CBOR interop vector
// ---------------------------------------------------------------------------

func TestVectorManifestCBOR(t *testing.T) {
	// Verify manifest CBOR via the Container API to ensure
	// deterministic encoding and current CDDL compliance.
	c := container.New()
	c.SetSender(container.SenderInfo{
		KID: "key-sign-p256",
		Claims: &container.SenderClaims{
			Email:     "alice@example.com",
			CreatedAt: time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		},
	})
	c.AddRecipient(container.RecipientRef{KID: "key-encrypt-001", Type: "key"})
	c.AddRecipient(container.RecipientRef{
		KID: "eng-team-key", Type: "group",
		Claims: &container.RecipientClaims{GroupID: "eng-team"},
	})
	c.AddFile("a1b2c3d4.cose", container.FileMetadata{
		OriginalName:  "report.pdf",
		Hash:          mustHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		HashAlgorithm: container.HashAlgSHA256,
		Size:          1024,
	}, nil)

	data, err := c.MarshalManifest()
	if err != nil {
		t.Fatal(err)
	}

	expected := "a46776657273696f6e61306566696c6573a16d61316232633364342e636f7365a46d6f726967696e616c5f6e616d656a7265706f72742e70646664686173685820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8556e686173685f616c676f726974686d2f6473697a651904006673656e646572a2636b69646d6b65792d7369676e2d7032353666636c61696d73a265656d61696c71616c696365406578616d706c652e636f6d6a637265617465645f61741a69c7c2c06a726563697069656e747382a2636b69646f6b65792d656e63727970742d3030316474797065636b6579a3636b69646c656e672d7465616d2d6b657964747970656567726f757066636c61696d73a16867726f75705f696468656e672d7465616d"

	actual := hex.EncodeToString(data)
	if actual != expected {
		t.Errorf("manifest CBOR mismatch\n  actual:   %s\n  expected: %s", actual, expected)
	}

	t.Logf("Manifest CBOR: %d bytes", len(data))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
