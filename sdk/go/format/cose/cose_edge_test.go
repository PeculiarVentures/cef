package cose

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Edge cases and negative tests (M6 coverage gaps)
// ---------------------------------------------------------------------------

func TestEncryptDecryptSingleBytePayload(t *testing.T) {
	kek := mustRandom(t, 32)
	msg := mustEncrypt(t, []byte{0x42}, kek, "k", nil)
	got := mustDecrypt(t, msg, kek, nil)
	if !bytes.Equal(got, []byte{0x42}) {
		t.Fatal("single byte mismatch")
	}
}

func TestDecryptWithNilCiphertext(t *testing.T) {
	msg := &EncryptMessage{
		Protected:   ProtectedHeader{HeaderAlgorithm: AlgA256GCM},
		Unprotected: UnprotectedHeader{HeaderIV: make([]byte, 12)},
		Ciphertext:  nil,
		Recipients:  []Recipient{{Ciphertext: []byte("fake")}},
	}
	unwrap := func(_ []byte, _ *Recipient) ([]byte, error) { return make([]byte, 32), nil }
	_, err := Decrypt(msg, 0, unwrap, nil)
	if err == nil {
		t.Fatal("expected error decrypting nil ciphertext")
	}
}

func TestDecryptWithWrongIVType(t *testing.T) {
	msg := &EncryptMessage{
		Protected:   ProtectedHeader{HeaderAlgorithm: AlgA256GCM},
		Unprotected: UnprotectedHeader{HeaderIV: "not-bytes"}, // string instead of []byte
		Ciphertext:  []byte("data"),
		Recipients:  []Recipient{{Ciphertext: []byte("fake")}},
	}
	unwrap := func(_ []byte, _ *Recipient) ([]byte, error) { return make([]byte, 32), nil }
	_, err := Decrypt(msg, 0, unwrap, nil)
	if err == nil {
		t.Fatal("expected error for non-byte IV")
	}
}

func TestDecryptWithMissingIV(t *testing.T) {
	msg := &EncryptMessage{
		Protected:   ProtectedHeader{HeaderAlgorithm: AlgA256GCM},
		Unprotected: UnprotectedHeader{}, // no IV
		Ciphertext:  []byte("data"),
		Recipients:  []Recipient{{Ciphertext: []byte("fake")}},
	}
	unwrap := func(_ []byte, _ *Recipient) ([]byte, error) { return make([]byte, 32), nil }
	_, err := Decrypt(msg, 0, unwrap, nil)
	if err == nil {
		t.Fatal("expected error for missing IV")
	}
}

func TestDecryptWithTruncatedCiphertext(t *testing.T) {
	kek := mustRandom(t, 32)
	msg := mustEncrypt(t, []byte("hello world"), kek, "k", nil)

	// Truncate ciphertext (removes GCM tag).
	msg.Ciphertext = msg.Ciphertext[:len(msg.Ciphertext)-5]

	unwrap := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(kek, w) }
	_, err := Decrypt(msg, 0, unwrap, nil)
	if err == nil {
		t.Fatal("expected GCM authentication failure for truncated ciphertext")
	}
}

func TestUnmarshalTruncatedCBOR(t *testing.T) {
	kek := mustRandom(t, 32)
	msg := mustEncrypt(t, []byte("test"), kek, "k", nil)

	data, _ := msg.MarshalCBOR()

	// Truncate at various points.
	for _, truncLen := range []int{0, 1, 5, len(data) / 2, len(data) - 1} {
		var msg2 EncryptMessage
		err := msg2.UnmarshalCBOR(data[:truncLen])
		if err == nil {
			t.Fatalf("expected error for truncated CBOR at %d/%d bytes", truncLen, len(data))
		}
	}
}

func TestUnmarshalWrongTag(t *testing.T) {
	// Create a CBOR tag 99 (not 96) wrapping an array.
	arr := []interface{}{[]byte{}, map[int64]interface{}{}, []byte("ct"), []interface{}{}}
	tagged := cbor.Tag{Number: 99, Content: arr}
	data, _ := cbor.Marshal(tagged)

	var msg EncryptMessage
	err := msg.UnmarshalCBOR(data)
	if err == nil {
		t.Fatal("expected error for wrong CBOR tag")
	}
}

func TestSign1UnmarshalWrongTag(t *testing.T) {
	arr := []interface{}{[]byte{}, map[int64]interface{}{}, []byte("p"), []byte("s")}
	tagged := cbor.Tag{Number: 99, Content: arr}
	data, _ := cbor.Marshal(tagged)

	var msg Sign1Message
	err := msg.UnmarshalCBOR(data)
	if err == nil {
		t.Fatal("expected error for wrong CBOR tag on Sign1")
	}
}

func TestUnmarshalWrongElementCount(t *testing.T) {
	// 3 elements instead of 4.
	arr := []interface{}{[]byte{}, map[int64]interface{}{}, []byte("ct")}
	data, _ := cbor.Marshal(arr)

	var msg EncryptMessage
	if err := msg.UnmarshalCBOR(data); err == nil {
		t.Fatal("expected error for 3-element array")
	}
}

func TestEncryptMultipleRecipientsIndependence(t *testing.T) {
	// Verify that compromising one KEK doesn't compromise other recipients.
	plaintext := []byte("multi-recipient independence test")

	kek1 := mustRandom(t, 32)
	kek2 := mustRandom(t, 32)

	recipients := []RecipientInfo{
		{KeyID: "r1", Algorithm: AlgA256KW, Type: "key"},
		{KeyID: "r2", Algorithm: AlgA256KW, Type: "key"},
	}
	wrapFn := func(cek []byte, ri *RecipientInfo) ([]byte, error) {
		if ri.KeyID == "r1" {
			return AESKeyWrap(kek1, cek)
		}
		return AESKeyWrap(kek2, cek)
	}

	msg, _ := Encrypt(plaintext, recipients, wrapFn, nil)

	// Recipient 1 can decrypt.
	unwrap1 := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(kek1, w) }
	got1, err := Decrypt(msg, 0, unwrap1, nil)
	if err != nil || !bytes.Equal(got1, plaintext) {
		t.Fatal("recipient 1 failed")
	}

	// Recipient 2 can decrypt.
	unwrap2 := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(kek2, w) }
	got2, err := Decrypt(msg, 1, unwrap2, nil)
	if err != nil || !bytes.Equal(got2, plaintext) {
		t.Fatal("recipient 2 failed")
	}

	// Recipient 1's KEK cannot unwrap recipient 2's wrapped CEK.
	unwrapCross := func(w []byte, _ *Recipient) ([]byte, error) { return AESKeyUnwrap(kek1, w) }
	_, err = Decrypt(msg, 1, unwrapCross, nil)
	if err == nil {
		t.Fatal("expected failure: kek1 should not unwrap r2's CEK")
	}
}

// ---------------------------------------------------------------------------
// Interoperability: verify CBOR diagnostic form
// ---------------------------------------------------------------------------

func TestCBORTagValues(t *testing.T) {
	kek := mustRandom(t, 32)
	msg := mustEncrypt(t, []byte("tag test"), kek, "k", nil)

	data, _ := msg.MarshalCBOR()

	// CBOR tag 96 starts with 0xd8 0x60 (tag in 1-byte form: 96 = 0x60).
	if len(data) < 2 || data[0] != 0xd8 || data[1] != 0x60 {
		t.Fatalf("COSE_Encrypt should start with CBOR tag 96 (0xd860), got %x %x", data[0], data[1])
	}

	// Sign1 tag 18 starts with 0xd2 (single byte tag).
	key := mustRandom(t, 32) // dummy
	_ = key
	signFn := func(ss []byte) ([]byte, error) { return mustRandom(t, 64), nil }
	sig, _ := Sign1(AlgES256, "k", []byte("p"), false, signFn)
	sigData, _ := sig.MarshalCBOR()
	if len(sigData) < 1 || sigData[0] != 0xd2 {
		t.Fatalf("COSE_Sign1 should start with CBOR tag 18 (0xd2), got %x", sigData[0])
	}
}

// ---------------------------------------------------------------------------
// RFC 3394 test vector
// ---------------------------------------------------------------------------

func TestAESKeyWrapRFC3394Vector(t *testing.T) {
	// RFC 3394 §4.1: 128-bit KEK, 128-bit key data.
	kek := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	keyData := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	expected := []byte{0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5}

	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, expected) {
		t.Fatalf("RFC 3394 test vector failed:\n  want: %x\n  got:  %x", expected, wrapped)
	}

	unwrapped, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, keyData) {
		t.Fatalf("unwrap mismatch:\n  want: %x\n  got:  %x", keyData, unwrapped)
	}
}

func TestAESKeyWrapRFC3394Vector256(t *testing.T) {
	// RFC 3394 §4.6: 256-bit KEK, 256-bit key data.
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	expected := []byte{
		0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
		0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
		0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
		0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
		0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
	}

	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrapped, expected) {
		t.Fatalf("RFC 3394 §4.6 test vector failed:\n  want: %x\n  got:  %x", expected, wrapped)
	}

	unwrapped, _ := AESKeyUnwrap(kek, wrapped)
	if !bytes.Equal(unwrapped, keyData) {
		t.Fatal("unwrap mismatch")
	}
}
