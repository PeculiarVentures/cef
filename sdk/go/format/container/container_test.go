package container

import (
	"bytes"
	"testing"
)

func TestNewContainer(t *testing.T) {
	c := New()
	if c.Manifest.Version != FormatVersion {
		t.Errorf("version: want %s, got %s", FormatVersion, c.Manifest.Version)
	}
}

func TestManifestCBOR(t *testing.T) {
	c := New()
	c.SetSender(SenderInfo{KID: "key-alice", Claims: &SenderClaims{Email: "alice@example.com"}})
	c.AddRecipient(RecipientRef{KID: "key-bob", Type: "email", Claims: &RecipientClaims{Email: "bob@example.com"}})
	c.AddRecipient(RecipientRef{KID: "grp-eng-key", Type: "group", Claims: &RecipientClaims{GroupID: "grp-eng"}})

	hash := make([]byte, 32)
	for i := range hash { hash[i] = byte(i) }
	c.AddFile("abc.cose", FileMetadata{
		OriginalName: "report.pdf", Hash: hash, HashAlgorithm: HashAlgSHA256, Size: 1024, ContentType: "application/pdf",
	}, nil)

	data, err := c.MarshalManifest()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CBOR manifest: %d bytes", len(data))

	c2 := New()
	if err := c2.UnmarshalManifest(data); err != nil {
		t.Fatal(err)
	}

	if c2.Manifest.Sender.Claims == nil || c2.Manifest.Sender.Claims.Email != "alice@example.com" {
		t.Error("sender claims email mismatch")
	}
	if len(c2.Manifest.Recipients) != 2 {
		t.Fatal("recipient count mismatch")
	}
	fm := c2.Manifest.Files["abc.cose"]
	if fm.OriginalName != "report.pdf" {
		t.Error("original name mismatch")
	}
	if !bytes.Equal(fm.Hash, hash) {
		t.Error("hash mismatch")
	}
}

func TestContainerZIP(t *testing.T) {
	c := New()
	c.SetEncryptedManifest([]byte("enc-manifest"))
	c.SetSignature([]byte("sig-bytes"))
	c.EncryptedFiles["f1.cose"] = []byte("enc-file-1")
	c.EncryptedFiles["f2.cose"] = []byte("enc-file-2")

	data, err := c.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Container ZIP: %d bytes", len(data))

	c2, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(c2.EncryptedManifest, []byte("enc-manifest")) {
		t.Error("manifest mismatch")
	}
	if !bytes.Equal(c2.ManifestSignature, []byte("sig-bytes")) {
		t.Error("signature mismatch")
	}
	if len(c2.EncryptedFiles) != 2 {
		t.Fatalf("want 2 files, got %d", len(c2.EncryptedFiles))
	}
}

func TestContainerFile(t *testing.T) {
	c := New()
	c.SetEncryptedManifest([]byte("test"))
	c.EncryptedFiles["x.cose"] = []byte("data")

	path := t.TempDir() + "/test.cef"
	if err := c.WriteToFile(path); err != nil {
		t.Fatal(err)
	}

	c2, err := ReadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2.EncryptedManifest, []byte("test")) {
		t.Error("manifest mismatch after file round-trip")
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	c := New()
	c.SetEncryptedManifest([]byte("enc-manifest"))
	c.SetSignature([]byte("sig-bytes"))
	c.SetTimestamp([]byte("mock-rfc3161-timestamp-token"))
	c.EncryptedFiles["f1.cose"] = []byte("enc-file")

	data, err := c.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	c2, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(c2.Timestamp, []byte("mock-rfc3161-timestamp-token")) {
		t.Error("timestamp mismatch")
	}
}

func TestTimestampAbsent(t *testing.T) {
	c := New()
	c.SetEncryptedManifest([]byte("enc-manifest"))
	c.EncryptedFiles["f1.cose"] = []byte("enc-file")

	data, err := c.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	c2, err := FromBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	if c2.Timestamp != nil {
		t.Error("timestamp should be nil when not set")
	}
	if c2.ManifestSignature != nil {
		t.Error("signature should be nil when not set")
	}
}

func TestTimestampFileRoundTrip(t *testing.T) {
	c := New()
	c.SetEncryptedManifest([]byte("manifest"))
	c.SetSignature([]byte("sig"))
	c.SetTimestamp([]byte("timestamp-token"))

	path := t.TempDir() + "/ts.cef"
	if err := c.WriteToFile(path); err != nil {
		t.Fatal(err)
	}

	c2, err := ReadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(c2.Timestamp, []byte("timestamp-token")) {
		t.Error("timestamp mismatch after file round-trip")
	}
}

func TestX5CClaimsExclusivity(t *testing.T) {
	fakeCert := []byte{0x30, 0x82, 0x01, 0x00}

	c := New()

	// Sender has BOTH x5c and claims — MarshalManifest should drop claims
	c.SetSender(SenderInfo{
		KID:    "cert-signer",
		X5C:    [][]byte{fakeCert},
		Claims: &SenderClaims{Email: "should-be-dropped@test.com"},
	})

	// Recipient 0: has x5c → claims should be dropped
	c.AddRecipient(RecipientRef{
		KID:    "cert-bob",
		Type:   "certificate",
		X5C:    [][]byte{fakeCert},
		Claims: &RecipientClaims{Email: "dropped@test.com"},
	})

	// Recipient 1: no x5c → claims should be preserved
	c.AddRecipient(RecipientRef{
		KID:    "key-carol",
		Type:   "key",
		Claims: &RecipientClaims{Email: "kept@test.com"},
	})

	data, err := c.MarshalManifest()
	if err != nil {
		t.Fatal(err)
	}

	c2 := New()
	if err := c2.UnmarshalManifest(data); err != nil {
		t.Fatal(err)
	}

	// Sender: x5c present → claims should be nil
	if len(c2.Manifest.Sender.X5C) != 1 {
		t.Error("sender x5c should have 1 cert")
	}
	if c2.Manifest.Sender.Claims != nil {
		t.Errorf("sender claims should be nil when x5c present, got %+v", c2.Manifest.Sender.Claims)
	}

	// Recipient 0: x5c present → claims should be nil
	if c2.Manifest.Recipients[0].Claims != nil {
		t.Errorf("recipient 0 claims should be nil when x5c present, got %+v", c2.Manifest.Recipients[0].Claims)
	}
	if len(c2.Manifest.Recipients[0].X5C) != 1 {
		t.Error("recipient 0 x5c should have 1 cert")
	}

	// Recipient 1: no x5c → claims preserved
	if c2.Manifest.Recipients[1].Claims == nil || c2.Manifest.Recipients[1].Claims.Email != "kept@test.com" {
		t.Error("recipient 1 claims should be preserved")
	}
	if c2.Manifest.Recipients[1].X5C != nil {
		t.Error("recipient 1 x5c should be nil")
	}
}

func TestCertificateRecipientNoClaimsNeeded(t *testing.T) {
	fakeCert := []byte{0x30, 0x82, 0x02, 0x00}

	c := New()
	c.SetSender(SenderInfo{KID: "signer", X5C: [][]byte{fakeCert}})
	c.AddRecipient(RecipientRef{KID: "cert-r", Type: "certificate", X5C: [][]byte{fakeCert}})

	data, err := c.MarshalManifest()
	if err != nil {
		t.Fatal(err)
	}

	c2 := New()
	if err := c2.UnmarshalManifest(data); err != nil {
		t.Fatal(err)
	}

	if c2.Manifest.Sender.Claims != nil {
		t.Error("sender claims should be nil")
	}
	if c2.Manifest.Recipients[0].Claims != nil {
		t.Error("recipient claims should be nil")
	}
}
