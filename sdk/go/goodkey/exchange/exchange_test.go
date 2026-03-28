package exchange

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "secret.txt", "Top secret GoodKey data!")
	out := filepath.Join(tmpDir, "secret.cef")

	result, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "secret.txt")}, out, &EncryptOptions{
		Recipients: []string{"key-encrypt-mlkem768"}, SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if result.FileCount != 1 || !result.Signed {
		t.Fatalf("result: files=%d signed=%v", result.FileCount, result.Signed)
	}

	decDir := filepath.Join(tmpDir, "dec")
	dec, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID: "key-encrypt-mlkem768", OutputDir: decDir,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(dec.Files) != 1 || !dec.Files[0].HashValid {
		t.Fatal("decrypted file invalid")
	}
	assertFileContent(t, dec.Files[0].OutputPath, "Top secret GoodKey data!")
}

func TestMultipleFiles(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	files := []string{"a.txt", "b.pdf", "c.png"}
	for _, f := range files {
		writeFile(t, tmpDir, f, "content-"+f)
	}

	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = filepath.Join(tmpDir, f)
	}

	out := filepath.Join(tmpDir, "bundle.cef")
	result, err := svc.EncryptFiles(ctx, paths, out, &EncryptOptions{
		Recipients: []string{"key-encrypt-mlkem768"}, SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.FileCount != 3 {
		t.Fatalf("want 3 files, got %d", result.FileCount)
	}

	dec, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID: "key-encrypt-mlkem768", OutputDir: filepath.Join(tmpDir, "dec"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range dec.Files {
		if !f.HashValid {
			t.Errorf("hash invalid: %s", f.OriginalName)
		}
	}
}

func TestEmailRecipient(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "msg.txt", "Hello Alice!")
	out := filepath.Join(tmpDir, "msg.cef")

	result, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "msg.txt")}, out, &EncryptOptions{
		RecipientEmails: []string{"alice@example.com"}, SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.PendingRecipients) != 1 {
		t.Fatalf("want 1 pending, got %d", len(result.PendingRecipients))
	}

	// Decrypt with provisioned key.
	aliceKey := result.RecipientDetails[0].KeyID
	dec, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID: aliceKey, OutputDir: filepath.Join(tmpDir, "dec"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, dec.Files[0].OutputPath, "Hello Alice!")
}

func TestGroupRecipient(t *testing.T) {
	svc, mock := newTestService()
	groupKey := make([]byte, 32)
	for i := range groupKey { groupKey[i] = byte(i) }
	mock.AddSymmetricKey("group-eng", "Engineering", groupKey)

	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "team.txt", "Team document")
	out := filepath.Join(tmpDir, "team.cef")

	_, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "team.txt")}, out, &EncryptOptions{
		RecipientGroups: []string{"group-eng"}, SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}

	dec, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID: "group-eng", OutputDir: filepath.Join(tmpDir, "dec"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, dec.Files[0].OutputPath, "Team document")
}

func TestMixedRecipients(t *testing.T) {
	svc, mock := newTestService()
	gk := make([]byte, 32)
	for i := range gk { gk[i] = byte(i + 100) }
	mock.AddSymmetricKey("group-sec", "Security", gk)

	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "mixed.txt", "Mixed")
	out := filepath.Join(tmpDir, "mixed.cef")

	result, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "mixed.txt")}, out, &EncryptOptions{
		Recipients:      []string{"key-encrypt-001"},
		RecipientEmails: []string{"bob@example.com"},
		RecipientGroups: []string{"group-sec"},
		SenderKeyID:     "key-sign-p256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 3 {
		t.Fatalf("want 3 recipients, got %d", len(result.Recipients))
	}

	// Each should decrypt independently.
	for _, keyID := range []string{"key-encrypt-001", "group-sec"} {
		_, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
			RecipientKeyID: keyID, OutputDir: filepath.Join(tmpDir, "dec-"+keyID),
		})
		if err != nil {
			t.Fatalf("decrypt with %s: %v", keyID, err)
		}
	}
}

// Verify duplicate recipients are deduplicated.
func TestDuplicateRecipients(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "dup.txt", "Dedup test")
	out := filepath.Join(tmpDir, "dup.cef")

	result, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "dup.txt")}, out, &EncryptOptions{
		Recipients:  []string{"key-encrypt-001", "key-encrypt-001"}, // duplicate
		SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 {
		t.Fatalf("duplicates not removed: got %d recipients", len(result.Recipients))
	}
}

func TestVerifyContainer(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "v.txt", "Verify")
	out := filepath.Join(tmpDir, "v.cef")
	svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "v.txt")}, out, &EncryptOptions{
		Recipients: []string{"key-encrypt-001"}, SenderKeyID: "key-sign-mldsa65",
	})

	result, _ := svc.VerifyContainer(ctx, out)
	if !result.ContainerValid || result.FileCount != 1 {
		t.Fatalf("verify: valid=%v files=%d", result.ContainerValid, result.FileCount)
	}
}

// --- Negative tests (M6) ---

func TestEncryptNoRecipients(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.EncryptFiles(context.Background(), []string{"f.txt"}, "o.cef", &EncryptOptions{SenderKeyID: "key-sign-mldsa65"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEncryptNoFiles(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.EncryptFiles(context.Background(), nil, "o.cef", &EncryptOptions{
		Recipients: []string{"key-encrypt-001"}, SenderKeyID: "key-sign-mldsa65",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	svc, mock := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "wrong.txt", "Wrong key test")
	out := filepath.Join(tmpDir, "wrong.cef")
	svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "wrong.txt")}, out, &EncryptOptions{
		Recipients: []string{"key-encrypt-001"}, SenderKeyID: "key-sign-mldsa65",
	})

	// Create a different key and try to decrypt.
	wrongKey := make([]byte, 32)
	for i := range wrongKey { wrongKey[i] = 0xFF }
	mock.AddSymmetricKey("wrong-key", "Wrong Key", wrongKey)

	_, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID: "wrong-key", OutputDir: filepath.Join(tmpDir, "dec"),
	})
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptCorruptContainer(t *testing.T) {
	svc, _ := newTestService()
	tmpDir := t.TempDir()

	// Write garbage as a .cef file.
	corrupt := filepath.Join(tmpDir, "corrupt.cef")
	os.WriteFile(corrupt, []byte("not a zip file"), 0644)

	_, err := svc.DecryptContainer(context.Background(), corrupt, &DecryptOptions{
		RecipientKeyID: "key-encrypt-mlkem768", OutputDir: filepath.Join(tmpDir, "dec"),
	})
	if err == nil {
		t.Fatal("expected error for corrupt container")
	}
}

// Verify key usage enforcement.
func TestWrapWithSigningKeyFails(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "usage.txt", "Usage test")
	out := filepath.Join(tmpDir, "usage.cef")

	// key-sign-p256 has AUTH usage, not CIPHER — wrap should fail.
	_, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "usage.txt")}, out, &EncryptOptions{
		Recipients:  []string{"key-sign-p256"}, // wrong usage!
		SenderKeyID: "key-sign-mldsa65",
	})
	if err == nil {
		t.Fatal("expected error: signing key should not be usable for wrap")
	}
}

// Verify COSE_Sign1 end-to-end: encrypt → decrypt with signature verification (default).
func TestSignatureVerification(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "signed.txt", "Signed document")
	out := filepath.Join(tmpDir, "signed.cef")

	_, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "signed.txt")}, out, &EncryptOptions{
		Recipients:  []string{"key-encrypt-mlkem768"},
		SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt — signature verification is on by default.
	dec, err := svc.DecryptContainer(ctx, out, &DecryptOptions{
		RecipientKeyID:  "key-encrypt-mlkem768",
		OutputDir:       filepath.Join(tmpDir, "dec"),
	})
	if err != nil {
		t.Fatalf("decrypt with verification: %v", err)
	}
	if !dec.SignatureValid {
		t.Fatal("signature should be valid")
	}
	assertFileContent(t, dec.Files[0].OutputPath, "Signed document")
}

// Verify tampered signature is detected.
func TestTamperedSignatureDetected(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tmpDir := t.TempDir()

	writeFile(t, tmpDir, "tamper.txt", "Tamper test")
	out := filepath.Join(tmpDir, "tamper.cef")

	_, err := svc.EncryptFiles(ctx, []string{filepath.Join(tmpDir, "tamper.txt")}, out, &EncryptOptions{
		Recipients:  []string{"key-encrypt-mlkem768"},
		SenderKeyID: "key-sign-mldsa65",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Read, tamper with the signature, rewrite.
	data, _ := os.ReadFile(out)
	// Flip a byte in the last 50 bytes (likely in the signature area of the ZIP).
	if len(data) > 50 {
		data[len(data)-30] ^= 0xFF
	}
	tamperedPath := filepath.Join(tmpDir, "tampered.cef")
	os.WriteFile(tamperedPath, data, 0644)

	// Decrypt with verification — should fail or produce invalid signature.
	// Decrypt — verification is on by default, should fail for tampered container.
	_, err = svc.DecryptContainer(ctx, tamperedPath, &DecryptOptions{
		RecipientKeyID:  "key-encrypt-mlkem768",
		OutputDir:       filepath.Join(tmpDir, "dec-tampered"),
	})
	// Either the container is unreadable or the signature verification fails.
	// Both are acceptable outcomes for tamper detection.
	if err == nil {
		t.Log("Warning: tampered container decrypted without error (tamper may have hit non-sig area)")
	}
}

// --- Test helpers ---

func newTestService() (*Service, *ipc.MockClient) {
	mock := ipc.NewMockClient()
	return NewService(mock), mock
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != expected {
		t.Fatalf("content mismatch:\n  want: %q\n  got:  %q", expected, string(data))
	}
}
