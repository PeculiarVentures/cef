package exchange

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PeculiarVentures/cef/sdk/go/format/container"
	gcose "github.com/PeculiarVentures/cef/sdk/go/format/cose"
	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

// DecryptContainer decrypts a .cef container.
func (s *Service) DecryptContainer(ctx context.Context, containerPath string, opts *DecryptOptions) (*DecryptResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("options required")
	}
	if opts.RecipientKeyID == "" {
		return nil, fmt.Errorf("recipient key ID required")
	}
	if opts.OutputDir == "" {
		return nil, fmt.Errorf("output directory required")
	}

	c, err := container.ReadFromFile(containerPath)
	if err != nil {
		return nil, fmt.Errorf("read container: %w", err)
	}
	if c.EncryptedManifest == nil {
		return nil, fmt.Errorf("container has no encrypted manifest")
	}

	unwrapCEK := s.buildUnwrapFunc(ctx, opts.RecipientKeyID)

	// Decrypt manifest.
	var encManifestMsg gcose.EncryptMessage
	if err := encManifestMsg.UnmarshalCBOR(c.EncryptedManifest); err != nil {
		return nil, fmt.Errorf("parse encrypted manifest: %w", err)
	}

	recipientIdx, err := findRecipientIndex(&encManifestMsg, opts.RecipientKeyID)
	if err != nil {
		return nil, fmt.Errorf("find recipient: %w", err)
	}

	manifestCBOR, err := gcose.Decrypt(&encManifestMsg, recipientIdx, unwrapCEK, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}

	if err := c.UnmarshalManifest(manifestCBOR); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	// Reject unrecognized major versions per spec §8.1.
	if c.Manifest.Version != "0" {
		return nil, fmt.Errorf("unsupported manifest version: %s (expected 0)", c.Manifest.Version)
	}

	// Verify COSE_Sign1 signature unless explicitly skipped.
	signatureValid := false
	verifySignature := !opts.SkipSignatureVerification
	if verifySignature && len(c.ManifestSignature) > 0 {
		var sig1 gcose.Sign1Message
		if err := sig1.UnmarshalCBOR(c.ManifestSignature); err != nil {
			return nil, fmt.Errorf("parse signature: %w", err)
		}

		// Extract signer key ID from the signature's unprotected header.
		signerKeyID := ""
		if kidRaw, ok := sig1.Unprotected[gcose.HeaderKeyID]; ok {
			if kid, ok := kidRaw.([]byte); ok {
				signerKeyID = string(kid)
			}
		}

		// Extract algorithm from COSE_Sign1 protected header.
		algName := ipc.ML_DSA_65.String()
		if algRaw, ok := sig1.Protected[gcose.HeaderAlgorithm]; ok {
			switch gcose.ToInt64(algRaw) {
			case gcose.AlgMLDSA44:
				algName = ipc.ML_DSA_44.String()
			case gcose.AlgMLDSA65:
				algName = ipc.ML_DSA_65.String()
			case gcose.AlgMLDSA87:
				algName = ipc.ML_DSA_87.String()
			case gcose.AlgES256:
				algName = ipc.ECDSA_P256_SHA256.String()
			case gcose.AlgES384:
				algName = ipc.ECDSA_P384_SHA384.String()
			case gcose.AlgEdDSA:
				algName = ipc.ED_25519.String()
			}
		}

		// Verify: delegate to GoodKey service.
		verifyFn := func(sigStructure, signature []byte) error {
			return s.verifyViaIPC(ctx, signerKeyID, algName, sigStructure, signature)
		}

		if err := gcose.Verify1(&sig1, c.EncryptedManifest, verifyFn); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
		signatureValid = true
	}

	// Create output directory with owner-only permissions.
	if err := os.MkdirAll(opts.OutputDir, 0700); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	// Verify output directory is not a symlink.
	dirInfo, err := os.Lstat(opts.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("stat output dir: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("output directory %s is a symlink", opts.OutputDir)
	}

	// Decrypt each file.
	var decryptedFiles []DecryptedFile
	for obfName, metadata := range c.Manifest.Files {
		encryptedData, ok := c.EncryptedFiles[obfName]
		if !ok {
			return nil, fmt.Errorf("missing encrypted file: %s", obfName)
		}

		var fileMsg gcose.EncryptMessage
		if err := fileMsg.UnmarshalCBOR(encryptedData); err != nil {
			return nil, fmt.Errorf("parse file %s: %w", metadata.OriginalName, err)
		}

		fileIdx, err := findRecipientIndex(&fileMsg, opts.RecipientKeyID)
		if err != nil {
			return nil, fmt.Errorf("find recipient in %s: %w", metadata.OriginalName, err)
		}

		decryptedData, err := gcose.Decrypt(&fileMsg, fileIdx, unwrapCEK, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", metadata.OriginalName, err)
		}

		hash := sha256.Sum256(decryptedData)
		hashValid := subtle.ConstantTimeCompare(hash[:], metadata.Hash) == 1

		// Refuse to write files with invalid hashes unless explicitly opted in.
		if !hashValid && !opts.AllowInvalidHash {
			return nil, fmt.Errorf("hash mismatch for %s: file integrity check failed", metadata.OriginalName)
		}

		// Path traversal protection — strip directory components.
		safeName := filepath.Base(metadata.OriginalName)
		if safeName == "." || safeName == ".." || strings.ContainsAny(safeName, `/\`) {
			safeName = obfName // Fall back to obfuscated name.
		}

		outputPath := filepath.Join(opts.OutputDir, safeName)

		// Verify output path is not a symlink before writing.
		if fi, err := os.Lstat(outputPath); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("output path %s is a symlink", outputPath)
			}
		}

		// Write decrypted files with owner-only permissions.
		if err := os.WriteFile(outputPath, decryptedData, 0600); err != nil {
			return nil, fmt.Errorf("write %s: %w", outputPath, err)
		}

		decryptedFiles = append(decryptedFiles, DecryptedFile{
			OriginalName: metadata.OriginalName,
			OutputPath:   outputPath,
			Size:         int64(len(decryptedData)),
			HashValid:    hashValid,
		})
	}

	return &DecryptResult{
		Files:            decryptedFiles,
		ManifestValid:    true,
		SignatureValid:   signatureValid,
		TimestampPresent: c.Timestamp != nil,
		SenderKID: c.Manifest.Sender.KID,
		SenderClaimsEmail: senderClaimsEmail(c.Manifest.Sender),
	}, nil
}

// verifyViaIPC verifies a signature by fetching the signer's public
// key from GoodKey and verifying locally. The server does not have a
// dedicated "verify" operation type; verification only needs the
// public half of the signing key.
func (s *Service) verifyViaIPC(ctx context.Context, keyID, algName string, sigStructure, signature []byte) error {
	if keyID == "" {
		return fmt.Errorf("signer key ID not found in COSE_Sign1 header")
	}

	// Fetch the signer's public key
	pubResp, err := s.client.GetPublicKey(ctx, &ipc.KeyRequest{ID: keyID})
	if err != nil {
		return fmt.Errorf("get public key for verify: %w", err)
	}

	// Verify locally using the public key
	return verifySignature(algName, pubResp.Data, sigStructure, signature)
}

// buildUnwrapFunc creates a CEK unwrap function.
//
// For ML-KEM keys: sends the ML-KEM ciphertext to the server as a
// "derive" operation. The server decapsulates and returns the shared
// secret. The SDK derives the KEK locally and unwraps the CEK with
// AES-KW locally.
//
// For classical keys: sends the wrapped CEK to the server as a
// "decrypt" operation.
func (s *Service) buildUnwrapFunc(ctx context.Context, recipientKeyID string) gcose.UnwrapCEKFunc {
	return func(wrappedData []byte, r *gcose.Recipient) ([]byte, error) {
		alg := int64(gcose.AlgA256KW) // fallback
		if algRaw, ok := r.Protected[gcose.HeaderAlgorithm]; ok {
			alg = gcose.ToInt64(algRaw)
		}

		switch alg {
		case gcose.AlgMLKEM768_A256KW, gcose.AlgMLKEM1024_A256KW:
			return s.mlkemUnwrap(ctx, recipientKeyID, alg, wrappedData)
		default:
			return s.classicalUnwrap(ctx, recipientKeyID, alg, wrappedData)
		}
	}
}

// mlkemUnwrap sends the ML-KEM ciphertext to the server for decapsulation,
// then derives the KEK and unwraps the CEK locally.
func (s *Service) mlkemUnwrap(ctx context.Context, keyID string, alg int64, wrappedData []byte) ([]byte, error) {
	// Split cipherText || wrappedCEK
	ctLen := 1088 // ML-KEM-768 ciphertext length
	if alg == gcose.AlgMLKEM1024_A256KW {
		ctLen = 1568 // ML-KEM-1024
	}
	if len(wrappedData) <= ctLen {
		return nil, fmt.Errorf("ML-KEM wrapped data too short (%d bytes, need >%d)", len(wrappedData), ctLen)
	}

	cipherText := wrappedData[:ctLen]
	wrappedCEK := wrappedData[ctLen:]

	// Determine the algorithm name the server expects
	algName := "ML_KEM_768"
	if alg == gcose.AlgMLKEM1024_A256KW {
		algName = "ML_KEM_1024"
	}

	// Send cipherText to server as a derive operation.
	// The ML-KEM ciphertext goes in the Parameters map, matching the real
	// GoodKey server's KeyOperationCreateParams.CipherText field.
	import_b64url := base64.RawURLEncoding.EncodeToString(cipherText)
	op, err := s.client.CreateKeyOperation(ctx, &ipc.CreateKeyOperationRequest{
		KeyID: keyID,
		Type:  string(ipc.OperationTypeDerive),
		Name:  algName,
		Parameters: map[string]string{
			"cipherText": import_b64url,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ML-KEM derive %s: %w", keyID, err)
	}
	if op.ApprovalsLeft > 0 {
		op, err = s.waitForApproval(ctx, keyID, op.ID)
		if err != nil {
			return nil, err
		}
	}

	// Finalize; server returns shared secret
	result, err := s.client.FinalizeKeyOperation(ctx, &ipc.FinalizeKeyOperationRequest{
		KeyID: keyID, OperationID: op.ID, Data: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("ML-KEM decapsulate %s: %w", keyID, err)
	}

	sharedSecret := result.Data
	defer zeroize(sharedSecret)

	// Derive KEK from shared secret with domain separation
	kek, err := deriveMLKEMKEK(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("derive KEK: %w", err)
	}
	defer zeroize(kek)

	// Unwrap CEK locally with AES-KW
	return aesKeyUnwrap(kek, wrappedCEK)
}

// classicalUnwrap delegates CEK unwrapping to the GoodKey service.
func (s *Service) classicalUnwrap(ctx context.Context, keyID string, alg int64, wrappedCEK []byte) ([]byte, error) {
	unwrapName := coseAlgToUnwrapName(alg)
	op, err := s.client.CreateKeyOperation(ctx, &ipc.CreateKeyOperationRequest{
		KeyID: keyID,
		Type:  string(ipc.OperationTypeDecrypt),
		Name:  unwrapName,
	})
	if err != nil {
		return nil, err
	}
	if op.ApprovalsLeft > 0 {
		op, err = s.waitForApproval(ctx, keyID, op.ID)
		if err != nil {
			return nil, err
		}
	}
	result, err := s.client.FinalizeKeyOperation(ctx, &ipc.FinalizeKeyOperationRequest{
		KeyID: keyID, OperationID: op.ID, Data: wrappedCEK,
	})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// coseAlgToUnwrapName maps a COSE key wrap algorithm ID to the operation name
// sent to GoodKey for classical unwrap operations.
func coseAlgToUnwrapName(coseAlg int64) string {
	switch coseAlg {
	case gcose.AlgA256KW:
		return "AES-256-UNWRAP"
	case gcose.AlgECDH_ES_A256KW:
		return "ECDH-ES-A256KW"
	default:
		return "AES-256-UNWRAP"
	}
}

// findRecipientIndex finds the COSE_Encrypt recipient matching a key ID.
// Handles both []byte and string types after CBOR round-trip.
func findRecipientIndex(msg *gcose.EncryptMessage, keyID string) (int, error) {
	keyIDBytes := []byte(keyID)

	for i, r := range msg.Recipients {
		kidRaw, ok := r.Unprotected[gcose.HeaderKeyID]
		if !ok {
			continue
		}
		switch kid := kidRaw.(type) {
		case []byte:
			if subtle.ConstantTimeCompare(kid, keyIDBytes) == 1 {
				return i, nil
			}
		case string:
			if kid == keyID {
				return i, nil
			}
		}
	}

	return -1, fmt.Errorf("no recipient with key ID %q", keyID)
}

// waitForApproval polls for operation approval.
func (s *Service) waitForApproval(ctx context.Context, keyID, operationID string) (*ipc.KeyOperationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("approval timeout")
		default:
		}

		op, err := s.client.GetKeyOperation(ctx, &ipc.GetKeyOperationRequest{
			KeyID: keyID, OperationID: operationID,
		})
		if err != nil {
			return nil, err
		}

		switch op.Status {
		case string(ipc.OperationStatusApproved), string(ipc.OperationStatusCompleted):
			return op, nil
		case string(ipc.OperationStatusCancelled), string(ipc.OperationStatusFailed):
			msg := op.Status
			if op.Error != "" {
				msg += ": " + op.Error
			}
			return nil, fmt.Errorf("operation %s", msg)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// senderClaimsEmail extracts the email claim from sender info, if present.
func senderClaimsEmail(s container.SenderInfo) string {
	if s.Claims != nil {
		return s.Claims.Email
	}
	return ""
}
