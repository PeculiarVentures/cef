package exchange

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PeculiarVentures/cef/sdk/go/format/container"
	gcose "github.com/PeculiarVentures/cef/sdk/go/format/cose"
	gcert "github.com/PeculiarVentures/cef/sdk/go/goodkey/cert"
	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

// EncryptFiles encrypts files for the specified recipients using COSE_Encrypt.
func (s *Service) EncryptFiles(ctx context.Context, inputFiles []string, outputPath string, opts *EncryptOptions) (*EncryptResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("options required")
	}
	if len(inputFiles) == 0 {
		return nil, fmt.Errorf("no input files specified")
	}
	if len(opts.Recipients) == 0 && len(opts.RecipientEmails) == 0 && len(opts.RecipientGroups) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}
	if opts.SenderKeyID == "" {
		return nil, fmt.Errorf("sender key ID required")
	}
	if opts.SignatureAlgorithm == ipc.AlgorithmUnspecified {
		sigAlg, err := s.resolveSignAlgorithm(ctx, opts.SenderKeyID)
		if err != nil {
			return nil, fmt.Errorf("resolve signing algorithm: %w", err)
		}
		opts.SignatureAlgorithm = sigAlg
	}
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize // M4
	}

	profile, err := s.client.GetProfile(ctx)
	if err != nil {
		return nil, fmt.Errorf("not authenticated: %w", err)
	}

	// Resolve recipients (M5: dedup by key ID).
	coseRecipients, recipientDetails, pendingRecipients, allKeyIDs, err := s.resolveRecipients(ctx, opts)
	if err != nil {
		return nil, err
	}

	wrapCEK := s.buildWrapFunc(ctx)

	c := container.New()
	c.SetSender(container.SenderInfo{
		KID: opts.SenderKeyID,
		Claims: &container.SenderClaims{
			Email:     profile.Email,
			CreatedAt: time.Now().UTC(),
		},
	})

	for _, ri := range coseRecipients {
		c.AddRecipient(container.RecipientRef{
			KID:  ri.KeyID,
			Type: ri.Type,
		})
	}

	// Encrypt each file.
	for _, inputFile := range inputFiles {
		// Check file size before reading.
		fi, err := os.Stat(inputFile)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", inputFile, err)
		}
		if fi.Size() > maxSize {
			return nil, fmt.Errorf("file %s exceeds maximum size (%d > %d)", inputFile, fi.Size(), maxSize)
		}

		data, err := os.ReadFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", inputFile, err)
		}

		hash := sha256.Sum256(data)
		obfName := randomHex(32) + ".cose"

		encMsg, err := gcose.Encrypt(data, coseRecipients, wrapCEK, nil)
		if err != nil {
			return nil, fmt.Errorf("encrypt %s: %w", inputFile, err)
		}
		encBytes, err := encMsg.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", inputFile, err)
		}

		c.AddFile(obfName, container.FileMetadata{
			OriginalName:  filepath.Base(inputFile),
			Hash:          hash[:],
			HashAlgorithm: container.HashAlgSHA256,
			Size:          int64(len(data)),
		}, encBytes)
	}

	// Encrypt manifest.
	manifestCBOR, err := c.MarshalManifest()
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	encManifest, err := gcose.Encrypt(manifestCBOR, coseRecipients, wrapCEK, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt manifest: %w", err)
	}
	encManifestBytes, err := encManifest.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted manifest: %w", err)
	}
	c.SetEncryptedManifest(encManifestBytes)

	// Create a proper COSE_Sign1 detached signature over the encrypted manifest.
	signFn := func(sigStructure []byte) ([]byte, error) {
		return s.signViaIPC(ctx, opts.SenderKeyID, opts.SignatureAlgorithm, sigStructure)
	}
	coseSignAlg := ipcAlgToCOSE(opts.SignatureAlgorithm)
	sig1, err := gcose.Sign1(coseSignAlg, opts.SenderKeyID, encManifestBytes, true, signFn)
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}
	sigBytes, err := sig1.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}
	c.SetSignature(sigBytes)

	// Set optional timestamp
	if opts.Timestamp != nil {
		c.SetTimestamp(opts.Timestamp)
	}

	if err := c.WriteToFile(outputPath); err != nil {
		return nil, fmt.Errorf("write container: %w", err)
	}

	return &EncryptResult{
		ContainerPath:     outputPath,
		FileCount:         len(inputFiles),
		Recipients:        allKeyIDs,
		Signed:            true,
		Timestamped:       opts.Timestamp != nil,
		PendingRecipients: pendingRecipients,
		RecipientDetails:  recipientDetails,
	}, nil
}

// signViaIPC delegates signing to the GoodKey service.
func (s *Service) signViaIPC(ctx context.Context, keyID string, alg ipc.AlgorithmIdentifier, data []byte) ([]byte, error) {
	op, err := s.client.CreateKeyOperation(ctx, &ipc.CreateKeyOperationRequest{
		KeyID: keyID,
		Type:  string(ipc.OperationTypeSign),
		Name:  alg.String(),
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
		KeyID: keyID, OperationID: op.ID, Data: data,
	})
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// resolveRecipients resolves all recipient types with M5 deduplication.
// Queries key type to set the correct COSE algorithm identifier.
func (s *Service) resolveRecipients(ctx context.Context, opts *EncryptOptions) (
	[]gcose.RecipientInfo, []*ipc.RecipientInfo, []string, []string, error,
) {
	var coseRecipients []gcose.RecipientInfo
	var recipientDetails []*ipc.RecipientInfo
	var pendingRecipients []string
	var allKeyIDs []string

	// Track seen key IDs to prevent duplicates.
	seen := make(map[string]bool)
	addRecipient := func(ri gcose.RecipientInfo) {
		if seen[ri.KeyID] {
			return
		}
		seen[ri.KeyID] = true
		coseRecipients = append(coseRecipients, ri)
		allKeyIDs = append(allKeyIDs, ri.KeyID)
	}

	for _, keyID := range opts.Recipients {
		alg, err := s.resolveKeyAlgorithm(ctx, keyID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("resolve algorithm for %s: %w", keyID, err)
		}
		addRecipient(gcose.RecipientInfo{KeyID: keyID, Algorithm: alg, Type: "key"})
	}

	for _, email := range opts.RecipientEmails {
		info, err := s.client.LookupRecipient(ctx, &ipc.LookupRecipientRequest{
			Email: email, AutoProvision: true,
		})
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("lookup %s: %w", email, err)
		}
		alg, err := s.resolveKeyAlgorithm(ctx, info.KeyID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("resolve algorithm for %s: %w", info.KeyID, err)
		}
		addRecipient(gcose.RecipientInfo{
			KeyID: info.KeyID, Algorithm: alg, Type: "email",
		})
		recipientDetails = append(recipientDetails, info)
		if info.Status == ipc.EnrollmentStatusPending {
			pendingRecipients = append(pendingRecipients, email)
		}
	}

	for _, groupID := range opts.RecipientGroups {
		alg, err := s.resolveKeyAlgorithm(ctx, groupID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("resolve algorithm for %s: %w", groupID, err)
		}
		addRecipient(gcose.RecipientInfo{
			KeyID: groupID, Algorithm: alg, Type: "group",
		})
	}

	// Certificate IDs: look up the certificate to get the bound key ID.
	for _, certID := range opts.RecipientCertIDs {
		cert, err := s.client.GetCertificate(ctx, &ipc.CertificateRequest{ID: certID})
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("certificate %s: %w", certID, err)
		}
		alg, err := s.resolveKeyAlgorithm(ctx, cert.KeyID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("resolve algorithm for %s: %w", cert.KeyID, err)
		}
		addRecipient(gcose.RecipientInfo{KeyID: cert.KeyID, Algorithm: alg, Type: "certificate"})
	}

	// Certificate files: parse PEM, extract public key, use SPKI hash as key ID.
	// In a real deployment, the backend would resolve this. For now, we extract
	// the key and treat it as a direct recipient with the cert's SPKI fingerprint.
	for _, certPath := range opts.RecipientCertFiles {
		pemData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read certificate %s: %w", certPath, err)
		}
		cert, err := gcert.ParsePEM(pemData)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("parse certificate %s: %w", certPath, err)
		}
		// Use the certificate's SubjectKeyIdentifier or SPKI SHA-256 as kid.
		spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("marshal public key from %s: %w", certPath, err)
		}
		kid := fmt.Sprintf("spki-sha256:%x", sha256.Sum256(spkiDER))
		alg := int64(gcose.FallbackKeyWrapAlgorithm) // certificates are classical today
		addRecipient(gcose.RecipientInfo{KeyID: kid, Algorithm: alg, Type: "key"})
	}

	return coseRecipients, recipientDetails, pendingRecipients, allKeyIDs, nil
}

// resolveKeyAlgorithm queries GoodKey for the key type and returns the
// appropriate COSE algorithm identifier for key wrapping.
func (s *Service) resolveKeyAlgorithm(ctx context.Context, keyID string) (int64, error) {
	key, err := s.client.GetKey(ctx, &ipc.KeyRequest{ID: keyID})
	if err != nil {
		return 0, fmt.Errorf("cannot determine key type for %s: %w", keyID, err)
	}
	if key.Type == ipc.KeyTypePQ {
		return gcose.DefaultKeyWrapAlgorithm, nil // ML-KEM-768+A256KW
	}
	return gcose.FallbackKeyWrapAlgorithm, nil // A256KW (classical)
}

// resolveSignAlgorithm queries GoodKey for the key type and returns the
// appropriate IPC algorithm identifier for signing.
func (s *Service) resolveSignAlgorithm(ctx context.Context, keyID string) (ipc.AlgorithmIdentifier, error) {
	key, err := s.client.GetKey(ctx, &ipc.KeyRequest{ID: keyID})
	if err != nil {
		return 0, fmt.Errorf("cannot determine key type for %s: %w", keyID, err)
	}
	switch key.Type {
	case ipc.KeyTypePQ:
		return ipc.ML_DSA_65, nil
	case ipc.KeyTypeEC:
		return ipc.ECDSA_P256_SHA256, nil
	case ipc.KeyTypeED:
		return ipc.ED_25519, nil
	default:
		return 0, fmt.Errorf("unsupported key type %d for signing key %s", key.Type, keyID)
	}
}

// buildWrapFunc creates a CEK wrapping function that delegates to GoodKey.
//
// For ML-KEM keys: fetches the recipient's public key, encapsulates locally
// to produce (cipherText, sharedSecret), derives a KEK from the shared
// secret, and wraps the CEK with AES-KW locally. The COSE_recipient
// ciphertext is cipherText || wrappedCEK.
//
// For classical keys: creates a wrap/decrypt operation on the server.
func (s *Service) buildWrapFunc(ctx context.Context) gcose.WrapCEKFunc {
	return func(cek []byte, ri *gcose.RecipientInfo) ([]byte, error) {
		switch ri.Algorithm {
		case gcose.AlgMLKEM768_A256KW, gcose.AlgMLKEM1024_A256KW:
			return s.mlkemWrap(ctx, cek, ri)
		default:
			return s.classicalWrap(ctx, cek, ri)
		}
	}
}

// mlkemWrap encapsulates locally using the recipient's ML-KEM public key.
// The server never sees the CEK. It only stores the ML-KEM private key
// and performs decapsulation during decrypt.
func (s *Service) mlkemWrap(ctx context.Context, cek []byte, ri *gcose.RecipientInfo) ([]byte, error) {
	// Fetch the recipient's ML-KEM public key (SPKI DER)
	pubResp, err := s.client.GetPublicKey(ctx, &ipc.KeyRequest{ID: ri.KeyID})
	if err != nil {
		return nil, fmt.Errorf("get public key %s: %w", ri.KeyID, err)
	}

	// Parse SPKI to extract raw ML-KEM public key
	rawPK, err := parseSPKIPublicKey(pubResp.Data)
	if err != nil {
		return nil, fmt.Errorf("parse SPKI for %s: %w", ri.KeyID, err)
	}

	// Encapsulate locally
	cipherText, sharedSecret, err := mlkemEncapsulate(rawPK)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM encapsulate for %s: %w", ri.KeyID, err)
	}

	// Derive KEK from shared secret with domain separation
	kek, err := deriveMLKEMKEK(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("derive KEK for %s: %w", ri.KeyID, err)
	}
	defer zeroize(kek)
	defer zeroize(sharedSecret)

	// Wrap CEK locally with AES-KW
	wrappedCEK, err := aesKeyWrap(kek, cek)
	if err != nil {
		return nil, fmt.Errorf("AES-KW wrap for %s: %w", ri.KeyID, err)
	}

	// Return cipherText || wrappedCEK
	result := make([]byte, len(cipherText)+len(wrappedCEK))
	copy(result, cipherText)
	copy(result[len(cipherText):], wrappedCEK)
	return result, nil
}

// classicalWrap delegates CEK wrapping to the GoodKey service for
// classical algorithms (AES-KW, ECDH-ES+A256KW).
func (s *Service) classicalWrap(ctx context.Context, cek []byte, ri *gcose.RecipientInfo) ([]byte, error) {
	wrapName := coseAlgToWrapName(ri.Algorithm)
	op, err := s.client.CreateKeyOperation(ctx, &ipc.CreateKeyOperationRequest{
		KeyID: ri.KeyID,
		Type:  string(ipc.OperationTypeDecrypt),
		Name:  wrapName,
	})
	if err != nil {
		return nil, fmt.Errorf("wrap %s: %w", ri.KeyID, err)
	}
	if op.ApprovalsLeft > 0 {
		op, err = s.waitForApproval(ctx, ri.KeyID, op.ID)
		if err != nil {
			return nil, err
		}
	}
	result, err := s.client.FinalizeKeyOperation(ctx, &ipc.FinalizeKeyOperationRequest{
		KeyID: ri.KeyID, OperationID: op.ID, Data: cek,
	})
	if err != nil {
		return nil, fmt.Errorf("finalize wrap %s: %w", ri.KeyID, err)
	}
	return result.Data, nil
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error()) // pre-condition: CSPRNG must work
	}
	return hex.EncodeToString(b)[:n]
}

// ipcAlgToCOSE maps IPC algorithm identifiers to COSE algorithm identifiers.
func ipcAlgToCOSE(alg ipc.AlgorithmIdentifier) int64 {
	switch alg {
	case ipc.ML_DSA_44:
		return gcose.AlgMLDSA44
	case ipc.ML_DSA_65:
		return gcose.AlgMLDSA65
	case ipc.ML_DSA_87:
		return gcose.AlgMLDSA87
	case ipc.ECDSA_P256_SHA256:
		return gcose.AlgES256
	case ipc.ECDSA_P384_SHA384:
		return gcose.AlgES384
	case ipc.ED_25519:
		return gcose.AlgEdDSA
	default:
		return gcose.DefaultSignatureAlgorithm
	}
}

// coseAlgToWrapName maps a COSE key wrap algorithm ID to the operation name
// sent to GoodKey for wrap operations.
func coseAlgToWrapName(coseAlg int64) string {
	switch coseAlg {
	case gcose.AlgMLKEM768_A256KW:
		return "ML-KEM-768-A256KW"
	case gcose.AlgMLKEM1024_A256KW:
		return "ML-KEM-1024-A256KW"
	case gcose.AlgA256KW:
		return "AES-256-WRAP"
	case gcose.AlgECDH_ES_A256KW:
		return "ECDH-ES-A256KW"
	default:
		return "AES-256-WRAP"
	}
}
