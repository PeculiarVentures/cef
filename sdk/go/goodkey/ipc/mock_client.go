package ipc

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	gkxcrypto "github.com/PeculiarVentures/cef/sdk/go/format/crypto"

	// Post-quantum cryptography via Cloudflare CIRCL (FIPS 203/204).
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MockClient implements CEFServiceClient for testing.
// It holds keys in memory and performs cryptographic operations locally
// using CIRCL for post-quantum algorithms.
var _ CEFServiceClient = (*MockClient)(nil)
type MockClient struct {
	mu                sync.Mutex
	Profile           *ProfileResponse
	Keys              []*KeyResponse
	Certificates      []*CertificateResponse
	CertificateData   map[string][]byte
	Operations        map[string]*KeyOperationResponse
	OperationParams   map[string]map[string]string // opID -> parameters from create
	PrivateKeys       map[string]*rsa.PrivateKey
	CryptoKeys        map[string]crypto.PrivateKey
	ECDHKeys          map[string]*ecdh.PrivateKey
	SymmetricKeys     map[string][]byte
	PendingRecipients map[string]*RecipientInfo

	// Post-quantum keys (FIPS 203/204).
	MLKEMPrivateKeys map[string]*mlkem768.PrivateKey
	MLKEMPublicKeys  map[string]*mlkem768.PublicKey
	MLDSAPrivateKeys map[string]*mldsa65.PrivateKey
	MLDSAPublicKeys  map[string]*mldsa65.PublicKey

	RequireApproval bool
	ApprovalDelay   time.Duration
	nextOpID        int
}

// NewMockClient creates a mock client with default PQ and classical keys.
func NewMockClient() *MockClient {
	m := &MockClient{
		Profile: &ProfileResponse{
			ID: "user-123", Email: "test@example.com",
			FirstName: "Test", LastName: "User",
			Token: &ProfileToken{
				Type: "bearer", ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
				Origin: "https://goodkey.example.com", OrgID: "org-456",
			},
			Organization: &OrganizationResponse{ID: "org-456", Name: "Test Organization"},
		},
		Keys: []*KeyResponse{}, Certificates: []*CertificateResponse{},
		CertificateData: make(map[string][]byte), Operations: make(map[string]*KeyOperationResponse),
		OperationParams: make(map[string]map[string]string),
		PrivateKeys: make(map[string]*rsa.PrivateKey), CryptoKeys: make(map[string]crypto.PrivateKey),
		ECDHKeys: make(map[string]*ecdh.PrivateKey), SymmetricKeys: make(map[string][]byte),
		PendingRecipients: make(map[string]*RecipientInfo),
		MLKEMPrivateKeys:  make(map[string]*mlkem768.PrivateKey),
		MLKEMPublicKeys:   make(map[string]*mlkem768.PublicKey),
		MLDSAPrivateKeys:  make(map[string]*mldsa65.PrivateKey),
		MLDSAPublicKeys:   make(map[string]*mldsa65.PublicKey),
	}

	// --- Post-quantum keys (DEFAULT) ---

	// ML-DSA-65 signing key (FIPS 204, ~192-bit PQ security).
	m.generateMLDSAKey("key-sign-mldsa65", "Signing Key (ML-DSA-65)")

	// ML-KEM-768 encryption key (FIPS 203, ~192-bit PQ security).
	// ML-KEM produces a shared secret; we derive a symmetric KEK from it
	// for AES Key Wrap. In the mock, we pre-generate the keypair and
	// simulate encapsulate/decapsulate on wrap/unwrap.
	m.generateMLKEMKey("key-encrypt-mlkem768", "Encryption Key (ML-KEM-768)")

	// --- Classical keys (backward compatibility) ---

	m.generateECDSAKey("key-sign-p256", "Signing Key (P-256)", elliptic.P256(), []KeyUsage{KeyUsageAuth})
	m.generateEd25519Key("key-sign-ed25519", "Signing Key (Ed25519)", []KeyUsage{KeyUsageAuth})
	m.generateRSAKey("key-sign-rsa", "Signing Key (RSA-2048)", 2048, []KeyUsage{KeyUsageAuth})
	m.generateSymmetricKey("key-encrypt-001", "Encryption Key (AES-256)", []KeyUsage{KeyUsageCipher})
	m.generateSymmetricKey("key-encrypt-002", "Encryption Key (Alt)", []KeyUsage{KeyUsageCipher})
	m.generateECDHKey("key-ecdh-p256", "Key Agreement (P-256)", ecdh.P256(), []KeyUsage{KeyUsageExchange})

	return m
}

// --- Post-quantum key generation ---

func (m *MockClient) generateMLDSAKey(id, name string) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("ML-DSA-65 keygen failed: %v", err))
	}
	m.MLDSAPrivateKeys[id] = priv
	m.MLDSAPublicKeys[id] = pub
	m.Keys = append(m.Keys, &KeyResponse{
		ID: id, Name: name, Type: KeyTypePQ, Status: KeyStatusActive,
		Size: 256, Usages: []KeyUsage{KeyUsageAuth},
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	})
}

func (m *MockClient) generateMLKEMKey(id, name string) {
	pub, priv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("ML-KEM-768 keygen failed: %v", err))
	}
	m.MLKEMPrivateKeys[id] = priv
	m.MLKEMPublicKeys[id] = pub
	m.Keys = append(m.Keys, &KeyResponse{
		ID: id, Name: name, Type: KeyTypePQ, Status: KeyStatusActive,
		Size: 768, Usages: []KeyUsage{KeyUsageCipher},
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	})
}

// --- Classical key generation (unchanged) ---

func (m *MockClient) generateSymmetricKey(id, name string, usages []KeyUsage) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	m.SymmetricKeys[id] = key
	m.Keys = append(m.Keys, &KeyResponse{
		ID: id, Name: name, Status: KeyStatusActive, Size: 256, Usages: usages,
		CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
	})
}

func (m *MockClient) generateRSAKey(id, name string, bits int, usages []KeyUsage) {
	pk, _ := rsa.GenerateKey(rand.Reader, bits)
	m.PrivateKeys[id] = pk
	m.CryptoKeys[id] = pk
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Test Organization"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m.addKeyMeta(id, name, KeyTypeRSA, int32(bits), usages, "cert-"+id, certPEM)
}

func (m *MockClient) generateECDSAKey(id, name string, curve elliptic.Curve, usages []KeyUsage) {
	pk, _ := ecdsa.GenerateKey(curve, rand.Reader)
	m.CryptoKeys[id] = pk
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Test Organization"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m.addKeyMeta(id, name, KeyTypeEC, int32(curve.Params().BitSize), usages, "cert-"+id, certPEM)
}

func (m *MockClient) generateEd25519Key(id, name string, usages []KeyUsage) {
	pub, pk, _ := ed25519.GenerateKey(rand.Reader)
	m.CryptoKeys[id] = pk
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name, Organization: []string{"Test Organization"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, pk)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	m.addKeyMeta(id, name, KeyTypeED, 256, usages, "cert-"+id, certPEM)
}

func (m *MockClient) generateECDHKey(id, name string, curve ecdh.Curve, usages []KeyUsage) {
	pk, _ := curve.GenerateKey(rand.Reader)
	m.ECDHKeys[id] = pk
	size := int32(256)
	if curve == ecdh.P384() { size = 384 }
	m.Keys = append(m.Keys, &KeyResponse{
		ID: id, Name: name, Type: KeyTypeECDH, Status: KeyStatusActive, Size: size, Usages: usages,
		CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
	})
}

func (m *MockClient) addKeyMeta(keyID, name string, keyType KeyType, size int32, usages []KeyUsage, certID string, certPEM []byte) {
	found := false
	for _, k := range m.Keys { if k.ID == keyID { found = true; break } }
	if !found {
		m.Keys = append(m.Keys, &KeyResponse{
			ID: keyID, Name: name, Type: keyType, Status: KeyStatusActive, Size: size, Usages: usages,
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		})
	}
	if certPEM != nil {
		m.Certificates = append(m.Certificates, &CertificateResponse{
			ID: certID, Name: name + " Certificate", Type: CertificateTypeX509,
			Status: CertificateStatusActive, KeyID: keyID,
			CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
		})
		m.CertificateData[certID] = certPEM
	}
}

// --- GoodKeyServiceClient implementation ---

func (m *MockClient) Close() error { return nil }
func (m *MockClient) GetProfile(ctx context.Context) (*ProfileResponse, error) { return m.Profile, nil }

func (m *MockClient) GetKeys(ctx context.Context, req *KeyFilterRequest) (*KeyListResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	var result []*KeyShortResponse
	for _, key := range m.Keys {
		if req.Status != KeyStatusUnspecified && key.Status != req.Status { continue }
		if req.Type != KeyTypeUnspecified && key.Type != req.Type { continue }
		if req.Usage != KeyUsageUnspecified {
			if !hasUsage(key.Usages, req.Usage) { continue }
		}
		result = append(result, &KeyShortResponse{
			ID: key.ID, Name: key.Name, Type: key.Type, Status: key.Status, Size: key.Size, Usages: key.Usages,
		})
	}
	return &KeyListResponse{Keys: result}, nil
}

func (m *MockClient) GetKey(ctx context.Context, req *KeyRequest) (*KeyResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, key := range m.Keys { if key.ID == req.ID { return key, nil } }
	return nil, fmt.Errorf("key not found: %s", req.ID)
}

func (m *MockClient) CreateKeyOperation(ctx context.Context, req *CreateKeyOperationRequest) (*KeyOperationResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()

	var keyResp *KeyResponse
	for _, key := range m.Keys { if key.ID == req.KeyID { keyResp = key; break } }
	if keyResp == nil { return nil, fmt.Errorf("key not found: %s", req.KeyID) }

	// Validate key usage.
	opType := OperationType(req.Type)
	switch opType {
	case OperationTypeSign:
		if !hasUsage(keyResp.Usages, KeyUsageAuth) {
			return nil, fmt.Errorf("key %s does not have AUTH usage for %s", req.KeyID, req.Type)
		}
	case OperationTypeDecrypt, OperationTypeDerive:
		if !hasUsage(keyResp.Usages, KeyUsageCipher) && !hasUsage(keyResp.Usages, KeyUsageExchange) {
			return nil, fmt.Errorf("key %s does not have CIPHER/EXCHANGE usage for %s", req.KeyID, req.Type)
		}
	}

	m.nextOpID++
	opID := fmt.Sprintf("op-%d", m.nextOpID)
	status := string(OperationStatusApproved)
	approvalsLeft := int32(0)
	if m.RequireApproval {
		status = string(OperationStatusPending)
		approvalsLeft = 1
	}
	op := &KeyOperationResponse{
		ID: opID, Type: req.Type, Name: req.Name, KeyID: req.KeyID, Status: status,
		ApprovalsLeft: approvalsLeft,
		CreatedAt: time.Now().Format(time.RFC3339), UpdatedAt: time.Now().Format(time.RFC3339),
	}
	m.Operations[opID] = op
	if req.Parameters != nil {
		m.OperationParams[opID] = req.Parameters
	}
	if m.RequireApproval && m.ApprovalDelay > 0 {
		go func() {
			time.Sleep(m.ApprovalDelay)
			m.mu.Lock()
			if o, ok := m.Operations[opID]; ok { o.Status = string(OperationStatusApproved); o.ApprovalsLeft = 0 }
			m.mu.Unlock()
		}()
	}
	return op, nil
}

func (m *MockClient) GetKeyOperation(ctx context.Context, req *GetKeyOperationRequest) (*KeyOperationResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	op, ok := m.Operations[req.OperationID]
	if !ok { return nil, fmt.Errorf("operation not found: %s", req.OperationID) }
	return op, nil
}

func (m *MockClient) CancelKeyOperation(ctx context.Context, req *CancelKeyOperationRequest) (*KeyOperationResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	op, ok := m.Operations[req.OperationID]
	if !ok { return nil, fmt.Errorf("operation not found: %s", req.OperationID) }
	op.Status = string(OperationStatusCancelled)
	return op, nil
}

func (m *MockClient) FinalizeKeyOperation(ctx context.Context, req *FinalizeKeyOperationRequest) (*FinalizeKeyOperationResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()

	op, ok := m.Operations[req.OperationID]
	if !ok { return nil, fmt.Errorf("operation not found: %s", req.OperationID) }
	if op.Status != string(OperationStatusApproved) {
		return nil, fmt.Errorf("operation not approved: %s", op.Status)
	}

	var result []byte
	var err error

	switch OperationType(op.Type) {
	case OperationTypeSign:
		result, err = m.performSign(req.KeyID, req.Data)
	case OperationTypeDecrypt:
		result, err = m.performDecrypt(req.KeyID, req.Data)
	case OperationTypeDerive:
		// ML-KEM: ciphertext is in the operation parameters (from create), not finalize data
		params := m.OperationParams[req.OperationID]
		result, err = m.performDerive(req.KeyID, op.Name, params)
	default:
		return nil, fmt.Errorf("unsupported operation type: %s", op.Type)
	}

	if err != nil { return nil, fmt.Errorf("%s failed: %w", op.Type, err) }
	op.Status = string(OperationStatusCompleted)
	return &FinalizeKeyOperationResponse{Operation: op, Data: result}, nil
}

// --- Cryptographic operations ---

func (m *MockClient) performSign(keyID string, data []byte) ([]byte, error) {
	// ML-DSA-65 (post-quantum).
	if priv, ok := m.MLDSAPrivateKeys[keyID]; ok {
		sig := make([]byte, mldsa65.SignatureSize)
		err := mldsa65.SignTo(priv, data, nil, false, sig)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 sign: %w", err)
		}
		return sig, nil
	}

	// Classical algorithms.
	hash := sha256.Sum256(data)
	if rsaKey, ok := m.PrivateKeys[keyID]; ok {
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	}
	if key, ok := m.CryptoKeys[keyID]; ok {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, hash[:])
		case *ecdsa.PrivateKey:
			return ecdsa.SignASN1(rand.Reader, k, hash[:])
		case ed25519.PrivateKey:
			return ed25519.Sign(k, data), nil
		}
	}
	return nil, fmt.Errorf("signing key not found: %s", keyID)
}

func (m *MockClient) performDerive(keyID string, algName string, params map[string]string) ([]byte, error) {
	// ML-KEM decapsulation: returns the shared secret.
	if priv, ok := m.MLKEMPrivateKeys[keyID]; ok {
		ctB64, ok := params["cipherText"]
		if !ok {
			return nil, fmt.Errorf("ML-KEM derive: cipherText parameter required")
		}
		cipherText, err := base64.RawURLEncoding.DecodeString(ctB64)
		if err != nil {
			return nil, fmt.Errorf("ML-KEM derive: decode cipherText: %w", err)
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		priv.DecapsulateTo(ss, cipherText)
		return ss, nil
	}

	// ECDH derive (classical key agreement)
	if key, ok := m.CryptoKeys[keyID]; ok {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			pubB64, ok := params["public"]
			if !ok {
				return nil, fmt.Errorf("ECDH derive: public parameter required")
			}
			pubData, err := base64.RawURLEncoding.DecodeString(pubB64)
			if err != nil {
				return nil, fmt.Errorf("ECDH derive: decode public: %w", err)
			}
			ourPrivate, err := ecdsaKey.ECDH()
			if err != nil {
				return nil, err
			}
			curve := ecdh.P256()
			if ecdsaKey.Curve == elliptic.P384() {
				curve = ecdh.P384()
			}
			theirPublic, err := curve.NewPublicKey(pubData)
			if err != nil {
				return nil, err
			}
			shared, err := ourPrivate.ECDH(theirPublic)
			if err != nil {
				return nil, err
			}
			return shared, nil
		}
	}

	return nil, fmt.Errorf("derive key not found: %s", keyID)
}

func (m *MockClient) performDecrypt(keyID string, data []byte) ([]byte, error) {
	// Symmetric key wrap/unwrap (for group keys, direct KEKs)
	if kek, ok := m.SymmetricKeys[keyID]; ok {
		// Try unwrap first (data is wrapped CEK)
		result, err := gkxcrypto.AESKeyUnwrap(kek, data)
		if err != nil {
			// Fall back to wrap (data is plaintext CEK)
			return gkxcrypto.AESKeyWrap(kek, data)
		}
		return result, nil
	}

	// RSA decryption
	if rsaKey, ok := m.PrivateKeys[keyID]; ok {
		return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, data)
	}
	if key, ok := m.CryptoKeys[keyID]; ok {
		if k, ok := key.(*rsa.PrivateKey); ok {
			return rsa.DecryptPKCS1v15(rand.Reader, k, data)
		}
	}
	return nil, fmt.Errorf("decryption key not found: %s", keyID)
}

// GetPublicKey returns the SPKI-encoded public key for the given key ID.
// All key types return SPKI DER, matching the real GoodKey server behavior.
func (m *MockClient) GetPublicKey(ctx context.Context, req *KeyRequest) (*PublicKeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// ML-KEM public keys (SPKI with OID 2.16.840.1.101.3.4.4.2)
	if pub, ok := m.MLKEMPublicKeys[req.ID]; ok {
		raw, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		spki := buildPQSPKI(oidMLKEM768, raw)
		return &PublicKeyResponse{Data: spki}, nil
	}

	// ML-DSA public keys (SPKI with OID 2.16.840.1.101.3.4.3.18)
	if pub, ok := m.MLDSAPublicKeys[req.ID]; ok {
		spki := buildPQSPKI(oidMLDSA65, pub.Bytes())
		return &PublicKeyResponse{Data: spki}, nil
	}

	// Classical keys (SPKI DER via Go stdlib)
	if key, ok := m.CryptoKeys[req.ID]; ok {
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				return nil, err
			}
			return &PublicKeyResponse{Data: spki}, nil
		case ed25519.PrivateKey:
			spki, err := x509.MarshalPKIXPublicKey(k.Public())
			if err != nil {
				return nil, err
			}
			return &PublicKeyResponse{Data: spki}, nil
		}
	}

	if rsaKey, ok := m.PrivateKeys[req.ID]; ok {
		spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return nil, err
		}
		return &PublicKeyResponse{Data: spki}, nil
	}

	return nil, fmt.Errorf("key not found: %s", req.ID)
}

// OIDs for PQ algorithms (matching the GoodKey server's @peculiar/asn1-schema OIDs)
var (
	// 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
	oidMLDSA65 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	// 2.16.840.1.101.3.4.4.2 (ML-KEM-768)
	oidMLKEM768 = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02}
)

// buildPQSPKI constructs an ASN.1 SPKI structure for PQ public keys,
// matching the encoding the real GoodKey server produces via
// @peculiar/asn1-schema's SubjectPublicKeyInfo.
func buildPQSPKI(oid, rawPubKey []byte) []byte {
	// AlgorithmIdentifier: SEQUENCE { OID }
	oidEncoded := make([]byte, 0, 2+len(oid))
	oidEncoded = append(oidEncoded, 0x06) // OID tag
	oidEncoded = append(oidEncoded, byte(len(oid)))
	oidEncoded = append(oidEncoded, oid...)

	algId := make([]byte, 0, 2+len(oidEncoded))
	algId = append(algId, 0x30) // SEQUENCE tag
	algId = append(algId, byte(len(oidEncoded)))
	algId = append(algId, oidEncoded...)

	// BIT STRING: tag, length, 0x00 (unused bits), raw key
	bsContent := make([]byte, 0, 1+len(rawPubKey))
	bsContent = append(bsContent, 0x00) // unused bits
	bsContent = append(bsContent, rawPubKey...)

	bitString := make([]byte, 0, 4+len(bsContent))
	bitString = append(bitString, 0x03) // BIT STRING tag
	bitString = appendDERLength(bitString, len(bsContent))
	bitString = append(bitString, bsContent...)

	// Outer SEQUENCE
	inner := append(algId, bitString...)
	result := make([]byte, 0, 4+len(inner))
	result = append(result, 0x30) // SEQUENCE tag
	result = appendDERLength(result, len(inner))
	result = append(result, inner...)
	return result
}

func appendDERLength(buf []byte, length int) []byte {
	if length < 0x80 {
		return append(buf, byte(length))
	}
	if length < 0x100 {
		return append(buf, 0x81, byte(length))
	}
	return append(buf, 0x82, byte(length>>8), byte(length))
}

// --- Certificate management ---

func (m *MockClient) GetCertificates(ctx context.Context) (*CertificateListResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	var items []*CertificateShortResponse
	for _, c := range m.Certificates {
		items = append(items, &CertificateShortResponse{ID: c.ID, Name: c.Name, Type: c.Type, KeyID: c.KeyID})
	}
	return &CertificateListResponse{Items: items}, nil
}

func (m *MockClient) GetCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, c := range m.Certificates { if c.ID == req.ID { return c, nil } }
	return nil, fmt.Errorf("certificate not found: %s", req.ID)
}

func (m *MockClient) GetCertificateRaw(ctx context.Context, req *CertificateRequest) (*CertificateRawResponse, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	data, ok := m.CertificateData[req.ID]
	if !ok { return nil, fmt.Errorf("certificate not found: %s", req.ID) }
	return &CertificateRawResponse{Data: data}, nil
}

// --- Recipient lookup ---

func (m *MockClient) LookupRecipient(ctx context.Context, req *LookupRecipientRequest) (*RecipientInfo, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	if req.Email == "" { return nil, fmt.Errorf("email is required") }

	// Enrolled user — returns PQ key by default.
	if req.Email == m.Profile.Email {
		return &RecipientInfo{Email: req.Email, Status: EnrollmentStatusEnrolled, KeyID: "key-encrypt-mlkem768"}, nil
	}

	if existing, ok := m.PendingRecipients[req.Email]; ok { return existing, nil }
	if !req.AutoProvision { return &RecipientInfo{Email: req.Email, Status: EnrollmentStatusInvited}, nil }

	// Provision ML-KEM-768 key for pending user.
	keyID := fmt.Sprintf("pending-key-%s", hashEmail(req.Email))
	pub, priv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil { return nil, fmt.Errorf("ML-KEM keygen: %w", err) }
	m.MLKEMPrivateKeys[keyID] = priv
	m.MLKEMPublicKeys[keyID] = pub
	m.Keys = append(m.Keys, &KeyResponse{
		ID: keyID, Name: fmt.Sprintf("Pending Key for %s", req.Email),
		Type: KeyTypePQ, Status: KeyStatusActive, Size: 768, Usages: []KeyUsage{KeyUsageCipher},
	})

	now := time.Now(); expires := now.AddDate(0, 0, 30)
	info := &RecipientInfo{
		Email: req.Email, Status: EnrollmentStatusPending,
		KeyID: keyID, ProvisionedAt: &now, ExpiresAt: &expires,
	}
	m.PendingRecipients[req.Email] = info
	return info, nil
}

func (m *MockClient) LookupRecipients(ctx context.Context, req *LookupRecipientsRequest) (*LookupRecipientsResponse, error) {
	resp := &LookupRecipientsResponse{Recipients: make([]*RecipientInfo, 0), Errors: make(map[string]string)}
	for _, email := range req.Emails {
		info, err := m.LookupRecipient(ctx, &LookupRecipientRequest{
			Email: email, AutoProvision: req.AutoProvision, SendInvitation: req.SendInvitation,
		})
		if err != nil { resp.Errors[email] = err.Error(); continue }
		resp.Recipients = append(resp.Recipients, info)
	}
	return resp, nil
}

// --- Test helpers ---

func hasUsage(usages []KeyUsage, target KeyUsage) bool {
	for _, u := range usages { if u == target { return true } }
	return false
}

func (m *MockClient) SetApprovalRequired(required bool, delay time.Duration) {
	m.mu.Lock(); defer m.mu.Unlock()
	m.RequireApproval = required; m.ApprovalDelay = delay
}

func (m *MockClient) ApproveOperation(opID string) error {
	m.mu.Lock(); defer m.mu.Unlock()
	op, ok := m.Operations[opID]; if !ok { return fmt.Errorf("not found") }
	op.Status = string(OperationStatusApproved); op.ApprovalsLeft = 0; return nil
}

// AddSymmetricKey adds a classical symmetric key for testing.
func (m *MockClient) AddSymmetricKey(id, name string, key []byte) {
	m.mu.Lock(); defer m.mu.Unlock()
	m.SymmetricKeys[id] = key
	m.Keys = append(m.Keys, &KeyResponse{
		ID: id, Name: name, Status: KeyStatusActive, Size: int32(len(key) * 8), Usages: []KeyUsage{KeyUsageCipher},
	})
}

func hashEmail(email string) string {
	h := sha256.Sum256([]byte(email))
	return fmt.Sprintf("%x", h[:8])
}

