// Package ipc provides types for communicating with the local GoodKey service via gRPC.
// These types mirror the protobuf definitions from the GoodKey local service.
package ipc

// AlgorithmIdentifier represents supported cryptographic algorithms.
type AlgorithmIdentifier int32

const (
	AlgorithmUnspecified        AlgorithmIdentifier = 0
	SHA1                        AlgorithmIdentifier = 1
	SHA256                      AlgorithmIdentifier = 2
	SHA384                      AlgorithmIdentifier = 3
	SHA512                      AlgorithmIdentifier = 4
	RSASSA_PKCS1_2048_SHA1      AlgorithmIdentifier = 5
	RSASSA_PKCS1_2048_SHA256    AlgorithmIdentifier = 6
	RSASSA_PKCS1_2048_SHA384    AlgorithmIdentifier = 7
	RSASSA_PKCS1_2048_SHA512    AlgorithmIdentifier = 8
	RSASSA_PKCS1_3072_SHA1      AlgorithmIdentifier = 9
	RSASSA_PKCS1_3072_SHA256    AlgorithmIdentifier = 10
	RSASSA_PKCS1_3072_SHA384    AlgorithmIdentifier = 11
	RSASSA_PKCS1_3072_SHA512    AlgorithmIdentifier = 12
	RSASSA_PKCS1_4096_SHA1      AlgorithmIdentifier = 13
	RSASSA_PKCS1_4096_SHA256    AlgorithmIdentifier = 14
	RSASSA_PKCS1_4096_SHA384    AlgorithmIdentifier = 15
	RSASSA_PKCS1_4096_SHA512    AlgorithmIdentifier = 16
	RSAES_PKCS1_2048            AlgorithmIdentifier = 17
	RSAES_PKCS1_3072            AlgorithmIdentifier = 18
	RSAES_PKCS1_4096            AlgorithmIdentifier = 19
	RSA_PSS_2048_SHA1           AlgorithmIdentifier = 20
	RSA_PSS_2048_SHA256         AlgorithmIdentifier = 21
	RSA_PSS_2048_SHA384         AlgorithmIdentifier = 22
	RSA_PSS_2048_SHA512         AlgorithmIdentifier = 23
	RSA_PSS_3072_SHA1           AlgorithmIdentifier = 24
	RSA_PSS_3072_SHA256         AlgorithmIdentifier = 25
	RSA_PSS_3072_SHA384         AlgorithmIdentifier = 26
	RSA_PSS_3072_SHA512         AlgorithmIdentifier = 27
	RSA_PSS_4096_SHA1           AlgorithmIdentifier = 28
	RSA_PSS_4096_SHA256         AlgorithmIdentifier = 29
	RSA_PSS_4096_SHA384         AlgorithmIdentifier = 30
	RSA_PSS_4096_SHA512         AlgorithmIdentifier = 31
	RSA_OAEP_2048_SHA1          AlgorithmIdentifier = 32
	RSA_OAEP_2048_SHA256        AlgorithmIdentifier = 33
	RSA_OAEP_2048_SHA384        AlgorithmIdentifier = 34
	RSA_OAEP_2048_SHA512        AlgorithmIdentifier = 35
	RSA_OAEP_3072_SHA1          AlgorithmIdentifier = 36
	RSA_OAEP_3072_SHA256        AlgorithmIdentifier = 37
	RSA_OAEP_3072_SHA384        AlgorithmIdentifier = 38
	RSA_OAEP_3072_SHA512        AlgorithmIdentifier = 39
	RSA_OAEP_4096_SHA1          AlgorithmIdentifier = 40
	RSA_OAEP_4096_SHA256        AlgorithmIdentifier = 41
	RSA_OAEP_4096_SHA384        AlgorithmIdentifier = 42
	RSA_OAEP_4096_SHA512        AlgorithmIdentifier = 43
	ECDSA_P256_SHA1             AlgorithmIdentifier = 44
	ECDSA_P256_SHA256           AlgorithmIdentifier = 45
	ECDSA_P256_SHA384           AlgorithmIdentifier = 46
	ECDSA_P256_SHA512           AlgorithmIdentifier = 47
	ECDSA_P384_SHA1             AlgorithmIdentifier = 48
	ECDSA_P384_SHA256           AlgorithmIdentifier = 49
	ECDSA_P384_SHA384           AlgorithmIdentifier = 50
	ECDSA_P384_SHA512           AlgorithmIdentifier = 51
	ECDSA_P521_SHA1             AlgorithmIdentifier = 52
	ECDSA_P521_SHA256           AlgorithmIdentifier = 53
	ECDSA_P521_SHA384           AlgorithmIdentifier = 54
	ECDSA_P521_SHA512           AlgorithmIdentifier = 55
	ECDH_P256                   AlgorithmIdentifier = 56
	ECDH_P384                   AlgorithmIdentifier = 57
	ECDH_P521                   AlgorithmIdentifier = 58
	ECDSA_K256_SHA1             AlgorithmIdentifier = 59
	ECDSA_K256_SHA256           AlgorithmIdentifier = 60
	ECDSA_K256_SHA384           AlgorithmIdentifier = 61
	ECDSA_K256_SHA512           AlgorithmIdentifier = 62
	ECDH_K256                   AlgorithmIdentifier = 63
	ED_25519                    AlgorithmIdentifier = 64
	ED_448                      AlgorithmIdentifier = 65
	X_25519                     AlgorithmIdentifier = 66
	// Algorithms 67-68 match the GoodKey service proto (algorithm.proto).
	ML_DSA_65                   AlgorithmIdentifier = 67 // FIPS 204, ~192-bit PQ security (DEFAULT)
	SLH_DSA_SHA2_128S           AlgorithmIdentifier = 68 // FIPS 205, hash-based (backup)

	// CEF extensions: algorithms not yet in the GoodKey service proto.
	// These IDs are reserved in the CEF SDK and will be proposed for
	// inclusion in the GoodKey service proto.
	ML_DSA_44                   AlgorithmIdentifier = 100 // FIPS 204, ~128-bit PQ security
	ML_DSA_87                   AlgorithmIdentifier = 101 // FIPS 204, ~256-bit PQ security
	ML_KEM_512                  AlgorithmIdentifier = 102 // FIPS 203, ~128-bit PQ security
	ML_KEM_768                  AlgorithmIdentifier = 103 // FIPS 203, ~192-bit PQ security (DEFAULT for CEF)
	ML_KEM_1024                 AlgorithmIdentifier = 104 // FIPS 203, ~256-bit PQ security
)

// String returns the algorithm name suitable for use in API calls.
func (a AlgorithmIdentifier) String() string {
	names := map[AlgorithmIdentifier]string{
		RSASSA_PKCS1_2048_SHA256: "RSASSA_PKCS1_2048_SHA256",
		RSASSA_PKCS1_2048_SHA384: "RSASSA_PKCS1_2048_SHA384",
		RSASSA_PKCS1_2048_SHA512: "RSASSA_PKCS1_2048_SHA512",
		RSASSA_PKCS1_3072_SHA256: "RSASSA_PKCS1_3072_SHA256",
		RSASSA_PKCS1_4096_SHA256: "RSASSA_PKCS1_4096_SHA256",
		RSAES_PKCS1_2048:         "RSAES_PKCS1_2048",
		RSAES_PKCS1_3072:         "RSAES_PKCS1_3072",
		RSAES_PKCS1_4096:         "RSAES_PKCS1_4096",
		RSA_OAEP_2048_SHA256:     "RSA_OAEP_2048_SHA256",
		RSA_OAEP_3072_SHA256:     "RSA_OAEP_3072_SHA256",
		RSA_OAEP_4096_SHA256:     "RSA_OAEP_4096_SHA256",
		ECDSA_P256_SHA256:        "ECDSA_P256_SHA256",
		ECDSA_P384_SHA384:        "ECDSA_P384_SHA384",
		ECDSA_P521_SHA512:        "ECDSA_P521_SHA512",
		ECDH_P256:                "ECDH_P256",
		ECDH_P384:                "ECDH_P384",
		ECDH_P521:                "ECDH_P521",
		ED_25519:                 "ED_25519",
		ED_448:                   "ED_448",
		X_25519:                  "X_25519",
		ML_DSA_44:                "ML_DSA_44",
		ML_DSA_65:                "ML_DSA_65",
		ML_DSA_87:                "ML_DSA_87",
		SLH_DSA_SHA2_128S:        "SLH_DSA_SHA2_128S",
		ML_KEM_512:               "ML_KEM_512",
		ML_KEM_768:               "ML_KEM_768",
		ML_KEM_1024:              "ML_KEM_1024",
	}
	if name, ok := names[a]; ok {
		return name
	}
	return "UNKNOWN"
}

// KeyUsage represents the intended use of a key.
type KeyUsage int32

const (
	KeyUsageUnspecified KeyUsage = 0
	KeyUsageAuth        KeyUsage = 1 // Authentication/signing
	KeyUsageCipher      KeyUsage = 2 // Encryption/decryption
	KeyUsageExchange    KeyUsage = 3 // Key exchange
)

// KeyType represents the cryptographic key type.
type KeyType int32

const (
	KeyTypeUnspecified KeyType = 0
	KeyTypeRSA         KeyType = 1
	KeyTypeEC          KeyType = 2  // ECDSA (P-256, P-384, P-521)
	KeyTypeED          KeyType = 3  // EdDSA (Ed25519)
	KeyTypePQ          KeyType = 4  // Post-quantum (ML-DSA, SLH-DSA, ML-KEM)
	KeyTypeECDH        KeyType = 5  // ECDH key agreement (P-256, P-384, X25519)
)

// KeyStatus represents the status of a key.
type KeyStatus int32

const (
	KeyStatusUnspecified KeyStatus = 0
	KeyStatusActive      KeyStatus = 1
	KeyStatusInactive    KeyStatus = 2
	KeyStatusPending     KeyStatus = 3
	KeyStatusExpired     KeyStatus = 4
)

// CertificateType represents the type of certificate.
type CertificateType int32

const (
	CertificateTypeUnspecified CertificateType = 0
	CertificateTypeX509        CertificateType = 1
	CertificateTypeCSR         CertificateType = 2
	CertificateTypeSSH         CertificateType = 3
)

// CertificateStatus represents the status of a certificate.
type CertificateStatus int32

const (
	CertificateStatusUnspecified CertificateStatus = 0
	CertificateStatusActive      CertificateStatus = 1
	CertificateStatusInactive    CertificateStatus = 2
	CertificateStatusPending     CertificateStatus = 3
)

// OperationType represents the type of key operation.
type OperationType string

const (
	OperationTypeSign       OperationType = "sign"
	OperationTypeDecrypt    OperationType = "decrypt"
	OperationTypeDerive     OperationType = "derive"
)

// OperationStatus represents the status of a key operation.
type OperationStatus string

const (
	OperationStatusPending   OperationStatus = "pending"
	OperationStatusApproved  OperationStatus = "approved"
	OperationStatusCompleted OperationStatus = "completed"
	OperationStatusCancelled OperationStatus = "cancelled"
	OperationStatusFailed    OperationStatus = "failed"
)

// --- Request/Response Types ---

// EmptyRequest is used for RPCs that don't require input.
type EmptyRequest struct{}

// EmptyResponse is used for RPCs that don't return data.
type EmptyResponse struct{}

// ProfileToken contains authentication token information.
type ProfileToken struct {
	Type      string `json:"type"`
	ExpiresAt int64  `json:"expires_at"`
	Origin    string `json:"origin"`
	OrgID     string `json:"org_id"`
}

// OrganizationResponse contains organization information.
type OrganizationResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ProfileResponse contains the authenticated user's profile.
type ProfileResponse struct {
	ID           string               `json:"id"`
	Email        string               `json:"email"`
	FirstName    string               `json:"first_name"`
	LastName     string               `json:"last_name"`
	Token        *ProfileToken        `json:"token"`
	Organization *OrganizationResponse `json:"organization"`
}

// KeyFilterRequest is used to filter keys when listing.
type KeyFilterRequest struct {
	Status KeyStatus `json:"status"`
	Type   KeyType   `json:"type"`
	Usage  KeyUsage  `json:"usage"`
	Name   string    `json:"name"`
}

// KeyProviderShortResponse contains key provider information.
type KeyProviderShortResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// KeyShortResponse contains summary key information.
type KeyShortResponse struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Type   KeyType    `json:"type"`
	Status KeyStatus  `json:"status"`
	Size   int32      `json:"size"`
	Usages []KeyUsage `json:"usages"`
	SPKI   string     `json:"spki"` // Base64-encoded SubjectPublicKeyInfo
}

// KeyResponse contains detailed key information.
type KeyResponse struct {
	ID         string                    `json:"id"`
	Name       string                    `json:"name"`
	Type       KeyType                   `json:"type"`
	Status     KeyStatus                 `json:"status"`
	Quorum     int32                     `json:"quorum"`
	SPKI       string                    `json:"spki"`
	CreatedAt  string                    `json:"created_at"`
	UpdatedAt  string                    `json:"updated_at"`
	Provider   *KeyProviderShortResponse `json:"provider"`
	Size       int32                     `json:"size"`
	Usages     []KeyUsage                `json:"usages"`
	Algorithms []string                  `json:"algorithms"`
}

// KeyListResponse contains a list of keys.
type KeyListResponse struct {
	Keys []*KeyShortResponse `json:"keys"`
}

// KeyRequest is used to request a specific key.
type KeyRequest struct {
	ID     string `json:"id"`
	Format string `json:"format"` // Optional: pem, der, ssh
}

// PublicKeyResponse contains the public key data.
type PublicKeyResponse struct {
	Data []byte `json:"data"`
}

// CertificateShortResponse contains summary certificate information.
type CertificateShortResponse struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Type  CertificateType `json:"type"`
	KeyID string          `json:"key_id"`
}

// CertificateResponse contains detailed certificate information.
type CertificateResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        CertificateType   `json:"type"`
	Status      CertificateStatus `json:"status"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
	KeyID       string            `json:"key_id"`
	Thumbprint  string            `json:"thumbprint"`
}

// CertificateListResponse contains a list of certificates.
type CertificateListResponse struct {
	Items []*CertificateShortResponse `json:"items"`
}

// CertificateRequest is used to request a specific certificate.
type CertificateRequest struct {
	ID     string `json:"id"`
	Format string `json:"format"` // Optional: pem, der, ssh
}

// CertificateRawResponse contains raw certificate data.
type CertificateRawResponse struct {
	Data []byte `json:"data"`
}

// CreateKeyOperationRequest is used to create a new key operation.
type CreateKeyOperationRequest struct {
	KeyID      string            `json:"key_id"`
	Type       string            `json:"type"` // "sign", "decrypt", "derive"
	Name       string            `json:"name"` // Algorithm name
	ExpiresAt  string            `json:"expires_at,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// GetKeyOperationRequest is used to get operation status.
type GetKeyOperationRequest struct {
	KeyID       string `json:"key_id"`
	OperationID string `json:"operation_id"`
}

// CancelKeyOperationRequest is used to cancel a pending operation.
type CancelKeyOperationRequest struct {
	KeyID       string `json:"key_id"`
	OperationID string `json:"operation_id"`
	Reason      string `json:"reason"`
}

// KeyOperationResponse contains key operation status.
type KeyOperationResponse struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Name          string `json:"name"`  // Algorithm name (e.g., "ML_KEM_768", "ECDSA_P256_SHA256")
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	KeyID         string `json:"key_id"`
	ApprovalsLeft int32  `json:"approvals_left"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

// FinalizeKeyOperationRequest is used to complete an operation with data.
type FinalizeKeyOperationRequest struct {
	KeyID       string `json:"key_id"`
	OperationID string `json:"operation_id"`
	Data        []byte `json:"data"` // Data to sign, decrypt, or derive (e.g., ML-KEM ciphertext)
}

// FinalizeKeyOperationResponse contains the operation result.
type FinalizeKeyOperationResponse struct {
	Operation *KeyOperationResponse `json:"operation"`
	Data      []byte                `json:"data"` // Signature or decrypted/unwrapped data
}
