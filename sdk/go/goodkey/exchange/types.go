// Package exchange provides the file exchange service using the local GoodKey service.
//
// Architecture:
//   - Container format handling (ZIP structure, CBOR manifest) → local
//   - Hash computation → local
//   - COSE_Encrypt / COSE_Sign1 structure building → local
//   - All private key operations (sign, wrap, unwrap) → GoodKey service via IPC
//
// Private keys never leave the secure environment.
package exchange

import (
	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

// Service provides file exchange operations.
// Requires a CEFServiceClient which extends the base GoodKey service
// interface with recipient lookup for the "encrypt to anyone" flow.
type Service struct {
	client ipc.CEFServiceClient
}

// NewService creates a new file exchange service.
func NewService(client ipc.CEFServiceClient) *Service {
	return &Service{client: client}
}

// EncryptOptions configures the encrypt operation.
type EncryptOptions struct {
	// Recipients is a list of GoodKey key IDs for direct recipients.
	Recipients []string

	// RecipientEmails enables "encrypt to anyone." The GoodKey service
	// looks up each email address:
	//   - If the user is enrolled, their current encryption key is used.
	//   - If the user is not enrolled, GoodKey provisions a key pair,
	//     wraps the CEK to that key, and marks the recipient as pending.
	//     The user can decrypt once they complete enrollment.
	// This allows senders to encrypt to recipients who have never used
	// GoodKey before. No pre-enrollment required.
	RecipientEmails []string

	// RecipientGroups is a list of group key IDs. Group keys are shared
	// keys managed by GoodKey with membership-based access control and
	// optional key versioning for temporal enforcement.
	RecipientGroups []string

	// RecipientCertIDs is a list of GoodKey certificate IDs. The service
	// resolves each certificate ID to the associated encryption key.
	// This supports workflows where the operator thinks in certificates
	// rather than key IDs (e.g., PIV/CAC, LDAP directory lookups).
	RecipientCertIDs []string

	// RecipientCertFiles is a list of PEM-encoded certificate file paths.
	// The SDK extracts the public key from each certificate, validates it
	// for encryption usage, and wraps the CEK directly. No GoodKey lookup
	// required. This supports offline certificate-based encryption.
	RecipientCertFiles []string

	// SenderKeyID is the key to use for signing (must have AUTH usage).
	SenderKeyID string

	// SenderCertID is the certificate to identify the sender. If set,
	// the sender's email is extracted from the certificate subject.
	SenderCertID string

	SignatureAlgorithm ipc.AlgorithmIdentifier // Default: ML_DSA_65 (PQ)
	MaxFileSize        int64                   // Default: 1GB

	// Timestamp is an optional RFC 3161 timestamp token (DER-encoded).
	// The caller is responsible for obtaining the token from a TSA.
	// If set, the token is included as META-INF/manifest.tst in the container.
	Timestamp []byte
}

// DecryptOptions configures the decrypt operation.
type DecryptOptions struct {
	// RecipientKeyID is the key to use for decryption.
	RecipientKeyID string

	// RecipientCertID is an alternative to RecipientKeyID. The service
	// resolves the certificate ID to the associated decryption key.
	RecipientCertID string

	OutputDir       string
	AllowInvalidHash bool // Default: false, files with hash mismatches are rejected

	// SkipSignatureVerification disables COSE_Sign1 signature verification.
	// Default: false (verification is on). Set to true only when the sender's
	// key is unavailable for verification.
	SkipSignatureVerification bool
}

// EncryptResult contains the results of an encrypt operation.
type EncryptResult struct {
	ContainerPath string
	FileCount     int
	Recipients    []string
	Signed        bool
	Timestamped   bool

	// PendingRecipients lists email addresses of recipients who are not
	// yet enrolled in GoodKey. They will be able to decrypt once they
	// complete enrollment. The container is already encrypted to their
	// provisioned key.
	PendingRecipients []string

	RecipientDetails []*ipc.RecipientInfo
}

// DecryptResult contains the results of a decrypt operation.
type DecryptResult struct {
	Files            []DecryptedFile
	ManifestValid    bool
	SignatureValid   bool
	TimestampPresent bool
	SenderKID        string // Verified sender key identifier
	SenderClaimsEmail string // Unverified sender email claim (for display)
}

// DecryptedFile represents a decrypted file.
type DecryptedFile struct {
	OriginalName string
	OutputPath   string
	Size         int64
	HashValid    bool
}

// VerifyResult contains the results of a verify operation.
// Note: without a recipient key, full cryptographic signature verification
// is not possible. SignaturePresent indicates the signature is well-formed
// COSE_Sign1 but has not been cryptographically verified.
type VerifyResult struct {
	ContainerValid    bool
	SignaturePresent  bool // COSE_Sign1 structure is well-formed (not cryptographically verified)
	TimestampPresent  bool
	FileCount         int
	SenderKID         string // Verified sender key identifier
	SenderClaimsEmail string // Unverified sender email claim
	Recipients        []string
	Errors            []string
}

// DefaultMaxFileSize is the default maximum file size (1 GB).
const DefaultMaxFileSize = 1 << 30
