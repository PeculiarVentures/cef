package ipc

import (
	"context"
	"time"
)

// EnrollmentStatus represents the enrollment state of a recipient.
type EnrollmentStatus string

const (
	// EnrollmentStatusEnrolled means the user has a GoodKey account with keys.
	EnrollmentStatusEnrolled EnrollmentStatus = "enrolled"

	// EnrollmentStatusPending means a key was provisioned but user hasn't claimed it.
	EnrollmentStatusPending EnrollmentStatus = "pending"

	// EnrollmentStatusInvited means an invitation was sent but no key provisioned yet.
	EnrollmentStatusInvited EnrollmentStatus = "invited"
)

// RecipientInfo contains information about a recipient for encryption.
type RecipientInfo struct {
	// Email is the recipient's email address.
	Email string `json:"email"`

	// Status indicates whether the user is enrolled, pending, or invited.
	Status EnrollmentStatus `json:"status"`

	// CertificateID is the ID of the certificate associated with this recipient.
	// In v2, this may be empty when using symmetric key wrap (COSE_Encrypt).
	CertificateID string `json:"certificate_id"`

	// KeyID is the ID of the key used for key wrap/unwrap operations.
	KeyID string `json:"key_id"`

	// Certificate is the PEM-encoded certificate, if applicable.
	// In v2, this field is optional — symmetric key wrap doesn't require certificates.
	Certificate []byte `json:"certificate,omitempty"`

	// ProvisionedAt is when the key was provisioned (for pending users).
	ProvisionedAt *time.Time `json:"provisioned_at,omitempty"`

	// ExpiresAt is when the pending invitation expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// LookupRecipientRequest is the request to look up a recipient by email.
type LookupRecipientRequest struct {
	// Email is the recipient's email address.
	Email string `json:"email"`

	// AutoProvision controls whether to automatically provision a key
	// for non-enrolled users. Default is true.
	AutoProvision bool `json:"auto_provision"`

	// SendInvitation controls whether to send an email invitation
	// to non-enrolled users. Default is true.
	SendInvitation bool `json:"send_invitation"`

	// KeyType specifies the key type to provision. Default is RSA.
	KeyType KeyType `json:"key_type,omitempty"`

	// Algorithm specifies the algorithm for the provisioned key.
	Algorithm AlgorithmIdentifier `json:"algorithm,omitempty"`
}

// LookupRecipientsRequest is the request to look up multiple recipients.
type LookupRecipientsRequest struct {
	// Emails is the list of recipient email addresses.
	Emails []string `json:"emails"`

	// AutoProvision controls whether to automatically provision keys
	// for non-enrolled users. Default is true.
	AutoProvision bool `json:"auto_provision"`

	// SendInvitation controls whether to send email invitations
	// to non-enrolled users. Default is true.
	SendInvitation bool `json:"send_invitation"`
}

// LookupRecipientsResponse contains results for multiple recipient lookups.
type LookupRecipientsResponse struct {
	// Recipients contains the info for each looked-up recipient.
	// The order matches the order of emails in the request.
	Recipients []*RecipientInfo `json:"recipients"`

	// Errors contains any errors that occurred during lookup.
	// Key is the email address that failed.
	Errors map[string]string `json:"errors,omitempty"`
}

// RecipientLookupService provides recipient directory operations.
type RecipientLookupService interface {
	// LookupRecipient finds or provisions a recipient by email.
	//
	// If the user is enrolled, returns their existing certificate.
	// If the user is not enrolled and AutoProvision is true (default),
	// provisions a new key/certificate and returns it.
	//
	// This enables "encrypt to anyone" - the sender always gets a
	// certificate to encrypt to, even if the recipient hasn't signed up yet.
	LookupRecipient(ctx context.Context, req *LookupRecipientRequest) (*RecipientInfo, error)

	// LookupRecipients looks up multiple recipients in a single call.
	// More efficient than multiple LookupRecipient calls.
	LookupRecipients(ctx context.Context, req *LookupRecipientsRequest) (*LookupRecipientsResponse, error)

	// GetRecipientStatus checks the current enrollment status of an email.
	// Does not provision anything - just checks current state.
	GetRecipientStatus(ctx context.Context, email string) (*RecipientInfo, error)
}
