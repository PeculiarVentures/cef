// Package cert provides X.509 certificate validation utilities for CEF
// implementations that use certificate-backed recipients.
//
// This is part of the GoodKey implementation layer, not the format layer.
// The CEF format itself is certificate-agnostic — it identifies recipients
// by key ID. This package provides the validation logic for backends that
// resolve key IDs to certificates.
package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// Validator validates certificates for use in CEF operations.
type Validator interface {
	ValidateForEncryption(cert *x509.Certificate) error
	ValidateForSigning(cert *x509.Certificate) error
	ValidateChain(cert *x509.Certificate, intermediates []*x509.Certificate) error
}

// StandardValidator implements standard certificate validation with
// configurable checks for expiry, key usage, and self-signed acceptance.
type StandardValidator struct {
	CheckExpiry      bool
	CheckKeyUsage    bool
	AllowExpired     bool
	AllowSelfSigned  bool

	// nowFn can be overridden for testing. Defaults to time.Now.
	nowFn func() time.Time
}

// DefaultValidator is the default certificate validator.
var DefaultValidator Validator = &StandardValidator{
	CheckExpiry:   true,
	CheckKeyUsage: true,
}

// now returns the current time, using nowFn if set.
func (v *StandardValidator) now() time.Time {
	if v.nowFn != nil {
		return v.nowFn()
	}
	return time.Now()
}

// ValidateForEncryption checks if a certificate is suitable for encrypting to.
func (v *StandardValidator) ValidateForEncryption(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if v.CheckExpiry && !v.AllowExpired {
		now := v.now()
		if now.Before(cert.NotBefore) {
			return &ValidationError{
				Certificate: cert,
				Reason:      fmt.Sprintf("certificate not yet valid (notBefore: %s)", cert.NotBefore.Format(time.RFC3339)),
			}
		}
		if now.After(cert.NotAfter) {
			return &ValidationError{
				Certificate: cert,
				Reason:      fmt.Sprintf("certificate expired (notAfter: %s)", cert.NotAfter.Format(time.RFC3339)),
			}
		}
	}

	if v.CheckKeyUsage {
		// For encryption recipients, the certificate needs KeyEncipherment (RSA)
		// or KeyAgreement (ECDH). Some certs have both.
		hasEncryptionUsage := cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 ||
			cert.KeyUsage&x509.KeyUsageKeyAgreement != 0
		// If KeyUsage is zero, the extension is absent — allow by default
		if cert.KeyUsage != 0 && !hasEncryptionUsage {
			return &ValidationError{
				Certificate: cert,
				Reason:      "certificate does not have KeyEncipherment or KeyAgreement usage",
			}
		}
	}

	return nil
}

// ValidateForSigning checks if a certificate is suitable for signature verification.
func (v *StandardValidator) ValidateForSigning(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if v.CheckExpiry && !v.AllowExpired {
		now := v.now()
		if now.Before(cert.NotBefore) {
			return &ValidationError{
				Certificate: cert,
				Reason:      fmt.Sprintf("certificate not yet valid (notBefore: %s)", cert.NotBefore.Format(time.RFC3339)),
			}
		}
		if now.After(cert.NotAfter) {
			return &ValidationError{
				Certificate: cert,
				Reason:      fmt.Sprintf("certificate expired (notAfter: %s)", cert.NotAfter.Format(time.RFC3339)),
			}
		}
	}

	if v.CheckKeyUsage {
		hasSigningUsage := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 ||
			cert.KeyUsage&x509.KeyUsageContentCommitment != 0
		if cert.KeyUsage != 0 && !hasSigningUsage {
			return &ValidationError{
				Certificate: cert,
				Reason:      "certificate does not have DigitalSignature usage",
			}
		}
	}

	return nil
}

// ValidateChain validates a certificate against system roots with optional intermediates.
func (v *StandardValidator) ValidateChain(cert *x509.Certificate, intermediates []*x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if v.AllowSelfSigned && cert.IsCA {
		return nil
	}

	pool := x509.NewCertPool()
	for _, ic := range intermediates {
		pool.AddCert(ic)
	}

	opts := x509.VerifyOptions{
		Intermediates: pool,
		CurrentTime:   v.now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return &ValidationError{
			Certificate: cert,
			Reason:      fmt.Sprintf("chain validation failed: %v", err),
		}
	}

	return nil
}

// NoOpValidator accepts all certificates without validation.
// Useful for testing and development environments.
type NoOpValidator struct{}

func (v *NoOpValidator) ValidateForEncryption(*x509.Certificate) error { return nil }
func (v *NoOpValidator) ValidateForSigning(*x509.Certificate) error    { return nil }
func (v *NoOpValidator) ValidateChain(*x509.Certificate, []*x509.Certificate) error {
	return nil
}

// ValidationError represents a certificate validation failure.
type ValidationError struct {
	Certificate *x509.Certificate
	Reason      string
}

func (e *ValidationError) Error() string {
	if e.Certificate != nil {
		return fmt.Sprintf("certificate validation failed for %s: %s", e.Certificate.Subject.CommonName, e.Reason)
	}
	return fmt.Sprintf("certificate validation failed: %s", e.Reason)
}

// ---------------------------------------------------------------------------
// PEM utilities
// ---------------------------------------------------------------------------

// ParsePEM parses a single PEM-encoded certificate.
func ParsePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePEMChain parses multiple PEM-encoded certificates from a single byte slice.
func ParsePEMChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return certs, nil
}

// MatchIssuerAndSerial checks if a certificate matches the given issuer DN and serial number.
func MatchIssuerAndSerial(cert *x509.Certificate, issuer []byte, serial []byte) bool {
	if cert == nil {
		return false
	}
	if !bytes.Equal(cert.RawIssuer, issuer) {
		return false
	}
	return bytes.Equal(cert.SerialNumber.Bytes(), serial)
}

// KeyType returns a human-readable description of the certificate's public key type.
func KeyType(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pk := cert.PublicKey.(*rsa.PublicKey)
		return fmt.Sprintf("RSA-%d", pk.N.BitLen())
	case *ecdsa.PublicKey:
		pk := cert.PublicKey.(*ecdsa.PublicKey)
		return fmt.Sprintf("ECDSA-%s", pk.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", cert.PublicKey)
	}
}
