package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateTestCert creates a self-signed test certificate with the given options.
func generateTestCert(t *testing.T, opts struct {
	CN        string
	NotBefore time.Time
	NotAfter  time.Time
	KeyUsage  x509.KeyUsage
}) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: opts.CN},
		NotBefore:    opts.NotBefore,
		NotAfter:     opts.NotAfter,
		KeyUsage:     opts.KeyUsage,
		IsCA:         true, // self-signed needs this for chain validation
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func validCert(t *testing.T, cn string, usage x509.KeyUsage) *x509.Certificate {
	return generateTestCert(t, struct {
		CN        string
		NotBefore time.Time
		NotAfter  time.Time
		KeyUsage  x509.KeyUsage
	}{
		CN:        cn,
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  usage,
	})
}

func expiredCert(t *testing.T) *x509.Certificate {
	return generateTestCert(t, struct {
		CN        string
		NotBefore time.Time
		NotAfter  time.Time
		KeyUsage  x509.KeyUsage
	}{
		CN:        "Expired",
		NotBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	})
}

func futureCert(t *testing.T) *x509.Certificate {
	return generateTestCert(t, struct {
		CN        string
		NotBefore time.Time
		NotAfter  time.Time
		KeyUsage  x509.KeyUsage
	}{
		CN:        "Future",
		NotBefore: time.Now().Add(365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	})
}

func certToPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// --- Validation tests ---

func TestValidateForEncryption(t *testing.T) {
	v := &StandardValidator{CheckExpiry: true, CheckKeyUsage: true}

	t.Run("keyEncipherment passes", func(t *testing.T) {
		cert := validCert(t, "Alice", x509.KeyUsageKeyEncipherment)
		if err := v.ValidateForEncryption(cert); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("keyAgreement passes", func(t *testing.T) {
		cert := validCert(t, "Bob", x509.KeyUsageKeyAgreement)
		if err := v.ValidateForEncryption(cert); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("digitalSignature only rejected", func(t *testing.T) {
		cert := validCert(t, "SignOnly", x509.KeyUsageDigitalSignature)
		if err := v.ValidateForEncryption(cert); err == nil {
			t.Fatal("expected error for signing-only cert")
		}
	})

	t.Run("nil cert rejected", func(t *testing.T) {
		if err := v.ValidateForEncryption(nil); err == nil {
			t.Fatal("expected error for nil cert")
		}
	})
}

func TestValidateForSigning(t *testing.T) {
	v := &StandardValidator{CheckExpiry: true, CheckKeyUsage: true}

	t.Run("digitalSignature passes", func(t *testing.T) {
		cert := validCert(t, "Signer", x509.KeyUsageDigitalSignature)
		if err := v.ValidateForSigning(cert); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("keyEncipherment only rejected", func(t *testing.T) {
		cert := validCert(t, "EncryptOnly", x509.KeyUsageKeyEncipherment)
		if err := v.ValidateForSigning(cert); err == nil {
			t.Fatal("expected error for encryption-only cert")
		}
	})
}

func TestValidateExpiry(t *testing.T) {
	v := &StandardValidator{CheckExpiry: true, CheckKeyUsage: false}

	t.Run("expired rejected", func(t *testing.T) {
		cert := expiredCert(t)
		if err := v.ValidateForEncryption(cert); err == nil {
			t.Fatal("expected error for expired cert")
		}
	})

	t.Run("not yet valid rejected", func(t *testing.T) {
		cert := futureCert(t)
		if err := v.ValidateForEncryption(cert); err == nil {
			t.Fatal("expected error for future cert")
		}
	})

	t.Run("allowExpired skips check", func(t *testing.T) {
		v2 := &StandardValidator{CheckExpiry: true, AllowExpired: true}
		cert := expiredCert(t)
		if err := v2.ValidateForEncryption(cert); err != nil {
			t.Fatalf("unexpected error with AllowExpired: %v", err)
		}
	})
}

func TestNoOpValidator(t *testing.T) {
	v := &NoOpValidator{}
	cert := expiredCert(t)
	if err := v.ValidateForEncryption(cert); err != nil {
		t.Fatalf("NoOp should accept everything: %v", err)
	}
	if err := v.ValidateForSigning(cert); err != nil {
		t.Fatalf("NoOp should accept everything: %v", err)
	}
	if err := v.ValidateChain(cert, nil); err != nil {
		t.Fatalf("NoOp should accept everything: %v", err)
	}
}

// --- PEM tests ---

func TestParsePEM(t *testing.T) {
	cert := validCert(t, "PEM Test", x509.KeyUsageDigitalSignature)
	pemData := certToPEM(t, cert)

	parsed, err := ParsePEM(pemData)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if parsed.Subject.CommonName != "PEM Test" {
		t.Fatalf("wrong CN: %s", parsed.Subject.CommonName)
	}
}

func TestParsePEMInvalid(t *testing.T) {
	if _, err := ParsePEM([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	badPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := ParsePEM(badPEM); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestParsePEMChain(t *testing.T) {
	cert1 := validCert(t, "Cert1", x509.KeyUsageDigitalSignature)
	cert2 := validCert(t, "Cert2", x509.KeyUsageKeyEncipherment)

	chainPEM := append(certToPEM(t, cert1), certToPEM(t, cert2)...)

	certs, err := ParsePEMChain(chainPEM)
	if err != nil {
		t.Fatalf("ParsePEMChain: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Cert1" {
		t.Fatalf("wrong first cert CN: %s", certs[0].Subject.CommonName)
	}
}

func TestParsePEMChainEmpty(t *testing.T) {
	if _, err := ParsePEMChain([]byte("no certs here")); err == nil {
		t.Fatal("expected error for empty PEM chain")
	}
}

// --- MatchIssuerAndSerial tests ---

func TestMatchIssuerAndSerial(t *testing.T) {
	cert := validCert(t, "Match Test", x509.KeyUsageDigitalSignature)

	if !MatchIssuerAndSerial(cert, cert.RawIssuer, cert.SerialNumber.Bytes()) {
		t.Fatal("should match own issuer and serial")
	}

	if MatchIssuerAndSerial(cert, []byte("wrong issuer"), cert.SerialNumber.Bytes()) {
		t.Fatal("should not match wrong issuer")
	}

	if MatchIssuerAndSerial(cert, cert.RawIssuer, []byte{99}) {
		t.Fatal("should not match wrong serial")
	}

	if MatchIssuerAndSerial(nil, cert.RawIssuer, cert.SerialNumber.Bytes()) {
		t.Fatal("should not match nil cert")
	}
}

// --- KeyType tests ---

func TestKeyType(t *testing.T) {
	cert := validCert(t, "ECDSA Cert", x509.KeyUsageDigitalSignature)
	kt := KeyType(cert)
	if kt != "ECDSA-P-256" {
		t.Fatalf("expected ECDSA-P-256, got %s", kt)
	}
}

// --- ValidationError tests ---

func TestValidationError(t *testing.T) {
	cert := validCert(t, "ErrorTest", 0)
	err := &ValidationError{Certificate: cert, Reason: "test reason"}
	if err.Error() == "" {
		t.Fatal("error string should not be empty")
	}

	err2 := &ValidationError{Reason: "no cert"}
	if err2.Error() == "" {
		t.Fatal("error string without cert should not be empty")
	}
}
