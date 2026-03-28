package exchange

import (
	"context"

	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

// ListSigningKeys returns keys suitable for signing.
func (s *Service) ListSigningKeys(ctx context.Context) ([]*ipc.KeyShortResponse, error) {
	resp, err := s.client.GetKeys(ctx, &ipc.KeyFilterRequest{
		Status: ipc.KeyStatusActive,
		Usage:  ipc.KeyUsageAuth,
	})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// ListEncryptionKeys returns keys suitable for encryption/decryption.
func (s *Service) ListEncryptionKeys(ctx context.Context) ([]*ipc.KeyShortResponse, error) {
	resp, err := s.client.GetKeys(ctx, &ipc.KeyFilterRequest{
		Status: ipc.KeyStatusActive,
		Usage:  ipc.KeyUsageCipher,
	})
	if err != nil {
		return nil, err
	}
	return resp.Keys, nil
}

// ListCertificates returns available certificates.
func (s *Service) ListCertificates(ctx context.Context) ([]*ipc.CertificateShortResponse, error) {
	resp, err := s.client.GetCertificates(ctx)
	if err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// GetProfile returns the current user's profile.
func (s *Service) GetProfile(ctx context.Context) (*ipc.ProfileResponse, error) {
	return s.client.GetProfile(ctx)
}

// SupportedSignatureAlgorithms returns algorithms suitable for signing.
// PQ algorithms are listed first as they are preferred for new deployments.
func SupportedSignatureAlgorithms() []ipc.AlgorithmIdentifier {
	return []ipc.AlgorithmIdentifier{
		// Post-quantum (preferred for new deployments)
		ipc.ML_DSA_65,
		// Classical ECC
		ipc.ECDSA_P256_SHA256,
		ipc.ECDSA_P384_SHA384,
		ipc.ED_25519,
	}
}

// SupportedKeyWrapAlgorithms returns algorithms suitable for CEK key wrapping.
func SupportedKeyWrapAlgorithms() []ipc.AlgorithmIdentifier {
	return []ipc.AlgorithmIdentifier{
		// Post-quantum (preferred)
		ipc.ML_KEM_768,
		// Classical
		ipc.ECDH_P256,
		ipc.X_25519,
	}
}

// IsPostQuantumAlgorithm returns true if the algorithm is post-quantum.
func IsPostQuantumAlgorithm(alg ipc.AlgorithmIdentifier) bool {
	switch alg {
	case ipc.ML_DSA_44, ipc.ML_DSA_65, ipc.ML_DSA_87,
		ipc.ML_KEM_512, ipc.ML_KEM_768, ipc.ML_KEM_1024,
		ipc.SLH_DSA_SHA2_128S:
		return true
	default:
		return false
	}
}

// AlgorithmCategory returns "pq", "ecc", or "unknown" for the given algorithm.
func AlgorithmCategory(alg ipc.AlgorithmIdentifier) string {
	if IsPostQuantumAlgorithm(alg) {
		return "pq"
	}
	switch alg {
	case ipc.ECDSA_P256_SHA256, ipc.ECDSA_P384_SHA384, ipc.ED_25519,
		ipc.ECDH_P256, ipc.X_25519:
		return "ecc"
	default:
		return "unknown"
	}
}
