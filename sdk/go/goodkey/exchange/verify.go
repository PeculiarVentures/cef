package exchange

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/cef/sdk/go/format/container"
	gcose "github.com/PeculiarVentures/cef/sdk/go/format/cose"
)

// VerifyContainer verifies a container's integrity without decrypting.
func (s *Service) VerifyContainer(ctx context.Context, containerPath string) (*VerifyResult, error) {
	result := &VerifyResult{}

	c, err := container.ReadFromFile(containerPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("read: %v", err))
		return result, nil
	}

	result.ContainerValid = true
	result.FileCount = len(c.EncryptedFiles)

	if len(c.ManifestSignature) > 0 {
		// Verify the signature is well-formed CBOR (COSE_Sign1 structure).
		// Full cryptographic verification requires decrypting the manifest to
		// get the sender's key ID, which requires a recipient key. Without that,
		// we can only confirm the structure is parseable.
		var sig1 gcose.Sign1Message
		if err := sig1.UnmarshalCBOR(c.ManifestSignature); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("signature: invalid COSE_Sign1: %v", err))
		} else {
			result.SignaturePresent = true // Well-formed COSE_Sign1 (not cryptographically verified)
		}
	}

	return result, nil
}
