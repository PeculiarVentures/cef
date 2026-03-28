// Package ipc provides the client for communicating with the local GoodKey service via gRPC.
package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// GoodKeyServiceClient is the interface for the local GoodKey service.
// Methods in this interface match the GoodKey service gRPC proto
// (service.proto) and work with the existing GoodKey local service.
type GoodKeyServiceClient interface {
	// Authentication
	GetProfile(ctx context.Context) (*ProfileResponse, error)

	// Key management
	GetKeys(ctx context.Context, req *KeyFilterRequest) (*KeyListResponse, error)
	GetKey(ctx context.Context, req *KeyRequest) (*KeyResponse, error)
	GetPublicKey(ctx context.Context, req *KeyRequest) (*PublicKeyResponse, error)

	// Key operations
	CreateKeyOperation(ctx context.Context, req *CreateKeyOperationRequest) (*KeyOperationResponse, error)
	GetKeyOperation(ctx context.Context, req *GetKeyOperationRequest) (*KeyOperationResponse, error)
	CancelKeyOperation(ctx context.Context, req *CancelKeyOperationRequest) (*KeyOperationResponse, error)
	FinalizeKeyOperation(ctx context.Context, req *FinalizeKeyOperationRequest) (*FinalizeKeyOperationResponse, error)

	// Certificate management
	GetCertificates(ctx context.Context) (*CertificateListResponse, error)
	GetCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error)
	GetCertificateRaw(ctx context.Context, req *CertificateRequest) (*CertificateRawResponse, error)

	// Connection management
	Close() error
}

// CEFServiceClient extends GoodKeyServiceClient with methods needed for
// CEF recipient resolution. These RPCs are not yet part of the GoodKey
// service proto and will be proposed for inclusion.
type CEFServiceClient interface {
	GoodKeyServiceClient

	// LookupRecipient resolves an email address to a recipient key.
	// If the user is enrolled, returns their encryption key.
	// If not enrolled and AutoProvision is true, provisions a key pair
	// and returns it with Status = EnrollmentStatusPending.
	LookupRecipient(ctx context.Context, req *LookupRecipientRequest) (*RecipientInfo, error)

	// LookupRecipients resolves multiple email addresses in a single call.
	LookupRecipients(ctx context.Context, req *LookupRecipientsRequest) (*LookupRecipientsResponse, error)
}

// ClientConfig contains configuration for connecting to the local service.
type ClientConfig struct {
	// Address is the gRPC server address (e.g., "localhost:50051" or "unix:///var/run/goodkey.sock")
	Address string

	// Timeout is the default timeout for operations
	Timeout time.Duration

	// MaxRetries is the maximum number of retries for transient failures
	MaxRetries int
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		Address:    "localhost:50051",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}
}

// client implements CEFServiceClient using a simple JSON-over-TCP protocol.
// The JSON-RPC transport is a reference implementation. The real GoodKey
// service uses gRPC with protobuf serialization.
var _ CEFServiceClient = (*client)(nil)

type client struct {
	config *ClientConfig
	conn   net.Conn
	mu     sync.Mutex
}

// NewClient creates a new client connected to the local GoodKey service.
func NewClient(config *ClientConfig) (GoodKeyServiceClient, error) {
	if config == nil {
		config = DefaultConfig()
	}

	conn, err := net.DialTimeout("tcp", config.Address, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to GoodKey service at %s: %w", config.Address, err)
	}

	return &client{
		config: config,
		conn:   conn,
	}, nil
}

// Close closes the connection to the service.
func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// rpcCall performs an RPC call to the service.
// Simplified JSON-RPC transport. The real GoodKey service uses gRPC.
func (c *client) rpcCall(ctx context.Context, method string, req, resp interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check context
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Build request envelope
	envelope := struct {
		Method string      `json:"method"`
		Data   interface{} `json:"data"`
	}{
		Method: method,
		Data:   req,
	}

	// Set deadline
	if deadline, ok := ctx.Deadline(); ok {
		c.conn.SetDeadline(deadline)
	} else {
		c.conn.SetDeadline(time.Now().Add(c.config.Timeout))
	}

	// Encode and send request
	encoder := json.NewEncoder(c.conn)
	if err := encoder.Encode(envelope); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(c.conn)
	var respEnvelope struct {
		Success bool            `json:"success"`
		Error   string          `json:"error,omitempty"`
		Data    json.RawMessage `json:"data,omitempty"`
	}
	if err := decoder.Decode(&respEnvelope); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if !respEnvelope.Success {
		return fmt.Errorf("RPC error: %s", respEnvelope.Error)
	}

	// Decode response data
	if resp != nil && len(respEnvelope.Data) > 0 {
		if err := json.Unmarshal(respEnvelope.Data, resp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// GetProfile returns the authenticated user's profile.
func (c *client) GetProfile(ctx context.Context) (*ProfileResponse, error) {
	var resp ProfileResponse
	if err := c.rpcCall(ctx, "GetProfile", &EmptyRequest{}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKeys returns keys matching the filter criteria.
func (c *client) GetKeys(ctx context.Context, req *KeyFilterRequest) (*KeyListResponse, error) {
	var resp KeyListResponse
	if err := c.rpcCall(ctx, "GetKeys", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKey returns detailed information about a specific key.
func (c *client) GetKey(ctx context.Context, req *KeyRequest) (*KeyResponse, error) {
	var resp KeyResponse
	if err := c.rpcCall(ctx, "GetKey", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPublicKey returns the public key data.
func (c *client) GetPublicKey(ctx context.Context, req *KeyRequest) (*PublicKeyResponse, error) {
	var resp PublicKeyResponse
	if err := c.rpcCall(ctx, "GetPublicKey", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateKeyOperation creates a new key operation (sign, decrypt, etc.).
func (c *client) CreateKeyOperation(ctx context.Context, req *CreateKeyOperationRequest) (*KeyOperationResponse, error) {
	var resp KeyOperationResponse
	if err := c.rpcCall(ctx, "CreateKeyOperation", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKeyOperation returns the status of a key operation.
func (c *client) GetKeyOperation(ctx context.Context, req *GetKeyOperationRequest) (*KeyOperationResponse, error) {
	var resp KeyOperationResponse
	if err := c.rpcCall(ctx, "GetKeyOperation", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CancelKeyOperation cancels a pending key operation.
func (c *client) CancelKeyOperation(ctx context.Context, req *CancelKeyOperationRequest) (*KeyOperationResponse, error) {
	var resp KeyOperationResponse
	if err := c.rpcCall(ctx, "CancelKeyOperation", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FinalizeKeyOperation completes a key operation with the provided data.
func (c *client) FinalizeKeyOperation(ctx context.Context, req *FinalizeKeyOperationRequest) (*FinalizeKeyOperationResponse, error) {
	var resp FinalizeKeyOperationResponse
	if err := c.rpcCall(ctx, "FinalizeKeyOperation", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCertificates returns all available certificates.
func (c *client) GetCertificates(ctx context.Context) (*CertificateListResponse, error) {
	var resp CertificateListResponse
	if err := c.rpcCall(ctx, "GetCertificates", &EmptyRequest{}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCertificate returns detailed information about a certificate.
func (c *client) GetCertificate(ctx context.Context, req *CertificateRequest) (*CertificateResponse, error) {
	var resp CertificateResponse
	if err := c.rpcCall(ctx, "GetCertificate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetCertificateRaw returns the raw certificate data.
func (c *client) GetCertificateRaw(ctx context.Context, req *CertificateRequest) (*CertificateRawResponse, error) {
	var resp CertificateRawResponse
	if err := c.rpcCall(ctx, "GetCertificateRaw", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// --- Helper methods for common workflows ---

// WaitForApproval polls for operation approval with the given interval.
// Returns when the operation is approved, completed, cancelled, or failed.
func (c *client) WaitForApproval(ctx context.Context, keyID, operationID string, pollInterval time.Duration) (*KeyOperationResponse, error) {
	req := &GetKeyOperationRequest{
		KeyID:       keyID,
		OperationID: operationID,
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		op, err := c.GetKeyOperation(ctx, req)
		if err != nil {
			return nil, err
		}

		// Check if operation is complete (no more approvals needed or terminal state)
		switch op.Status {
		case string(OperationStatusApproved), string(OperationStatusCompleted):
			return op, nil
		case string(OperationStatusCancelled), string(OperationStatusFailed):
			if op.Error != "" {
				return nil, fmt.Errorf("operation %s: %s", op.Status, op.Error)
			}
			return nil, fmt.Errorf("operation %s", op.Status)
		}

		// Still pending, wait and retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// SignData is a convenience method that creates a sign operation, waits for approval, and finalizes.
func (c *client) SignData(ctx context.Context, keyID string, algorithm AlgorithmIdentifier, data []byte) ([]byte, error) {
	// Create the operation
	op, err := c.CreateKeyOperation(ctx, &CreateKeyOperationRequest{
		KeyID: keyID,
		Type:  string(OperationTypeSign),
		Name:  algorithm.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sign operation: %w", err)
	}

	// Wait for approval if needed
	if op.ApprovalsLeft > 0 {
		op, err = c.WaitForApproval(ctx, keyID, op.ID, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("approval failed: %w", err)
		}
	}

	// Finalize with data
	result, err := c.FinalizeKeyOperation(ctx, &FinalizeKeyOperationRequest{
		KeyID:       keyID,
		OperationID: op.ID,
		Data:        data,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to finalize sign operation: %w", err)
	}

	return result.Data, nil
}

// DecryptData is a convenience method that creates a decrypt operation, waits for approval, and finalizes.
func (c *client) DecryptData(ctx context.Context, keyID string, algorithm AlgorithmIdentifier, ciphertext []byte) ([]byte, error) {
	// Create the operation
	op, err := c.CreateKeyOperation(ctx, &CreateKeyOperationRequest{
		KeyID: keyID,
		Type:  string(OperationTypeDecrypt),
		Name:  algorithm.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypt operation: %w", err)
	}

	// Wait for approval if needed
	if op.ApprovalsLeft > 0 {
		op, err = c.WaitForApproval(ctx, keyID, op.ID, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("approval failed: %w", err)
		}
	}

	// Finalize with data
	result, err := c.FinalizeKeyOperation(ctx, &FinalizeKeyOperationRequest{
		KeyID:       keyID,
		OperationID: op.ID,
		Data:        ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to finalize decrypt operation: %w", err)
	}

	return result.Data, nil
}


// LookupRecipient looks up a recipient by email.
func (c *client) LookupRecipient(ctx context.Context, req *LookupRecipientRequest) (*RecipientInfo, error) {
	var resp RecipientInfo
	if err := c.rpcCall(ctx, "LookupRecipient", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LookupRecipients looks up multiple recipients by email.
func (c *client) LookupRecipients(ctx context.Context, req *LookupRecipientsRequest) (*LookupRecipientsResponse, error) {
	var resp LookupRecipientsResponse
	if err := c.rpcCall(ctx, "LookupRecipients", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
