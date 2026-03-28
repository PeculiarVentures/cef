// Package container implements the CEF secure file exchange container format.
//
// A .cef container is a ZIP archive:
//
//	container.cef
//	├── META-INF/
//	│   ├── manifest.cbor.cose   # COSE_Encrypt-encrypted CBOR manifest
//	│   ├── manifest.cose-sign1  # COSE_Sign1 detached signature
//	│   └── manifest.tst         # Optional RFC 3161 timestamp token
//	└── encrypted/
//	    └── <obfuscated>.cose    # COSE_Encrypt-encrypted file payloads
//
// The manifest is a CBOR map. Both the manifest and individual files are
// encrypted using COSE_Encrypt with per-recipient key encapsulation managed
// by a key management service.
package container

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// FormatVersion is the container format version.
const FormatVersion = "0"

// HashAlgSHA256 is the COSE algorithm identifier for SHA-256 (RFC 9053 §2.1).
const HashAlgSHA256 int64 = -16

// Well-known ZIP entry paths.
const (
	PathManifest  = "META-INF/manifest.cbor.cose"
	PathSignature = "META-INF/manifest.cose-sign1"
	PathTimestamp = "META-INF/manifest.tst"
	DirEncrypted  = "encrypted/"
)

// Container represents a CEF secure file exchange container.
type Container struct {
	Manifest          Manifest
	EncryptedFiles    map[string][]byte // obfuscated name → COSE_Encrypt bytes
	EncryptedManifest []byte            // COSE_Encrypt bytes
	ManifestSignature []byte            // COSE_Sign1 bytes
	Timestamp         []byte            // Optional RFC 3161 timestamp token
}

// Manifest contains metadata about the container and its files.
type Manifest struct {
	Version    string                  `cbor:"version"`
	Files      map[string]FileMetadata `cbor:"files"`
	Sender     SenderInfo              `cbor:"sender"`
	Recipients []RecipientRef          `cbor:"recipients"`
}

// FileMetadata describes an encrypted file.
type FileMetadata struct {
	OriginalName  string `cbor:"original_name"`
	Hash          []byte `cbor:"hash"`
	HashAlgorithm int64  `cbor:"hash_algorithm"` // COSE algorithm ID: -16 = SHA-256
	Size          int64  `cbor:"size"`
	ContentType   string `cbor:"content_type,omitempty"`
}

// SenderInfo identifies the sender.
//
// The kid field is the key identifier verified via the COSE_Sign1 signature.
// The optional x5c field carries an X.509 certificate chain for verified identity.
// The optional claims field carries unverified hints (email, name) for UI display.
// This follows the IETF convention used by JOSE (RFC 7515), COSE (RFC 9052),
// and CMS (RFC 5652): key identifiers and certificate references, not
// self-asserted identity claims.
type SenderInfo struct {
	KID    string       `cbor:"kid"`
	X5C    [][]byte     `cbor:"x5c,omitempty"`    // X.509 certificate chain (DER)
	Claims *SenderClaims `cbor:"claims,omitempty"` // Unverified hints
}

// SenderClaims contains unverified self-asserted hints about the sender.
// These MUST NOT be used for access control; they exist only for UI display.
type SenderClaims struct {
	Email          string    `cbor:"email,omitempty"`
	Name           string    `cbor:"name,omitempty"`
	CreatedAt      time.Time `cbor:"created_at,omitempty"`      // Sender-asserted creation time

	// Handling marks — sender-asserted labels for recipient handling guidance.
	// Security enforcement is through backend key policy, not these labels.
	Classification string   `cbor:"classification,omitempty"`   // e.g. "TOP SECRET"
	SCIControls    []string `cbor:"sci_controls,omitempty"`     // e.g. ["HCS", "SI"]
	SAPPrograms    []string `cbor:"sap_programs,omitempty"`     // SAP identifiers
	Dissemination  []string `cbor:"dissemination,omitempty"`    // e.g. ["NOFORN", "ORCON"]
	Releasability  string   `cbor:"releasability,omitempty"`    // e.g. "REL TO USA, FVEY"
}

// RecipientRef identifies a recipient in the manifest.
//
// KID is the key identifier used for key unwrapping. The optional type
// field hints how the recipient was resolved (key, email, certificate,
// group). The optional claims field carries unverified hints. The optional
// x5c field carries a certificate chain for verified identity.
type RecipientRef struct {
	KID    string           `cbor:"kid"`
	Type   string           `cbor:"type,omitempty"`    // "key", "certificate", "group"
	X5C    [][]byte         `cbor:"x5c,omitempty"`     // X.509 certificate chain (DER)
	Claims *RecipientClaims `cbor:"claims,omitempty"`  // Unverified hints

	// Extension fields — optional, ignored by current implementations.
	LogicalKeyID string `cbor:"logical_key_id,omitempty"` // Stable named key
	VersionID    string `cbor:"version_id,omitempty"`     // Key material version
	PolicyRef    string `cbor:"policy_ref,omitempty"`     // Policy or attribute reference
}

// RecipientClaims contains unverified self-asserted hints about a recipient.
type RecipientClaims struct {
	Email   string `cbor:"email,omitempty"`
	Name    string `cbor:"name,omitempty"`
	GroupID string `cbor:"group_id,omitempty"`
}

// New creates an empty container.
func New() *Container {
	return &Container{
		Manifest: Manifest{
			Version:    FormatVersion,
			Files:      make(map[string]FileMetadata),
			Recipients: []RecipientRef{},
		},
		EncryptedFiles: make(map[string][]byte),
	}
}

func (c *Container) AddFile(name string, meta FileMetadata, data []byte) {
	c.EncryptedFiles[name] = data
	c.Manifest.Files[name] = meta
}

func (c *Container) SetSender(s SenderInfo)     { c.Manifest.Sender = s }
func (c *Container) AddRecipient(r RecipientRef) { c.Manifest.Recipients = append(c.Manifest.Recipients, r) }
func (c *Container) SetEncryptedManifest(d []byte) { c.EncryptedManifest = d }
func (c *Container) SetSignature(d []byte)         { c.ManifestSignature = d }
func (c *Container) SetTimestamp(d []byte)          { c.Timestamp = d }

func (c *Container) MarshalManifest() ([]byte, error) {
	// Enforce x5c/claims exclusivity (§5.5): when a certificate chain
	// is present, identity comes from the cert — skip unverified claims.
	m := c.Manifest
	if len(m.Sender.X5C) > 0 {
		m.Sender.Claims = nil
	}
	for i := range m.Recipients {
		if len(m.Recipients[i].X5C) > 0 {
			m.Recipients[i].Claims = nil
		}
	}
	return cbor.Marshal(m)
}
func (c *Container) UnmarshalManifest(data []byte) error {
	if err := cbor.Unmarshal(data, &c.Manifest); err != nil {
		return err
	}
	if c.Manifest.Version != FormatVersion {
		return fmt.Errorf("manifest: unsupported version %q (expected %q)", c.Manifest.Version, FormatVersion)
	}
	if c.Manifest.Sender.KID == "" {
		return fmt.Errorf("manifest: sender.kid is required")
	}
	for i, r := range c.Manifest.Recipients {
		if r.KID == "" {
			return fmt.Errorf("manifest: recipient[%d].kid is required", i)
		}
	}
	return nil
}

// Write serializes the container as a ZIP archive.
func (c *Container) Write(w io.Writer) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	if c.EncryptedManifest != nil {
		if err := writeEntry(zw, PathManifest, c.EncryptedManifest); err != nil {
			return err
		}
	}
	if c.ManifestSignature != nil {
		if err := writeEntry(zw, PathSignature, c.ManifestSignature); err != nil {
			return err
		}
	}
	if c.Timestamp != nil {
		if err := writeEntry(zw, PathTimestamp, c.Timestamp); err != nil {
			return err
		}
	}
	for name, data := range c.EncryptedFiles {
		if err := writeEntry(zw, DirEncrypted+name, data); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(zw *zip.Writer, name string, data []byte) error {
	fw, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	if _, err := fw.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func (c *Container) WriteToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := c.Write(f); err != nil {
		return err
	}
	// Ensure data is flushed to disk before close.
	return f.Sync()
}

// Read deserializes a container from a ZIP archive.
func Read(r io.ReaderAt, size int64) (*Container, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	c := New()

	if len(zr.File) > maxZIPEntries {
		return nil, fmt.Errorf("too many ZIP entries (%d > %d)", len(zr.File), maxZIPEntries)
	}

	var totalDecompressed int64
	for _, f := range zr.File {
		data, err := readEntry(f)
		if err != nil {
			return nil, err
		}
		totalDecompressed += int64(len(data))
		if totalDecompressed > maxTotalDecompressed {
			return nil, fmt.Errorf("total decompressed size exceeds limit (%d bytes)", maxTotalDecompressed)
		}

		switch {
		case f.Name == PathManifest:
			c.EncryptedManifest = data
		case f.Name == PathSignature:
			c.ManifestSignature = data
		case f.Name == PathTimestamp:
			c.Timestamp = data
		// Use strings.HasPrefix instead of fragile slice indexing.
		case strings.HasPrefix(f.Name, DirEncrypted):
			name := strings.TrimPrefix(f.Name, DirEncrypted)
			if name != "" {
				c.EncryptedFiles[name] = data
			}
		}
	}
	return c, nil
}

// maxZIPEntrySize limits individual ZIP entry reads to prevent ZIP bombs.
const maxZIPEntrySize = 2 << 30 // 2 GB

// maxZIPEntries limits the number of ZIP entries to prevent resource exhaustion.
const maxZIPEntries = 10000

// maxTotalDecompressed limits total decompressed size across all entries.
const maxTotalDecompressed int64 = 2 << 30 // 2 GB

func readEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer rc.Close()
	// Limit read size to prevent ZIP bomb / memory exhaustion.
	lr := io.LimitReader(rc, maxZIPEntrySize)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name, err)
	}
	if int64(len(data)) >= maxZIPEntrySize {
		return nil, fmt.Errorf("entry %s exceeds maximum size (%d bytes)", f.Name, maxZIPEntrySize)
	}
	return data, nil
}

func ReadFromFile(path string) (*Container, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return Read(f, fi.Size())
}

func (c *Container) ToBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func FromBytes(data []byte) (*Container, error) {
	return Read(bytes.NewReader(data), int64(len(data)))
}

// RandomFileName generates a random obfuscated basename for encrypted entries.
// The caller or container.Write() adds the "encrypted/" prefix.
func RandomFileName() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("cef: crypto/rand failed: " + err.Error())
	}
	return fmt.Sprintf("%x.cose", b)
}
