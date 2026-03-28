// Command cef is the CEF Secure File Exchange CLI.
//
// Usage:
//
//	cef encrypt [flags] <files...>    Encrypt files into a .cef container
//	cef decrypt [flags] <file.cef>    Decrypt a .cef container
//	cef verify <file.cef>             Verify container structure
//	cef keys                          List available keys
//	cef certs                         List available certificates
//	cef profile                       Show current user profile
//	cef demo                          Run end-to-end demo
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/PeculiarVentures/cef/sdk/go/goodkey/exchange"
	"github.com/PeculiarVentures/cef/sdk/go/goodkey/ipc"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		cmdEncrypt(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "keys":
		cmdKeys()
	case "certs":
		cmdCerts()
	case "profile":
		cmdProfile()
	case "demo":
		cmdDemo()
	case "version", "-v", "--version":
		fmt.Printf("cef %s (COSE/CBOR)\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`cef %s - CEF Secure File Exchange (COSE/CBOR)

Commands:
  encrypt   Encrypt files into a .cef container
  decrypt   Decrypt a .cef container
  verify    Verify container structure and signature
  keys      List available keys
  certs     List available certificates
  profile   Show current user profile
  demo      Run end-to-end demonstration

Encrypt:
  cef encrypt [flags] <files...>
    -r <key-id>      Recipient key ID (repeatable)
    -e <email>       Recipient email, encrypt-to-anyone (repeatable)
    -c <cert.pem>    Recipient certificate file (repeatable)
    --cert-id <id>   Recipient certificate ID in GoodKey (repeatable)
    -g <group-id>    Recipient group ID (repeatable)
    -k <key-id>      Sender signing key (required)
    -o <path>        Output file (default: first_input.cef)

Decrypt:
  cef decrypt [flags] <file.cef>
    -k <key-id>      Recipient key for decryption (required)
    --cert-id <id>   Recipient certificate for decryption
    -o <dir>         Output directory (default: ./decrypted)
    --no-verify      Skip sender signature verification

Verify:
  cef verify <file.cef>
`, version)
}

func cmdEncrypt(args []string) {
	var recipients, emails, groups, certFiles, certIDs []string
	var senderKey, output string
	var files []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-r":
			i++
			if i < len(args) {
				recipients = append(recipients, args[i])
			}
		case "-e":
			i++
			if i < len(args) {
				emails = append(emails, args[i])
			}
		case "-c":
			i++
			if i < len(args) {
				certFiles = append(certFiles, args[i])
			}
		case "--cert-id":
			i++
			if i < len(args) {
				certIDs = append(certIDs, args[i])
			}
		case "-g":
			i++
			if i < len(args) {
				groups = append(groups, args[i])
			}
		case "-k":
			i++
			if i < len(args) {
				senderKey = args[i]
			}
		case "-o":
			i++
			if i < len(args) {
				output = args[i]
			}
		default:
			if args[i][0] != '-' {
				files = append(files, args[i])
			}
		}
	}

	if len(files) == 0 {
		fatal("no input files specified")
	}
	if senderKey == "" {
		senderKey = "key-sign-mldsa65" // demo default
	}
	if output == "" {
		output = files[0] + ".cef"
	}

	svc := newService()
	result, err := svc.EncryptFiles(context.Background(), files, output, &exchange.EncryptOptions{
		Recipients:         recipients,
		RecipientEmails:    emails,
		RecipientGroups:    groups,
		RecipientCertFiles: certFiles,
		RecipientCertIDs:   certIDs,
		SenderKeyID:        senderKey,
	})
	if err != nil {
		fatal("encryption failed: %v", err)
	}

	fmt.Printf("Created: %s\n", result.ContainerPath)
	fmt.Printf("  Files:      %d\n", result.FileCount)
	fmt.Printf("  Signed:     %v\n", result.Signed)
	fmt.Printf("  Recipients: %s\n", strings.Join(result.Recipients, ", "))
	if len(result.PendingRecipients) > 0 {
		fmt.Printf("  Pending:    %s\n", strings.Join(result.PendingRecipients, ", "))
	}
}

func cmdDecrypt(args []string) {
	var keyID, outputDir, containerPath string
	skipVerify := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k":
			i++
			if i < len(args) {
				keyID = args[i]
			}
		case "-o":
			i++
			if i < len(args) {
				outputDir = args[i]
			}
		case "--no-verify":
			skipVerify = true
		default:
			if args[i][0] != '-' {
				containerPath = args[i]
			}
		}
	}

	if containerPath == "" {
		fatal("no container file specified")
	}
	if keyID == "" {
		keyID = "key-encrypt-mlkem768" // demo default
	}
	if outputDir == "" {
		outputDir = "./decrypted"
	}

	svc := newService()
	result, err := svc.DecryptContainer(context.Background(), containerPath, &exchange.DecryptOptions{
		RecipientKeyID:            keyID,
		OutputDir:                 outputDir,
		SkipSignatureVerification: skipVerify,
	})
	if err != nil {
		fatal("decryption failed: %v", err)
	}

	fmt.Printf("Decrypted %d file(s) to %s\n", len(result.Files), outputDir)
	for _, f := range result.Files {
		status := "OK"
		if !f.HashValid {
			status = "HASH MISMATCH"
		}
		fmt.Printf("  %s (%d bytes) [%s]\n", f.OriginalName, f.Size, status)
	}
	fmt.Printf("Sender key: %s\n", result.SenderKID)
	if result.SenderClaimsEmail != "" {
		fmt.Printf("Sender email (unverified claim): %s\n", result.SenderClaimsEmail)
	}
	if result.SignatureValid {
		fmt.Println("Signature: VALID")
	}
}

func cmdVerify(args []string) {
	if len(args) == 0 {
		fatal("no container file specified")
	}

	svc := newService()
	result, err := svc.VerifyContainer(context.Background(), args[0])
	if err != nil {
		fatal("verification failed: %v", err)
	}

	fmt.Printf("Container:  %v\n", boolStr(result.ContainerValid, "VALID", "INVALID"))
	fmt.Printf("Signature:  %v\n", boolStr(result.SignaturePresent, "PRESENT", "ABSENT"))
	fmt.Printf("Files:      %d\n", result.FileCount)
	if len(result.Errors) > 0 {
		for _, e := range result.Errors {
			fmt.Printf("  Error: %s\n", e)
		}
	}
}

func cmdKeys() {
	svc := newService()
	ctx := context.Background()

	fmt.Println("Signing Keys (AUTH):")
	signKeys, _ := svc.ListSigningKeys(ctx)
	if len(signKeys) == 0 {
		fmt.Println("  (none)")
	}
	for _, k := range signKeys {
		fmt.Printf("  %-24s %s\n", k.ID, k.Name)
	}

	fmt.Println("\nEncryption Keys (CIPHER):")
	encKeys, _ := svc.ListEncryptionKeys(ctx)
	if len(encKeys) == 0 {
		fmt.Println("  (none)")
	}
	for _, k := range encKeys {
		fmt.Printf("  %-24s %s\n", k.ID, k.Name)
	}
}

func cmdCerts() {
	svc := newService()
	ctx := context.Background()

	fmt.Println("Certificates:")
	certs, _ := svc.ListCertificates(ctx)
	if len(certs) == 0 {
		fmt.Println("  (none)")
	}
	for _, c := range certs {
		fmt.Printf("  %-24s %s (key: %s)\n", c.ID, c.Name, c.KeyID)
	}
}

func cmdProfile() {
	svc := newService()
	profile, err := svc.GetProfile(context.Background())
	if err != nil {
		fatal("get profile: %v", err)
	}
	fmt.Printf("User:         %s %s\n", profile.FirstName, profile.LastName)
	fmt.Printf("Email:        %s\n", profile.Email)
	if profile.Organization != nil {
		fmt.Printf("Organization: %s\n", profile.Organization.Name)
	}
}

func cmdDemo() {
	fmt.Printf("=== GoodKey File Exchange Demo (COSE/CBOR v%s) ===\n\n", version)

	mock := ipc.NewMockClient()
	svc := exchange.NewService(mock)
	ctx := context.Background()

	// 1. Profile
	profile, _ := svc.GetProfile(ctx)
	fmt.Printf("1. User: %s (%s)\n\n", profile.Email, profile.Organization.Name)

	// 2. Create test file
	tmpDir, _ := os.MkdirTemp("", "cef-demo-*")
	defer os.RemoveAll(tmpDir)

	testFile := tmpDir + "/classified.txt"
	os.WriteFile(testFile, []byte("TOP SECRET: Project Phoenix launch date is April 15."), 0644)
	fmt.Printf("2. Test file: %s\n\n", testFile)

	// 3. Add group key and encrypt
	groupKey := make([]byte, 32)
	for i := range groupKey {
		groupKey[i] = byte(i + 42)
	}
	mock.AddSymmetricKey("group-board", "Board of Directors", groupKey)

	outputFile := tmpDir + "/classified.cef"
	result, err := svc.EncryptFiles(ctx, []string{testFile}, outputFile, &exchange.EncryptOptions{
		Recipients:      []string{"key-encrypt-mlkem768"},
		RecipientEmails: []string{"newexec@example.com"},
		RecipientGroups: []string{"group-board"},
		SenderKeyID:     "key-sign-mldsa65",
	})
	if err != nil {
		fatal("encrypt: %v", err)
	}

	fi, _ := os.Stat(outputFile)
	fmt.Printf("3. Encrypted: %s (%d bytes)\n", outputFile, fi.Size())
	fmt.Printf("   Recipients: %d\n", len(result.Recipients))
	for _, r := range result.Recipients {
		fmt.Printf("     - %s\n", r)
	}
	if len(result.PendingRecipients) > 0 {
		fmt.Printf("   Pending enrollment: %s\n", strings.Join(result.PendingRecipients, ", "))
	}
	fmt.Println()

	// 4. Decrypt as direct key recipient
	decDir1 := tmpDir + "/dec-direct"
	dec1, err := svc.DecryptContainer(ctx, outputFile, &exchange.DecryptOptions{
		RecipientKeyID: "key-encrypt-mlkem768", OutputDir: decDir1,
	})
	if err != nil {
		fatal("decrypt (direct): %v", err)
	}
	content, _ := os.ReadFile(dec1.Files[0].OutputPath)
	fmt.Printf("4. Decrypted (direct key):\n")
	fmt.Printf("   %s [hash: %v]\n", dec1.Files[0].OriginalName, dec1.Files[0].HashValid)
	fmt.Printf("   Content: %s\n\n", content)

	// 5. Decrypt as group recipient
	decDir2 := tmpDir + "/dec-group"
	dec2, err := svc.DecryptContainer(ctx, outputFile, &exchange.DecryptOptions{
		RecipientKeyID: "group-board", OutputDir: decDir2,
	})
	if err != nil {
		fatal("decrypt (group): %v", err)
	}
	fmt.Printf("5. Decrypted (group key, Board of Directors):\n")
	fmt.Printf("   %s [hash: %v]\n\n", dec2.Files[0].OriginalName, dec2.Files[0].HashValid)

	// 6. Verify
	vr, _ := svc.VerifyContainer(ctx, outputFile)
	fmt.Printf("6. Verify: container=%v signature=%v files=%d\n\n", vr.ContainerValid, vr.SignaturePresent, vr.FileCount)

	fmt.Println("Architecture:")
	fmt.Println("  - ML-KEM-768 + AES-256-KW for key encapsulation (FIPS 203, PQ-secure)")
	fmt.Println("  - ML-DSA-65 for COSE_Sign1 detached signatures (FIPS 204, PQ-secure)")
	fmt.Println("  - AES-256-GCM for content encryption (128-bit security vs Grover's)")
	fmt.Println("  - CBOR manifest, COSE_Encrypt structures, ZIP container")
	fmt.Println("  - Mixed PQ + classical recipients in a single container")
	fmt.Println("  - GoodKey governs all key ops via IPC, private keys never leave HSM")
}

func newService() *exchange.Service {
	return exchange.NewService(ipc.NewMockClient())
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "cef: "+format+"\n", args...)
	os.Exit(1)
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
