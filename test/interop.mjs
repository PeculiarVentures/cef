#!/usr/bin/env node
/**
 * Cross-SDK interop test.
 *
 * 1. TS encrypts → Go decrypts (via Go test helper)
 * 2. Go encrypts → TS decrypts (via Go test helper)
 *
 * Run: node test/interop.mjs
 * Requires: Go SDK built, TS SDK built
 */

import { execSync } from 'child_process';
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const tmpDir = mkdtempSync(join(tmpdir(), 'cef-interop-'));

// Import TS SDK
const { encrypt, decrypt } = await import(join(root, 'sdk/typescript/dist/src/index.js'));
const { mlkemKeygen, mldsaKeygen } = await import(join(root, 'sdk/typescript/dist/src/format/pq.js'));

try {
  console.log('=== CEF Cross-SDK Interop Test ===\n');

  // Generate keys
  const sender = mldsaKeygen();
  const recipient = mlkemKeygen();

  // --- Test 1: TS encrypts → Go decrypts ---
  console.log('1. TS encrypts → Go decrypts');

  const tsResult = await encrypt({
    files: [{ name: 'hello.txt', data: new TextEncoder().encode('hello from TypeScript') }],
    sender: { signingKey: sender.secretKey, kid: 'ts-sender' },
    recipients: [{ kid: 'go-recipient', encryptionKey: recipient.publicKey }],
  });

  // Write container and keys for Go
  writeFileSync(join(tmpDir, 'ts-container.cef'), tsResult.container);
  writeFileSync(join(tmpDir, 'keys.json'), JSON.stringify({
    sender_pub: Buffer.from(sender.publicKey).toString('hex'),
    recip_sec: Buffer.from(recipient.secretKey).toString('hex'),
    recip_kid: 'go-recipient',
  }));

  // Go decrypts via test
  const goDecryptTest = `
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"github.com/PeculiarVentures/cef/sdk/go/cef"
)

func main() {
	container, _ := os.ReadFile(os.Args[1])
	keysJSON, _ := os.ReadFile(os.Args[2])

	var keys map[string]string
	json.Unmarshal(keysJSON, &keys)

	spub, _ := hex.DecodeString(keys["sender_pub"])
	rsec, _ := hex.DecodeString(keys["recip_sec"])

	result, err := cef.Decrypt(container, cef.DecryptOptions{
		RecipientKID:           keys["recip_kid"],
		RecipientDecryptionKey: rsec,
		SenderVerificationKey:  spub,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %s: %s\\n", result.Files[0].OriginalName, string(result.Files[0].Data))
}
`;

  writeFileSync(join(tmpDir, 'go_decrypt.go'), goDecryptTest);
  const goOut1 = execSync(
    `cd ${join(root, 'sdk/go')} && go run ${join(tmpDir, 'go_decrypt.go')} ${join(tmpDir, 'ts-container.cef')} ${join(tmpDir, 'keys.json')}`,
    { encoding: 'utf-8' }
  );
  console.log('   ' + goOut1.trim());

  // --- Test 2: Go encrypts → TS decrypts ---
  console.log('2. Go encrypts → TS decrypts');

  const goEncryptTest = `
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"github.com/PeculiarVentures/cef/sdk/go/cef"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	dsaPub, dsaSec, _ := mldsa65.GenerateKey(rand.Reader)
	kemPub, kemSec, _ := mlkem768.GenerateKeyPair(rand.Reader)

	spub, _ := dsaPub.MarshalBinary()
	ssec, _ := dsaSec.MarshalBinary()

	rpub := make([]byte, mlkem768.PublicKeySize)
	kemPub.Pack(rpub)
	rsec := make([]byte, mlkem768.PrivateKeySize)
	kemSec.Pack(rsec)

	result, err := cef.Encrypt(cef.EncryptOptions{
		Files:            []cef.FileInput{{Name: "greetings.txt", Data: []byte("hello from Go")}},
		SenderSigningKey: ssec,
		SenderKID:        "go-sender",
		Recipients:       []cef.Recipient{{KID: "ts-recipient", EncryptionKey: rpub}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\\n", err)
		os.Exit(1)
	}

	os.WriteFile(os.Args[1], result.Container, 0644)
	keys, _ := json.Marshal(map[string]string{
		"sender_pub": hex.EncodeToString(spub),
		"recip_sec":  hex.EncodeToString(rsec),
		"recip_kid":  "ts-recipient",
	})
	os.WriteFile(os.Args[2], keys, 0644)
	fmt.Println("OK: Go encrypted container written")
}
`;

  writeFileSync(join(tmpDir, 'go_encrypt.go'), goEncryptTest);
  const goOut2 = execSync(
    `cd ${join(root, 'sdk/go')} && go run ${join(tmpDir, 'go_encrypt.go')} ${join(tmpDir, 'go-container.cef')} ${join(tmpDir, 'keys2.json')}`,
    { encoding: 'utf-8' }
  );
  console.log('   ' + goOut2.trim());

  // TS decrypts Go container
  const goContainer = readFileSync(join(tmpDir, 'go-container.cef'));
  const goKeys = JSON.parse(readFileSync(join(tmpDir, 'keys2.json'), 'utf-8'));

  const tsDecResult = await decrypt(new Uint8Array(goContainer), {
    recipient: {
      kid: goKeys.recip_kid,
      decryptionKey: Buffer.from(goKeys.recip_sec, 'hex'),
    },
    verify: Buffer.from(goKeys.sender_pub, 'hex'),
  });

  const text = new TextDecoder().decode(tsDecResult.files[0].data);
  if (text !== 'hello from Go') {
    console.error('   FAIL: content mismatch:', text);
    process.exit(1);
  }
  console.log('   OK: ' + tsDecResult.files[0].originalName + ': ' + text);

  console.log('\n=== All interop tests passed ===');
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
