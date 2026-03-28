#!/usr/bin/env node
/**
 * Cross-SDK interop test.
 *
 * 1. TS encrypts → Go decrypts
 * 2. Go encrypts → TS decrypts
 * 3. Rust encrypts → TS decrypts
 * 4. TS encrypts → Rust decrypts
 * 5. Rust encrypts → Go decrypts
 * 6. Go encrypts → Rust decrypts
 *
 * Run: node test/interop.mjs
 * Requires: Go SDK built, TS SDK built, Rust SDK built
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

  // --- Test 3: Rust encrypts → TS decrypts ---
  console.log('3. Rust encrypts → TS decrypts');

  // Build Rust CLI if needed
  execSync(`cd ${join(root, 'sdk/rust')} && cargo build --bin cef_interop --quiet 2>/dev/null || true`);
  const rustBin = join(root, 'sdk/rust/target/debug/cef_interop');

  // Generate Rust keys
  const rustKeys = execSync(`${rustBin} keygen`, { encoding: 'utf-8' }).trim().split('\n');
  const rustKemPk = rustKeys[0];   // 1184 bytes hex
  const rustKemSk = rustKeys[1];   // 64 bytes hex (seed)
  const rustDsaPk = rustKeys[2];   // 1952 bytes hex
  const rustDsaSk = rustKeys[3];   // 32 bytes hex (seed)

  // TS generates its own KEM key for Rust to encrypt to
  const tsRecipForRust = mlkemKeygen();
  const tsRecipPkHex = Buffer.from(tsRecipForRust.publicKey).toString('hex');
  const tsRecipSkHex = Buffer.from(tsRecipForRust.secretKey).toString('hex');

  // Rust encrypts
  const rustEncInput = JSON.stringify([{ name: 'greetings.txt', data: Buffer.from('hello from Rust').toString('base64') }]);
  const rustContainer = execSync(
    `echo '${rustEncInput}' | ${rustBin} encrypt ${rustDsaSk} rust-sender ${tsRecipPkHex} ts-recipient`,
    { encoding: 'buffer' }
  );
  console.log('   Rust container: ' + rustContainer.length + ' bytes');

  // TS decrypts Rust container
  const tsDecRust = await decrypt(new Uint8Array(rustContainer), {
    recipient: {
      kid: 'ts-recipient',
      decryptionKey: tsRecipForRust.secretKey,
    },
    verify: Buffer.from(rustDsaPk, 'hex'),
  });
  const rustText = new TextDecoder().decode(tsDecRust.files[0].data);
  if (rustText !== 'hello from Rust') {
    console.error('   FAIL: content mismatch:', rustText);
    process.exit(1);
  }
  console.log('   OK: ' + tsDecRust.files[0].originalName + ': ' + rustText);

  // --- Test 4: TS encrypts → Rust decrypts ---
  console.log('4. TS encrypts → Rust decrypts');

  // TS encrypts to Rust's KEM public key
  const tsSenderForRust = mldsaKeygen();
  const tsResultForRust = await encrypt({
    files: [{ name: 'hello.txt', data: new TextEncoder().encode('hello from TypeScript to Rust') }],
    sender: { signingKey: tsSenderForRust.secretKey, kid: 'ts-sender' },
    recipients: [{ kid: 'rust-recipient', encryptionKey: Buffer.from(rustKemPk, 'hex') }],
  });

  writeFileSync(join(tmpDir, 'ts-for-rust.cef'), tsResultForRust.container);
  const tsSenderPkHex = Buffer.from(tsSenderForRust.publicKey).toString('hex');

  // Rust decrypts
  const rustDecOutput = execSync(
    `${rustBin} decrypt ${rustKemSk} rust-recipient ${tsSenderPkHex} < ${join(tmpDir, 'ts-for-rust.cef')}`,
    { encoding: 'utf-8' }
  );
  const rustDecFiles = JSON.parse(rustDecOutput);
  const rustDecText = Buffer.from(rustDecFiles[0].data, 'base64').toString('utf-8');
  if (rustDecText !== 'hello from TypeScript to Rust') {
    console.error('   FAIL: content mismatch:', rustDecText);
    process.exit(1);
  }
  console.log('   OK: ' + rustDecFiles[0].name + ': ' + rustDecText);

  // --- Test 5: Rust encrypts → Go decrypts ---
  console.log('5. Rust encrypts → Go decrypts');

  const goHelper = `
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"github.com/PeculiarVentures/cef/sdk/go/cef"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func main() {
	mode := os.Args[1]
	if mode == "keygen" {
		kemPub, kemSec, _ := mlkem768.GenerateKeyPair(rand.Reader)
		rpub := make([]byte, mlkem768.PublicKeySize)
		kemPub.Pack(rpub)
		rsec := make([]byte, mlkem768.PrivateKeySize)
		kemSec.Pack(rsec)
		keys, _ := json.Marshal(map[string]string{
			"kem_pub": hex.EncodeToString(rpub),
			"kem_sec": hex.EncodeToString(rsec),
		})
		os.WriteFile(os.Args[2], keys, 0644)
		fmt.Println("OK: Go keys generated")
	} else if mode == "decrypt" {
		container, _ := os.ReadFile(os.Args[2])
		keysJSON, _ := os.ReadFile(os.Args[3])
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
}
`;
  writeFileSync(join(tmpDir, 'go_helper.go'), goHelper);

  execSync(
    `cd ${join(root, 'sdk/go')} && go run ${join(tmpDir, 'go_helper.go')} keygen ${join(tmpDir, 'go_kem_keys.json')}`,
    { encoding: 'utf-8' }
  );
  const goKemKeys = JSON.parse(readFileSync(join(tmpDir, 'go_kem_keys.json'), 'utf-8'));

  const rustEncForGo = JSON.stringify([{ name: 'greetings.txt', data: Buffer.from('hello from Rust to Go').toString('base64') }]);
  const rustContainerForGo = execSync(
    `echo '${rustEncForGo}' | ${rustBin} encrypt ${rustDsaSk} rust-sender ${goKemKeys.kem_pub} go-recipient`,
    { encoding: 'buffer' }
  );
  writeFileSync(join(tmpDir, 'rust-for-go.cef'), rustContainerForGo);
  writeFileSync(join(tmpDir, 'rust-for-go-keys.json'), JSON.stringify({
    sender_pub: rustDsaPk,
    recip_sec: goKemKeys.kem_sec,
    recip_kid: 'go-recipient',
  }));

  const goDecRust = execSync(
    `cd ${join(root, 'sdk/go')} && go run ${join(tmpDir, 'go_helper.go')} decrypt ${join(tmpDir, 'rust-for-go.cef')} ${join(tmpDir, 'rust-for-go-keys.json')}`,
    { encoding: 'utf-8' }
  );
  console.log('   ' + goDecRust.trim());

  // --- Test 6: Go encrypts → Rust decrypts ---
  console.log('6. Go encrypts → Rust decrypts');

  const goEncForRust = `
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"github.com/PeculiarVentures/cef/sdk/go/cef"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	dsaPub, dsaSec, _ := mldsa65.GenerateKey(rand.Reader)
	spub, _ := dsaPub.MarshalBinary()
	ssec, _ := dsaSec.MarshalBinary()
	rpub, _ := hex.DecodeString(os.Args[3])

	result, err := cef.Encrypt(cef.EncryptOptions{
		Files:            []cef.FileInput{{Name: "greetings.txt", Data: []byte("hello from Go to Rust")}},
		SenderSigningKey: ssec,
		SenderKID:        "go-sender",
		Recipients:       []cef.Recipient{{KID: "rust-recipient", EncryptionKey: rpub}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\\n", err)
		os.Exit(1)
	}
	os.WriteFile(os.Args[1], result.Container, 0644)
	keys, _ := json.Marshal(map[string]string{
		"sender_pub": hex.EncodeToString(spub),
	})
	os.WriteFile(os.Args[2], keys, 0644)
	fmt.Println("OK: Go encrypted for Rust")
}
`;
  writeFileSync(join(tmpDir, 'go_enc_for_rust.go'), goEncForRust);
  const goEncRustOut = execSync(
    `cd ${join(root, 'sdk/go')} && go run ${join(tmpDir, 'go_enc_for_rust.go')} ${join(tmpDir, 'go-for-rust.cef')} ${join(tmpDir, 'go-for-rust-keys.json')} ${rustKemPk}`,
    { encoding: 'utf-8' }
  );
  console.log('   ' + goEncRustOut.trim());

  const goForRustKeys = JSON.parse(readFileSync(join(tmpDir, 'go-for-rust-keys.json'), 'utf-8'));
  const rustDecGoOutput = execSync(
    `${rustBin} decrypt ${rustKemSk} rust-recipient ${goForRustKeys.sender_pub} < ${join(tmpDir, 'go-for-rust.cef')}`,
    { encoding: 'utf-8' }
  );
  const rustDecGoFiles = JSON.parse(rustDecGoOutput);
  const rustDecGoText = Buffer.from(rustDecGoFiles[0].data, 'base64').toString('utf-8');
  if (rustDecGoText !== 'hello from Go to Rust') {
    console.error('   FAIL: content mismatch:', rustDecGoText);
    process.exit(1);
  }
  console.log('   OK: ' + rustDecGoFiles[0].name + ': ' + rustDecGoText);

  console.log('\n=== All interop tests passed ===');
} finally {
  rmSync(tmpDir, { recursive: true, force: true });
}
