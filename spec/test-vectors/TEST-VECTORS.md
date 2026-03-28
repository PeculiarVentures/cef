# CEF Interoperability Test Vectors

These test vectors enable independent implementations to verify conformance
with the CEF format specification. All values are hex-encoded unless noted.

DO NOT use these keys in production.

## 1. AES-256 Key Wrap (RFC 3394)

```
KEK:         000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Plaintext:   deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
Expected:    05ef35ca76c10fa50ed1d8cb9d92ab6cfd6ba75c7d29fcbf78f332d2fecbc1fb8f05f75c636b3019
```

A conforming implementation MUST produce the expected output. This vector
is derived from RFC 3394 §4 using a 256-bit KEK and 256-bit plaintext.

## 2. Enc_structure (COSE RFC 9052 §5.3)

Input:
```
context:      "Encrypt"                   (UTF-8 string)
protected:    a10103                      (CBOR: {1: 3} = AES-256-GCM)
external_aad: (empty)                     (zero-length bstr)
```

Expected Enc_structure (CBOR array):
```
8367456e637279707443a1010340
```

Length: 14 bytes.

A conforming implementation MUST produce this Enc_structure when building
the AAD for AES-GCM encryption with AES-256-GCM and no external AAD.

## 3. Sig_structure (COSE RFC 9052 §4.4)

Input:
```
context:      "Signature1"                (UTF-8 string)
protected:    a10126                      (CBOR: {1: -7} = ES256)
external_aad: (empty)                     (zero-length bstr)
payload:      74657374207061796c6f6164    ("test payload" in UTF-8)
```

Expected Sig_structure (CBOR array):
```
846a5369676e61747572653143a10126404c74657374207061796c6f6164
```

## 4. COSE_Encrypt (complete structure)

Input:
```
plaintext:    "CEF test vector payload."  (24 bytes, UTF-8)
CEK:          deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
IV:           000102030405060708090a0b
KEK:          000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
kid:           "test-vector-key-001"       (UTF-8 string)
algorithm:    3                           (AES-256-GCM)
key_wrap_alg: -5                          (A256KW)
```

Expected COSE_Encrypt CBOR (tag 96):
```
d8608443a10103a1054c000102030405060708090a0b5828b74f27a023401ee6fbf947a43254104e67a60332cdfd785544c849659fdbe40e2bcf36c6bbcceda4818343a10124a10453746573742d766563746f722d6b65792d303031582805ef35ca76c10fa50ed1d8cb9d92ab6cfd6ba75c7d29fcbf78f332d2fecbc1fb8f05f75c636b3019
```

Length: 134 bytes.

Structure breakdown:
```
d860                                      CBOR tag 96 (COSE_Encrypt)
  84                                      array(4)
    43a10103                              protected: {1: 3}  (A256GCM)
    a1054c000102030405060708090a0b        unprotected: {5: h'000102...0b'}  (IV)
    5828b34139a0...d8b7c782               ciphertext (40 bytes = 24 plaintext + 16 GCM tag)
    81                                    recipients: array(1)
      83                                  array(3)
        43a10124                          recipient protected: {1: -5}  (A256KW)
        a10453746573742d766563746f722d6b65792d303031
                                          recipient unprotected: {4: "test-vector-key-001"}
        582805ef35ca...636b3019           wrapped CEK (40 bytes)
```

## 5. COSE_Sign1 Sig_structure

Input:
```
payload:      "CEF Sign1 test vector payload."  (30 bytes, UTF-8)
algorithm:    -7                                 (ES256)
kid:           "test-signer-key"                  (UTF-8 string)
```

Expected Sig_structure:
```
846a5369676e61747572653143a1012640581e434546205369676e31207465737420766563746f72207061796c6f61642e
```

Length: 49 bytes.

To verify interop: compute the Sig_structure from the same inputs and
confirm the hex matches. Then sign with your ES256 key and verify the
COSE_Sign1 structure round-trips correctly. The signature itself is
non-deterministic (ECDSA), so only the Sig_structure is testable
across implementations.

## 6. Manifest CBOR

Input (JSON equivalent):
```json
{
  "version": "0",
  "sender": {
    "kid": "key-sign-p256",
    "claims": {
      "email": "alice@example.com",
      "created_at": "2026-03-28T12:00:00Z"
    }
  },
  "recipients": [
    {"kid": "key-encrypt-001", "type": "key"},
    {"kid": "eng-team-key", "type": "group", "claims": {"group_id": "eng-team"}}
  ],
  "files": {
    "a1b2c3d4.cose": {
      "original_name": "report.pdf",
      "hash_algorithm": -16,
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 1024
    }
  }
}
```

Expected CBOR (deterministic encoding per RFC 8949 §4.2.1, from Go
reference implementation):
```
a46776657273696f6e61306566696c6573a16d61316232633364342e636f7365a46d6f726967696e616c5f6e616d656a7265706f72742e70646664686173685820e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8556e686173685f616c676f726974686d2f6473697a651904006673656e646572a2636b69646d6b65792d7369676e2d7032353666636c61696d73a265656d61696c71616c696365406578616d706c652e636f6d6a637265617465645f61741a69c7c2c06a726563697069656e747382a2636b69646f6b65792d656e63727970742d3030316474797065636b6579a3636b69646c656e672d7465616d2d6b657964747970656567726f757066636c61696d73a16867726f75705f696468656e672d7465616d
```

Length: 292 bytes.

Notes:
- `created_at` is a sender claim (§5.5), not a top-level manifest field.
- `hash_algorithm` is a COSE integer (-16 = SHA-256, encoded as CBOR
  major type 1: `2f` = -16 in one byte).
- Map keys are sorted by encoded form per deterministic CBOR rules.

## Negative Test Cases

A conforming implementation MUST reject the following:

1. **Truncated COSE_Encrypt**: Any CBOR that starts with tag 96 but
   contains fewer than 4 array elements.

2. **Wrong CBOR tag**: A COSE_Encrypt structure with tag 97 instead of 96.

3. **Wrong content algorithm**: A COSE_Encrypt protected header with
   algorithm 1 (A128GCM) instead of 3 (A256GCM). Implementations
   supporting only A256GCM MUST reject this.

4. **AES Key Unwrap integrity failure**: Unwrapping with a wrong KEK
   MUST return an error, not corrupt plaintext.

5. **Manifest version mismatch**: A manifest with `version: "3.0"` MUST
   be rejected by implementations conforming to this spec.

6. **ZIP entry exceeding size limit**: A ZIP entry claiming to be larger
   than the implementation's maximum (default 2GB) MUST be rejected.
