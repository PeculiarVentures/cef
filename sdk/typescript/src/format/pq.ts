/**
 * Post-quantum cryptographic operations for CEF.
 *
 * Uses @noble/post-quantum for ML-KEM-768 (FIPS 203) key encapsulation
 * and ML-DSA-65 (FIPS 204) digital signatures.
 *
 * ⚠️  PROTOTYPING ONLY — not for production use.
 * noble-post-quantum is audited but not FIPS-certified. Use the Go SDK
 * with CIRCL for production PQ workloads.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { aesKeyWrap, aesKeyUnwrap, sha256, zeroize } from './crypto.js';

const subtle = globalThis.crypto.subtle;

/** Convert Uint8Array to BufferSource for WebCrypto compatibility. */
function buf(data: Uint8Array): BufferSource {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}
import {
  AlgMLKEM768_A256KW, AlgMLDSA65, HeaderKeyID,
  type RecipientInfo, type Recipient,
  type WrapCEKFunc, type UnwrapCEKFunc,
  type SignFunc, type VerifyFunc,
} from './cose.js';

// Re-export algorithm IDs for convenience
export { AlgMLKEM768_A256KW, AlgMLDSA65 };

// Domain separation label — must match Go SDK
const DOMAIN_LABEL = 'CEF-ML-KEM-768-A256KW';

// ---------------------------------------------------------------------------
// ML-KEM-768 key encapsulation
// ---------------------------------------------------------------------------

export interface MLKEMKeyPair {
  publicKey: Uint8Array;  // 1184 bytes
  secretKey: Uint8Array;  // 2400 bytes
}

/**
 * Generate an ML-KEM-768 key pair.
 */
export function mlkemKeygen(): MLKEMKeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

/**
 * Derive a 256-bit KEK from an ML-KEM shared secret using HKDF-SHA256 (RFC 5869).
 *
 * Parameters:
 * - IKM: ML-KEM shared secret (32 bytes)
 * - salt: empty (zero-length)
 * - info: domain label "CEF-ML-KEM-768-A256KW"
 * - length: 32 bytes
 *
 * Must match the Go implementation.
 */
async function deriveMLKEMKEK(sharedSecret: Uint8Array): Promise<Uint8Array> {
  const info = new TextEncoder().encode(DOMAIN_LABEL);

  // Import shared secret as HKDF key material
  const ikm = await subtle.importKey('raw', buf(sharedSecret), 'HKDF', false, ['deriveBits']);

  // HKDF-SHA256: Extract + Expand
  const derived = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: buf(info) },
    ikm,
    256, // 32 bytes
  );

  return new Uint8Array(derived);
}

/**
 * Create a WrapCEKFunc that uses ML-KEM-768 encapsulation.
 *
 * The recipient's public key must be provided in RecipientInfo.publicKey
 * (1184 bytes, raw ML-KEM-768 public key).
 */
export function mlkemWrapCEK(recipientPublicKeys: Map<string, Uint8Array>): WrapCEKFunc {
  return async (cek: Uint8Array, recipient: RecipientInfo): Promise<Uint8Array> => {
    const pk = recipientPublicKeys.get(recipient.keyId);
    if (!pk) {
      throw new Error(`mlkem: no public key for recipient ${recipient.keyId}`);
    }

    // Encapsulate — produces ciphertext + shared secret
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pk);

    // Derive KEK from shared secret with domain separation
    const kek = await deriveMLKEMKEK(sharedSecret);

    // Zeroize shared secret immediately after KEK derivation
    zeroize(sharedSecret);

    // Wrap CEK with derived KEK
    const wrappedCEK = await aesKeyWrap(kek, cek);

    // Zeroize KEK immediately after wrapping
    zeroize(kek);

    // Return ciphertext || wrappedCEK
    // The recipient needs the ML-KEM ciphertext to decapsulate,
    // then the wrapped CEK to unwrap.
    const result = new Uint8Array(cipherText.length + wrappedCEK.length);
    result.set(cipherText);
    result.set(wrappedCEK, cipherText.length);
    return result;
  };
}

/**
 * Create an UnwrapCEKFunc that uses ML-KEM-768 decapsulation.
 */
export function mlkemUnwrapCEK(secretKey: Uint8Array): UnwrapCEKFunc {
  return async (wrappedData: Uint8Array, _recipient: Recipient): Promise<Uint8Array> => {
    // ML-KEM-768 ciphertext is 1088 bytes
    const ctLen = 1088;
    if (wrappedData.length <= ctLen) {
      throw new Error(`mlkem: wrapped data too short (${wrappedData.length} bytes, need >${ctLen})`);
    }

    const cipherText = wrappedData.slice(0, ctLen);
    const wrappedCEK = wrappedData.slice(ctLen);

    // Decapsulate to recover shared secret
    const sharedSecret = ml_kem768.decapsulate(cipherText, secretKey);

    // Derive KEK with same domain separation
    const kek = await deriveMLKEMKEK(sharedSecret);

    // Zeroize shared secret immediately after KEK derivation
    zeroize(sharedSecret);

    // Unwrap CEK
    const cekResult = await aesKeyUnwrap(kek, wrappedCEK);

    // Zeroize KEK immediately after unwrapping
    zeroize(kek);

    return cekResult;
  };
}

// ---------------------------------------------------------------------------
// ML-DSA-65 digital signatures
// ---------------------------------------------------------------------------

export interface MLDSAKeyPair {
  publicKey: Uint8Array;  // 1952 bytes
  secretKey: Uint8Array;  // 4032 bytes
}

/**
 * Generate an ML-DSA-65 key pair.
 */
export function mldsaKeygen(): MLDSAKeyPair {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return { publicKey, secretKey };
}

/**
 * Create a SignFunc using ML-DSA-65.
 */
export function mldsaSign(secretKey: Uint8Array): SignFunc {
  return async (sigStructure: Uint8Array): Promise<Uint8Array> => {
    return ml_dsa65.sign(sigStructure, secretKey);
  };
}

/**
 * Create a VerifyFunc using ML-DSA-65.
 */
export function mldsaVerify(publicKey: Uint8Array): VerifyFunc {
  return async (sigStructure: Uint8Array, signature: Uint8Array): Promise<void> => {
    const valid = ml_dsa65.verify(signature, sigStructure, publicKey);
    if (!valid) {
      throw new Error('ML-DSA-65: signature verification failed');
    }
  };
}

/**
 * Raw ML-DSA-65 sign (synchronous, for certificate generation).
 * Returns a function that signs a message with the given secret key.
 */
export function mldsaSignRaw(secretKey: Uint8Array): (message: Uint8Array) => Uint8Array {
  return (message: Uint8Array): Uint8Array => {
    return ml_dsa65.sign(message, secretKey);
  };
}
