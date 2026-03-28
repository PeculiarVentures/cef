/**
 * CEF shared cryptographic primitives.
 *
 * Uses the Web Crypto API (SubtleCrypto) for all operations, making this
 * compatible with browsers, Node.js 20+, Deno, and Cloudflare Workers.
 */

// Use globalThis.crypto for cross-platform compatibility
const subtle = globalThis.crypto.subtle;

/**
 * Convert Uint8Array to BufferSource for WebCrypto API compatibility.
 * Required for TypeScript 5.7+ which distinguishes ArrayBuffer from ArrayBufferLike.
 */
function buf(data: Uint8Array): BufferSource {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

/**
 * AES Key Wrap (RFC 3394).
 *
 * Wraps a key using AES-KW with a 128, 192, or 256-bit KEK.
 */
export async function aesKeyWrap(kek: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error(`keywrap: KEK must be 16, 24, or 32 bytes, got ${kek.length}`);
  }
  if (plaintext.length % 8 !== 0 || plaintext.length < 16) {
    throw new Error(`keywrap: plaintext must be ≥16 bytes and a multiple of 8, got ${plaintext.length}`);
  }

  const wrapKey = await subtle.importKey('raw', buf(kek), 'AES-KW', false, ['wrapKey']);

  // Import plaintext as a raw AES key so we can use wrapKey()
  const keyToWrap = await subtle.importKey('raw', buf(plaintext), { name: 'AES-GCM', length: plaintext.length * 8 }, true, ['encrypt']);

  const wrapped = await subtle.wrapKey('raw', keyToWrap, wrapKey, 'AES-KW' as unknown as Algorithm);
  return new Uint8Array(wrapped);
}

/**
 * AES Key Unwrap (RFC 3394).
 *
 * Unwraps a key using AES-KW. Returns the plaintext key bytes.
 * Throws if the integrity check fails (wrong KEK or tampered ciphertext).
 */
export async function aesKeyUnwrap(kek: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (kek.length !== 16 && kek.length !== 24 && kek.length !== 32) {
    throw new Error(`keyunwrap: KEK must be 16, 24, or 32 bytes, got ${kek.length}`);
  }
  if (ciphertext.length % 8 !== 0 || ciphertext.length < 24) {
    throw new Error(`keyunwrap: ciphertext must be ≥24 bytes and a multiple of 8, got ${ciphertext.length}`);
  }

  const unwrapKey = await subtle.importKey('raw', buf(kek), 'AES-KW', false, ['unwrapKey']);

  // The unwrapped key length is ciphertext.length - 8
  const keyLength = (ciphertext.length - 8) * 8;

  try {
    const unwrapped = await subtle.unwrapKey(
      'raw',
      buf(ciphertext),
      unwrapKey,
      'AES-KW',
      { name: 'AES-GCM', length: keyLength },
      true,
      ['encrypt']
    );
    const exported = await subtle.exportKey('raw', unwrapped);
    return new Uint8Array(exported);
  } catch {
    throw new Error('keyunwrap: integrity check failed');
  }
}

/**
 * AES-256-GCM encrypt.
 *
 * Returns ciphertext with appended 128-bit authentication tag.
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`AES-256-GCM requires 32-byte key, got ${key.length}`);
  }
  if (iv.length !== 12) {
    throw new Error(`AES-GCM requires 12-byte IV, got ${iv.length}`);
  }

  const cryptoKey = await subtle.importKey('raw', buf(key), 'AES-GCM', false, ['encrypt']);

  const params: AesGcmParams = { name: 'AES-GCM', iv: buf(iv), tagLength: 128 };
  if (aad && aad.length > 0) {
    params.additionalData = buf(aad);
  }

  const result = await subtle.encrypt(params, cryptoKey, buf(plaintext));
  return new Uint8Array(result);
}

/**
 * AES-256-GCM decrypt.
 *
 * Expects ciphertext with appended 128-bit authentication tag.
 * Throws if authentication fails.
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error(`AES-256-GCM requires 32-byte key, got ${key.length}`);
  }
  if (iv.length !== 12) {
    throw new Error(`AES-GCM requires 12-byte IV, got ${iv.length}`);
  }

  const cryptoKey = await subtle.importKey('raw', buf(key), 'AES-GCM', false, ['decrypt']);

  const params: AesGcmParams = { name: 'AES-GCM', iv: buf(iv), tagLength: 128 };
  if (aad && aad.length > 0) {
    params.additionalData = buf(aad);
  }

  try {
    const result = await subtle.decrypt(params, cryptoKey, buf(ciphertext));
    return new Uint8Array(result);
  } catch {
    throw new Error('AES-GCM: authentication failed');
  }
}

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  // WebCrypto getRandomValues has a 65536-byte limit per call
  const chunkSize = 65536;
  for (let offset = 0; offset < length; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, length);
    globalThis.crypto.getRandomValues(buf.subarray(offset, end));
  }
  return buf;
}

/**
 * SHA-256 digest.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await subtle.digest('SHA-256', buf(data));
  return new Uint8Array(hash);
}

/**
 * Zeroize a Uint8Array. Best-effort in JS (GC may retain copies).
 */
export function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/**
 * Constant-time byte comparison.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}

/**
 * Hex encode a Uint8Array.
 */
export function toHex(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hex decode a string to Uint8Array.
 */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
