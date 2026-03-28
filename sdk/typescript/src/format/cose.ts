/**
 * CEF COSE profile: COSE_Encrypt (tag 96) and COSE_Sign1 (tag 18).
 *
 * Implements RFC 9052 structures using CBOR encoding. Key operations
 * (wrap, unwrap, sign, verify) are provided via callback functions,
 * making this layer backend-neutral.
 */

import { Encoder } from 'cbor-x';
import { aesGcmEncrypt, aesGcmDecrypt, randomBytes, zeroize, constantTimeEqual } from './crypto.js';

// ---------------------------------------------------------------------------
// COSE Algorithm Identifiers
// ---------------------------------------------------------------------------

export const AlgA256GCM = 3;
export const AlgA256KW = -5;
export const AlgECDH_ES_A256KW = -31;
export const AlgES256 = -7;
export const AlgES384 = -35;
export const AlgES512 = -36;
export const AlgEdDSA = -8;

// ML-DSA (IANA early-allocated, temporary until 2026-04-24)
export const AlgMLDSA44 = -48;
export const AlgMLDSA65 = -49;
export const AlgMLDSA87 = -50;

// ML-KEM (private-use range, pending IANA from draft-ietf-jose-pqc-kem)
// TODO: Update to permanent values when IANA assignment completes.
export const AlgMLKEM768_A256KW = -70010;
export const AlgMLKEM1024_A256KW = -70011;

export const DefaultKeyWrapAlgorithm = AlgMLKEM768_A256KW;
export const DefaultSignatureAlgorithm = AlgMLDSA65;

// COSE header labels
export const HeaderAlgorithm = 1;
export const HeaderKeyID = 4;
export const HeaderIV = 5;

// COSE tags
export const TagEncrypt = 96;
export const TagSign1 = 18;

// CEF private header labels
export const HeaderCEFRecipientType = -70001;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ProtectedHeader = Map<number, unknown>;
export type UnprotectedHeader = Map<number, unknown>;

export interface Recipient {
  protected: ProtectedHeader;
  unprotected: UnprotectedHeader;
  ciphertext: Uint8Array;
}

export interface EncryptMessage {
  protected: ProtectedHeader;
  protectedBytes: Uint8Array;
  unprotected: UnprotectedHeader;
  ciphertext: Uint8Array;
  recipients: Recipient[];
}

export interface Sign1Message {
  protected: ProtectedHeader;
  protectedBytes: Uint8Array;
  unprotected: UnprotectedHeader;
  payload: Uint8Array | null;
  signature: Uint8Array;
}

export interface RecipientInfo {
  keyId: string;
  algorithm: number;
  type?: string;        // "key", "certificate", "group"
  // Extension fields
  logicalKeyId?: string;
  versionId?: string;
  policyRef?: string;
}

export type WrapCEKFunc = (cek: Uint8Array, recipient: RecipientInfo) => Promise<Uint8Array>;
export type UnwrapCEKFunc = (wrappedCEK: Uint8Array, recipient: Recipient) => Promise<Uint8Array>;
export type SignFunc = (sigStructure: Uint8Array) => Promise<Uint8Array>;
export type VerifyFunc = (sigStructure: Uint8Array, signature: Uint8Array) => Promise<void>;

// ---------------------------------------------------------------------------
// Deterministic CBOR encoder
// ---------------------------------------------------------------------------

const cborEncoder = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false,
});

function cborEncode(value: unknown): Uint8Array {
  return cborEncoder.encode(value);
}

function cborDecode(data: Uint8Array): unknown {
  return cborEncoder.decode(data);
}

// ---------------------------------------------------------------------------
// Enc_structure and Sig_structure (RFC 9052)
// ---------------------------------------------------------------------------

export function buildEncStructure(protectedBytes: Uint8Array, externalAAD: Uint8Array = new Uint8Array(0)): Uint8Array {
  return cborEncode(['Encrypt', protectedBytes, externalAAD]);
}

export function buildSigStructure(
  protectedBytes: Uint8Array,
  externalAAD: Uint8Array = new Uint8Array(0),
  payload: Uint8Array,
): Uint8Array {
  return cborEncode(['Signature1', protectedBytes, externalAAD, payload]);
}

// ---------------------------------------------------------------------------
// Protected header encode/decode
// ---------------------------------------------------------------------------

function encodeProtected(header: ProtectedHeader): Uint8Array {
  if (header.size === 0) return new Uint8Array(0);
  return cborEncode(header);
}

function decodeProtected(data: Uint8Array): ProtectedHeader {
  if (data.length === 0) return new Map();
  const decoded = cborDecode(data);
  if (decoded instanceof Map) return decoded as ProtectedHeader;
  throw new Error('cose: protected header is not a CBOR map');
}

// ---------------------------------------------------------------------------
// COSE_Encrypt
// ---------------------------------------------------------------------------

export interface EncryptOpts {
  contentAlgorithm?: number;
  externalAAD?: Uint8Array;
  /** Fixed CEK for test vectors. DO NOT use in production. */
  _testCEK?: Uint8Array;
  /** Fixed IV for test vectors. DO NOT use in production. */
  _testIV?: Uint8Array;
}

/**
 * Create a COSE_Encrypt message (tag 96).
 *
 * Generates a random CEK, encrypts plaintext with AES-256-GCM, and wraps
 * the CEK for each recipient via the wrapCEK callback.
 */
export async function encrypt(
  plaintext: Uint8Array,
  recipients: RecipientInfo[],
  wrapCEK: WrapCEKFunc,
  opts?: EncryptOpts,
): Promise<EncryptMessage> {
  if (recipients.length === 0) {
    throw new Error('cose: at least one recipient required');
  }

  const algorithm = opts?.contentAlgorithm ?? AlgA256GCM;
  const externalAAD = opts?.externalAAD ?? new Uint8Array(0);

  // Generate CEK and IV (or use fixed values for test vectors)
  const cek = opts?._testCEK ?? randomBytes(32);
  const iv = opts?._testIV ?? randomBytes(12);

  try {
    const protectedHeader: ProtectedHeader = new Map([[HeaderAlgorithm, algorithm]]);
    const protectedBytes = encodeProtected(protectedHeader);

    const unprotectedHeader: UnprotectedHeader = new Map([[HeaderIV, iv]]);

    // Build AAD
    const aad = buildEncStructure(protectedBytes, externalAAD);

    // Encrypt content
    const ciphertext = await aesGcmEncrypt(cek, iv, plaintext, aad);

    // Wrap CEK for each recipient
    const coseRecipients: Recipient[] = [];
    for (const ri of recipients) {
      const rProtected: ProtectedHeader = new Map([[HeaderAlgorithm, ri.algorithm]]);
      const rProtectedBytes = encodeProtected(rProtected);

      const rUnprotected: UnprotectedHeader = new Map([
        [HeaderKeyID, new TextEncoder().encode(ri.keyId)],
      ]);

      // Add CEF private headers if present
      if (ri.type) rUnprotected.set(HeaderCEFRecipientType, ri.type);

      const wrappedCEK = await wrapCEK(cek, ri);

      coseRecipients.push({
        protected: rProtected,
        unprotected: rUnprotected,
        ciphertext: wrappedCEK,
      });
    }

    return {
      protected: protectedHeader,
      protectedBytes,
      unprotected: unprotectedHeader,
      ciphertext,
      recipients: coseRecipients,
    };
  } finally {
    zeroize(cek);
  }
}

/**
 * Decrypt a COSE_Encrypt message.
 */
export async function decrypt(
  msg: EncryptMessage,
  recipientIndex: number,
  unwrapCEK: UnwrapCEKFunc,
  opts?: EncryptOpts,
): Promise<Uint8Array> {
  if (recipientIndex < 0 || recipientIndex >= msg.recipients.length) {
    throw new Error(`cose: invalid recipient index ${recipientIndex}`);
  }

  // Validate content algorithm
  const alg = msg.protected.get(HeaderAlgorithm);
  if (alg !== AlgA256GCM) {
    throw new Error(`cose: unsupported content algorithm ${alg} (expected A256GCM)`);
  }

  const recipient = msg.recipients[recipientIndex]!;
  const cek = await unwrapCEK(recipient.ciphertext, recipient);

  try {
    const ivRaw = msg.unprotected.get(HeaderIV);
    // cbor-x may return Buffer (Node.js) instead of Uint8Array
    const iv = ivRaw instanceof Uint8Array ? ivRaw : new Uint8Array(ivRaw as ArrayLike<number>);
    if (!iv || iv.length !== 12) {
      throw new Error('cose: missing or invalid IV');
    }

    const externalAAD = opts?.externalAAD ?? new Uint8Array(0);
    const aad = buildEncStructure(msg.protectedBytes, externalAAD);

    return await aesGcmDecrypt(cek, iv, msg.ciphertext, aad);
  } finally {
    zeroize(cek);
  }
}

// ---------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------

/**
 * Create a COSE_Sign1 message (tag 18).
 *
 * If detached is true, the payload is not included in the serialized
 * structure (it must be supplied externally during verification).
 */
export async function sign1(
  algorithm: number,
  keyId: string,
  payload: Uint8Array,
  detached: boolean,
  signFn: SignFunc,
): Promise<Sign1Message> {
  const protectedHeader: ProtectedHeader = new Map([[HeaderAlgorithm, algorithm]]);
  const protectedBytes = encodeProtected(protectedHeader);

  const unprotectedHeader: UnprotectedHeader = new Map([
    [HeaderKeyID, new TextEncoder().encode(keyId)],
  ]);

  const sigStructure = buildSigStructure(protectedBytes, new Uint8Array(0), payload);
  const signature = await signFn(sigStructure);

  return {
    protected: protectedHeader,
    protectedBytes,
    unprotected: unprotectedHeader,
    payload: detached ? null : payload,
    signature,
  };
}

/**
 * Verify a COSE_Sign1 message.
 *
 * If the message has a detached payload (payload is null), the external
 * payload must be provided.
 */
export async function verify1(
  msg: Sign1Message,
  externalPayload: Uint8Array | null,
  verifyFn: VerifyFunc,
): Promise<void> {
  const payload = msg.payload ?? externalPayload;
  if (!payload) {
    throw new Error('cose: no payload for verification (detached signature requires external payload)');
  }

  const sigStructure = buildSigStructure(msg.protectedBytes, new Uint8Array(0), payload);
  await verifyFn(sigStructure, msg.signature);
}

// ---------------------------------------------------------------------------
// CBOR Serialization (COSE_Encrypt → bytes, bytes → COSE_Encrypt)
// ---------------------------------------------------------------------------

/**
 * Serialize a COSE_Encrypt message to CBOR with tag 96.
 */
export function marshalEncrypt(msg: EncryptMessage): Uint8Array {
  const recipients = msg.recipients.map(r => {
    const rProtectedBytes = encodeProtected(r.protected);
    return [rProtectedBytes, r.unprotected, r.ciphertext];
  });

  const structure = [msg.protectedBytes, msg.unprotected, msg.ciphertext, recipients];

  // Manually build tagged CBOR: tag 96 + array
  const inner = cborEncode(structure);
  // CBOR tag 96 = 0xd860 (major type 6, value 96 encoded as 1-byte)
  const tagged = new Uint8Array(2 + inner.length);
  tagged[0] = 0xd8; // tag (1-byte follows)
  tagged[1] = 0x60; // 96
  tagged.set(inner, 2);
  return tagged;
}

/**
 * Deserialize CBOR bytes to a COSE_Encrypt message.
 */
export function unmarshalEncrypt(data: Uint8Array): EncryptMessage {
  // Check for tag 96
  if (data[0] !== 0xd8 || data[1] !== 0x60) {
    throw new Error(`cose: expected CBOR tag 96 (COSE_Encrypt), got 0x${data[0]!.toString(16)}${data[1]!.toString(16)}`);
  }

  const inner = cborDecode(data.slice(2)) as unknown[];
  if (!Array.isArray(inner) || inner.length !== 4) {
    throw new Error(`cose: COSE_Encrypt must be a 4-element array, got ${inner.length}`);
  }

  const [protectedBytes, unprotectedRaw, ciphertext, recipientsRaw] = inner;

  const protectedHeader = decodeProtected(protectedBytes as Uint8Array);
  const unprotectedHeader = objToMap(unprotectedRaw as Record<number, unknown>);

  const recipients: Recipient[] = (recipientsRaw as unknown[][]).map(r => {
    const [rProt, rUnprot, rCipher] = r;
    return {
      protected: decodeProtected(rProt as Uint8Array),
      unprotected: objToMap(rUnprot as Record<number, unknown>),
      ciphertext: rCipher as Uint8Array,
    };
  });

  return {
    protected: protectedHeader,
    protectedBytes: protectedBytes as Uint8Array,
    unprotected: unprotectedHeader,
    ciphertext: ciphertext as Uint8Array,
    recipients,
  };
}

/**
 * Serialize a COSE_Sign1 message to CBOR with tag 18.
 */
export function marshalSign1(msg: Sign1Message): Uint8Array {
  const structure = [
    msg.protectedBytes,
    msg.unprotected,
    msg.payload ?? new Uint8Array(0),
    msg.signature,
  ];

  const inner = cborEncode(structure);
  // CBOR tag 18 = 0xd2 (major type 6, value 18 = 1-byte value)
  const tagged = new Uint8Array(1 + inner.length);
  tagged[0] = 0xd2; // tag 18 (< 24, so single byte 0xc0 | 18 = 0xd2)
  tagged.set(inner, 1);
  return tagged;
}

/**
 * Deserialize CBOR bytes to a COSE_Sign1 message.
 */
export function unmarshalSign1(data: Uint8Array): Sign1Message {
  // Tag 18 = 0xd2
  if (data[0] !== 0xd2) {
    throw new Error(`cose: expected CBOR tag 18 (COSE_Sign1), got 0x${data[0]!.toString(16)}`);
  }

  const inner = cborDecode(data.slice(1)) as unknown[];
  if (!Array.isArray(inner) || inner.length !== 4) {
    throw new Error(`cose: COSE_Sign1 must be a 4-element array, got ${inner.length}`);
  }

  const [protectedBytes, unprotectedRaw, payload, signature] = inner;

  const protectedHeader = decodeProtected(protectedBytes as Uint8Array);
  const unprotectedHeader = objToMap(unprotectedRaw as Record<number, unknown>);

  // Detached: payload is nil (CBOR null) or empty bstr per RFC 9052 §4.2
  const payloadBytes = payload as Uint8Array | null;
  const isDetached = payloadBytes == null || payloadBytes.length === 0;

  return {
    protected: protectedHeader,
    protectedBytes: protectedBytes as Uint8Array,
    unprotected: unprotectedHeader,
    payload: isDetached ? null : payloadBytes,
    signature: signature as Uint8Array,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a decoded CBOR object/Map to a Map<number, unknown>. */
function objToMap(obj: unknown): Map<number, unknown> {
  if (obj instanceof Map) {
    // cbor-x with mapsAsObjects:false returns Maps with correct key types
    // Integer keys stay as numbers, string keys stay as strings
    const m = new Map<number, unknown>();
    for (const [k, v] of obj as Map<unknown, unknown>) {
      m.set(typeof k === 'string' ? Number(k) : k as number, v);
    }
    return m;
  }
  const m = new Map<number, unknown>();
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      m.set(Number(k), v);
    }
  }
  return m;
}

/**
 * Find the recipient index matching a key ID.
 */
export function findRecipientIndex(msg: EncryptMessage, keyId: string): number {
  const keyIdBytes = new TextEncoder().encode(keyId);

  for (let i = 0; i < msg.recipients.length; i++) {
    const kid = msg.recipients[i]!.unprotected.get(HeaderKeyID);
    if (kid instanceof Uint8Array && constantTimeEqual(kid, keyIdBytes)) {
      return i;
    }
    // cbor-x may decode bstr as Buffer; also handle string comparison
    if (typeof kid === 'string' && kid === keyId) {
      return i;
    }
    // Handle Buffer (Node.js) — Buffer extends Uint8Array but check explicitly
    if (kid && typeof kid === 'object' && 'length' in kid) {
      const kidArr = new Uint8Array(kid as ArrayLike<number>);
      if (constantTimeEqual(kidArr, keyIdBytes)) {
        return i;
      }
    }
  }

  return -1;
}

