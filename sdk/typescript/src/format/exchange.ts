/**
 * CEF exchange orchestration layer.
 *
 * Provides high-level EncryptFiles / DecryptContainer / VerifyContainer
 * operations that compose the format-layer primitives (COSE, container,
 * crypto) into complete workflows.
 *
 * Backend-neutral: key operations are provided via callback functions.
 */

import {
  encrypt, decrypt, sign1, verify1,
  marshalEncrypt, unmarshalEncrypt,
  marshalSign1, unmarshalSign1,
  findRecipientIndex,
  DefaultSignatureAlgorithm,
  type RecipientInfo, type WrapCEKFunc, type UnwrapCEKFunc,
  type SignFunc, type VerifyFunc,
} from './cose.js';

import {
  type Claims, type SenderClaims,
  createContainer, addFile, marshalManifest, unmarshalManifest,
  writeContainer, readContainer, randomFileName, HashAlgSHA256,
  type Container, type FileMetadata, type SenderInfo, type RecipientRef,
} from './container.js';

import { sha256, constantTimeEqual, randomBytes } from './crypto.js';

// ---------------------------------------------------------------------------
// Security helpers
// ---------------------------------------------------------------------------

/**
 * Sanitize a file name from the manifest to prevent path traversal.
 * Strips directory components, rejects names with traversal sequences.
 */
function sanitizeFileName(name: string): string {
  // Reject empty names
  if (!name || name.length === 0) {
    throw new Error('cef: empty file name in manifest');
  }

  // Reject path traversal
  if (name.includes('..') || name.includes('/') || name.includes('\\')) {
    throw new Error(`cef: path traversal detected in file name "${name}"`);
  }

  // Reject names that start with a dot (hidden files)
  if (name.startsWith('.')) {
    throw new Error(`cef: hidden file name "${name}" rejected`);
  }

  // Reject null bytes
  if (name.includes('\0')) {
    throw new Error('cef: null byte in file name');
  }

  return name;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FileInput {
  name: string;
  data: Uint8Array;
  contentType?: string;
}

export interface EncryptOptions {
  /** Recipients with key IDs and algorithms. */
  recipients: RecipientInfo[];

  /** Sender info for the manifest. The sender's kid is also used as the
   *  signing key ID for COSE_Sign1. */
  sender?: SenderInfo;

  /** Signature algorithm (default: ML-DSA-65, FIPS 204). */
  signatureAlgorithm?: number;

  /** Sign callback. Required if sender is set. */
  signFn?: SignFunc;

  /** CEK wrap callback. Required. */
  wrapCEK: WrapCEKFunc;

  /** Maximum file size in bytes (default: 1GB). */
  maxFileSize?: number;

  /** Optional RFC 3161 timestamp token to include in the container.
   *  The caller is responsible for obtaining the token from a TSA. */
  timestamp?: Uint8Array;
}

export interface EncryptResult {
  /** The .cef container bytes (ZIP). */
  container: Uint8Array;

  /** Number of files encrypted. */
  fileCount: number;

  /** Whether the container was signed. */
  signed: boolean;

  /** Whether a timestamp was included. */
  timestamped: boolean;
}

export interface DecryptOptions {
  /** Recipient key ID to use for decryption. */
  recipientKeyId: string;

  /** CEK unwrap callback. Required. */
  unwrapCEK: UnwrapCEKFunc;

  /** Verify callback. Required unless skipSignatureVerification is true.
   *  If the container has a signature and no verifyFn is provided (and
   *  skipSignatureVerification is not true), decryption will fail. */
  verifyFn?: VerifyFunc;

  /** Skip signature verification. Default: false (verification is on).
   *  Set to true only when the sender's key is unavailable for verification. */
  skipSignatureVerification?: boolean;

  /** If true, files with hash mismatches are included with hashValid=false
   *  instead of throwing. Default: false (reject invalid hashes). */
  allowInvalidHash?: boolean;
}

export interface DecryptResult {
  files: DecryptedFile[];
  manifestValid: boolean;
  signatureValid: boolean | null;
  timestampPresent: boolean;

  /** The decrypted manifest. Contains the authoritative wire-format data. */
  manifest?: import('./container.js').Manifest;

  /** Container creation time (sender-asserted, from manifest). */
  createdAt?: string;

  /** Sender key identifier (verified via signature). */
  senderKid?: string;

  /** Sender X.509 certificate chain (DER, from manifest). */
  senderX5c?: Uint8Array[];

  /** Sender claims (unverified hints from manifest). */
  senderClaims?: SenderClaims;
}

export interface DecryptedFile {
  originalName: string;
  data: Uint8Array;
  size: number;
  hashValid: boolean;
}

export interface VerifyResult {
  containerValid: boolean;
  signatureValid: boolean | null;
  fileCount: number;

  /** Sender key identifier (verified via signature). */
  senderKid?: string;

  /** Sender X.509 certificate chain (DER, from manifest). */
  senderX5c?: Uint8Array[];

  /** Sender claims (unverified hints from manifest). */
  senderClaims?: SenderClaims;

  /** Recipient key IDs from the manifest. */
  recipients: string[];

  errors: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MAX_FILE_SIZE = 1 << 30; // 1 GB

// ---------------------------------------------------------------------------
// EncryptFiles
// ---------------------------------------------------------------------------

/**
 * Encrypt files into a .cef container.
 *
 * 1. Hash each file (SHA-256)
 * 2. Encrypt each file with COSE_Encrypt (one CEK per file)
 * 3. Build manifest with file metadata
 * 4. Encrypt manifest with COSE_Encrypt
 * 5. Optionally sign with COSE_Sign1 (detached)
 * 6. Package into ZIP
 */
export async function encryptFiles(
  files: FileInput[],
  opts: EncryptOptions,
): Promise<EncryptResult> {
  if (files.length === 0) {
    throw new Error('cef: no files to encrypt');
  }
  if (opts.recipients.length === 0) {
    throw new Error('cef: no recipients specified');
  }

  // Validate sender kid
  if (opts.sender && !opts.sender.kid) {
    throw new Error('cef: sender.kid is required');
  }

  // Validate recipient key IDs
  for (const r of opts.recipients) {
    if (!r.keyId) {
      throw new Error('cef: recipient keyId is required');
    }
  }

  const maxSize = opts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  // Validate file sizes
  for (const f of files) {
    if (f.data.length > maxSize) {
      throw new Error(`cef: file "${f.name}" exceeds max size (${f.data.length} > ${maxSize})`);
    }
  }

  const container = createContainer();

  // Set sender
  if (opts.sender) {
    container.manifest.sender = { ...opts.sender };
    // Auto-set created_at if sender has claims (and no x5c)
    if (container.manifest.sender.claims && !container.manifest.sender.x5c) {
      container.manifest.sender.claims = {
        ...container.manifest.sender.claims,
        createdAt: container.manifest.sender.claims.createdAt ?? new Date().toISOString(),
      };
    }
  } else {
    // Anonymous sender — generate a random kid for manifest validity
    const anonKid = Array.from(randomBytes(8), b => b.toString(16).padStart(2, '0')).join('');
    container.manifest.sender = {
      kid: anonKid,
      claims: { createdAt: new Date().toISOString() },
    };
  }

  // Set recipients in manifest
  for (const ri of opts.recipients) {
    const ref: RecipientRef = {
      kid: ri.keyId,
      type: ri.type ?? 'key',
    };
    if (ri.logicalKeyId) ref.logicalKeyId = ri.logicalKeyId;
    if (ri.versionId) ref.versionId = ri.versionId;
    if (ri.policyRef) ref.policyRef = ri.policyRef;
    container.manifest.recipients.push(ref);
  }

  // Encrypt each file
  for (const f of files) {
    const hash = await sha256(f.data);
    const obfuscatedName = randomFileName();

    const encMsg = await encrypt(f.data, opts.recipients, opts.wrapCEK);
    const encBytes = marshalEncrypt(encMsg);

    const metadata: FileMetadata = {
      originalName: f.name,
      hash,
      hashAlgorithm: HashAlgSHA256,
      size: f.data.length,
      contentType: f.contentType,
    };

    addFile(container, obfuscatedName, metadata, encBytes);
  }

  // Encrypt manifest
  const manifestCbor = marshalManifest(container.manifest);
  const encManifest = await encrypt(manifestCbor, opts.recipients, opts.wrapCEK);
  container.encryptedManifest = marshalEncrypt(encManifest);

  // Sign (optional — if sender is set with a signFn, use sender.kid)
  let signed = false;
  if (opts.sender && opts.signFn) {
    const sigAlg = opts.signatureAlgorithm ?? DefaultSignatureAlgorithm;
    const sig = await sign1(sigAlg, opts.sender.kid, container.encryptedManifest, true, opts.signFn);
    container.manifestSignature = marshalSign1(sig);
    signed = true;
  }

  // Timestamp (optional)
  if (opts.timestamp) {
    container.timestamp = opts.timestamp;
  }

  // Package
  const containerBytes = writeContainer(container);

  return {
    container: containerBytes,
    fileCount: files.length,
    signed,
    timestamped: !!opts.timestamp,
  };
}

// ---------------------------------------------------------------------------
// DecryptContainer
// ---------------------------------------------------------------------------

/**
 * Decrypt a .cef container.
 *
 * 1. Read ZIP
 * 2. Optionally verify COSE_Sign1 signature
 * 3. Decrypt manifest with COSE_Encrypt
 * 4. For each file, decrypt and verify hash
 */
export async function decryptContainer(
  containerBytes: Uint8Array,
  opts: DecryptOptions,
): Promise<DecryptResult> {
  // Read ZIP
  const container = readContainer(containerBytes);

  if (!container.encryptedManifest) {
    throw new Error('cef: container has no encrypted manifest');
  }

  // Verify signature
  let signatureValid: boolean | null = null;
  if (container.manifestSignature) {
    if (opts.verifyFn) {
      try {
        const sigMsg = unmarshalSign1(container.manifestSignature);
        await verify1(sigMsg, container.encryptedManifest, opts.verifyFn);
        signatureValid = true;
      } catch (e) {
        signatureValid = false;
        throw new Error(`cef: signature verification failed: ${(e as Error).message}`);
      }
    } else if (!opts.skipSignatureVerification) {
      // Signature present but no verifyFn and verification not explicitly skipped
      throw new Error(
        'cef: container has a signature but no verifyFn provided. ' +
        'Pass verifyFn to verify, or set skipSignatureVerification: true to skip.',
      );
    }
    // else: skipSignatureVerification is true — silently skip
  }

  // Decrypt manifest
  const encManifest = unmarshalEncrypt(container.encryptedManifest);
  const recipientIdx = findRecipientIndex(encManifest, opts.recipientKeyId);
  if (recipientIdx < 0) {
    throw new Error(`cef: no recipient matching key ID "${opts.recipientKeyId}"`);
  }

  const manifestCbor = await decrypt(encManifest, recipientIdx, opts.unwrapCEK);
  const manifest = unmarshalManifest(manifestCbor);

  // Verify all manifest files exist in the container (detect truncation)
  for (const obfName of Object.keys(manifest.files)) {
    if (!container.encryptedFiles.has(obfName)) {
      throw new Error(
        `cef: container is missing file "${obfName}" listed in manifest (possible truncation)`,
      );
    }
  }

  // Decrypt each file
  const decryptedFiles: DecryptedFile[] = [];

  for (const [obfuscatedName, metadata] of Object.entries(manifest.files)) {
    const encFileBytes = container.encryptedFiles.get(obfuscatedName);
    if (!encFileBytes) {
      throw new Error(`cef: encrypted file "${obfuscatedName}" not found in container`);
    }

    const encFileMsg = unmarshalEncrypt(encFileBytes);
    const fileRecipientIdx = findRecipientIndex(encFileMsg, opts.recipientKeyId);
    if (fileRecipientIdx < 0) {
      throw new Error(`cef: no recipient matching key ID in file "${metadata.originalName}"`);
    }

    const fileData = await decrypt(encFileMsg, fileRecipientIdx, opts.unwrapCEK);

    // Sanitize the original file name from the manifest
    const safeName = sanitizeFileName(metadata.originalName);

    // Validate hash algorithm (§6.9: MUST NOT accept weaker than SHA-256)
    if (metadata.hashAlgorithm !== undefined
        && metadata.hashAlgorithm !== 0
        && metadata.hashAlgorithm !== HashAlgSHA256) {
      throw new Error(
        `cef: unsupported hash algorithm ${metadata.hashAlgorithm} for "${safeName}" (only SHA-256 = ${HashAlgSHA256} is supported)`,
      );
    }

    // Verify hash
    const actualHash = await sha256(fileData);
    const hashValid = constantTimeEqual(actualHash, metadata.hash);

    if (!hashValid && !opts.allowInvalidHash) {
      throw new Error(`cef: hash mismatch for file "${safeName}"`);
    }

    decryptedFiles.push({
      originalName: safeName,
      data: fileData,
      size: fileData.length,
      hashValid,
    });
  }

  return {
    files: decryptedFiles,
    manifestValid: true,
    signatureValid,
    timestampPresent: container.timestamp !== null && container.timestamp !== undefined,
    manifest,
    createdAt: manifest.sender.claims?.createdAt,
    senderKid: manifest.sender.kid,
    senderX5c: manifest.sender.x5c,
    senderClaims: manifest.sender.claims,
  };
}

// ---------------------------------------------------------------------------
// VerifyContainer
// ---------------------------------------------------------------------------

/**
 * Verify a .cef container's structure and signature without decrypting files.
 *
 * This checks:
 * - ZIP structure is valid
 * - Required entries exist
 * - COSE_Sign1 signature is valid (if present and verifyFn provided)
 * - COSE_Encrypt structures parse correctly
 */
export async function verifyContainer(
  containerBytes: Uint8Array,
  opts?: { verifyFn?: VerifyFunc; unwrapCEK?: UnwrapCEKFunc; recipientKeyId?: string },
): Promise<VerifyResult> {
  const errors: string[] = [];
  let signatureValid: boolean | null = null;
  let senderKid: string | undefined;
  let senderX5c: Uint8Array[] | undefined;
  let senderClaims: SenderClaims | undefined;
  const recipients: string[] = [];

  // Read ZIP
  let container: Container;
  try {
    container = readContainer(containerBytes);
  } catch (e) {
    return {
      containerValid: false,
      signatureValid: null,
      fileCount: 0,
      errors: [`invalid container: ${(e as Error).message}`],
      recipients: [],
    };
  }

  if (!container.encryptedManifest) {
    errors.push('missing encrypted manifest');
    return { containerValid: false, signatureValid: null, fileCount: 0, errors, recipients };
  }

  // Verify signature
  if (container.manifestSignature && opts?.verifyFn) {
    try {
      const sigMsg = unmarshalSign1(container.manifestSignature);
      await verify1(sigMsg, container.encryptedManifest, opts.verifyFn);
      signatureValid = true;
    } catch (e) {
      signatureValid = false;
      errors.push(`signature invalid: ${(e as Error).message}`);
    }
  }

  // Try to decrypt manifest for metadata (optional)
  if (opts?.unwrapCEK && opts?.recipientKeyId) {
    try {
      const encManifest = unmarshalEncrypt(container.encryptedManifest);
      const idx = findRecipientIndex(encManifest, opts.recipientKeyId);
      if (idx >= 0) {
        const manifestCbor = await decrypt(encManifest, idx, opts.unwrapCEK);
        const manifest = unmarshalManifest(manifestCbor);
        senderKid = manifest.sender.kid;
        senderX5c = manifest.sender.x5c;
        senderClaims = manifest.sender.claims;
        for (const r of manifest.recipients) {
          if (r.kid) recipients.push(r.kid);
        }
      }
    } catch {
      // Manifest decryption failed — that's okay for verify
    }
  }

  // Validate encrypted file entries parse as COSE
  let validFileCount = 0;
  for (const [name, data] of container.encryptedFiles) {
    try {
      unmarshalEncrypt(data);
      validFileCount++;
    } catch (e) {
      errors.push(`file "${name}": invalid COSE_Encrypt: ${(e as Error).message}`);
    }
  }

  return {
    containerValid: errors.length === 0,
    signatureValid,
    fileCount: validFileCount,
    senderKid,
    senderX5c,
    senderClaims,
    recipients,
    errors,
  };
}
