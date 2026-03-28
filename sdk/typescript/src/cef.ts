/**
 * CEF Workflow API — the primary entry point for encrypting and decrypting files.
 *
 * @example
 * ```typescript
 * import { encrypt, decrypt } from '@peculiarventures/cef';
 *
 * const { container } = await encrypt({
 *   files: [{ name: 'report.pdf', data: pdfBytes }],
 *   sender: { signingKey: senderSec, kid: 'alice' },
 *   recipients: [{ kid: 'bob', encryptionKey: bobPub }],
 * });
 *
 * const { files } = await decrypt(container, {
 *   recipient: { kid: 'bob', decryptionKey: bobSec },
 *   verify: senderPub,
 * });
 * ```
 */

import { encryptFiles, decryptContainer, verifyContainer as verifyContainerInternal } from './format/exchange.js';
import type {
  FileInput,
  EncryptOptions as InternalEncryptOptions,
  DecryptOptions as InternalDecryptOptions,
  DecryptResult as InternalDecryptResult,
  EncryptResult as InternalEncryptResult,
  VerifyResult as InternalVerifyResult,
} from './format/exchange.js';
import type { SenderInfo, SenderClaims } from './format/container.js';
import { AlgMLDSA65 } from './format/cose.js';
import { mlkemWrapCEK, mlkemUnwrapCEK, mldsaSign, mldsaVerify } from './format/pq.js';
import type { WrapCEKFunc, UnwrapCEKFunc, SignFunc, VerifyFunc } from './format/cose.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A file to encrypt. */
export interface CEFFileInput {
  name: string;
  data: Uint8Array;
  contentType?: string;
}

/** Sender identity for signing. */
export interface Sender {
  /** ML-DSA-65 secret key (4032 bytes). */
  signingKey: Uint8Array;
  /** Key identifier. */
  kid: string;
  /** X.509 certificate chain (DER, leaf-first). Mutually exclusive with claims. */
  x5c?: Uint8Array[];
  /** Unverified sender claims. Mutually exclusive with x5c. */
  claims?: {
    email?: string;
    name?: string;
    classification?: string;
    sciControls?: string[];
    sapPrograms?: string[];
    dissemination?: string[];
    releasability?: string;
  };
}

/** A recipient of the encrypted container. */
export interface Recipient {
  /** Key identifier. */
  kid: string;
  /** ML-KEM-768 public key (1184 bytes). */
  encryptionKey: Uint8Array;
  /** Recipient kind. Default: 'key'. */
  kind?: 'key' | 'certificate';
  /** X.509 certificate chain (DER). Only when kind is 'certificate'. */
  x5c?: Uint8Array[];
}

/** Identity for decryption — who am I? */
export interface RecipientKey {
  /** Key identifier (must match a COSE recipient). */
  kid: string;
  /** ML-KEM-768 secret key (2400 bytes). */
  decryptionKey: Uint8Array;
}

/** Options for encrypt(). */
export interface EncryptOptions {
  /** Files to encrypt. */
  files: CEFFileInput[];
  /** Sender identity for signing. */
  sender: Sender;
  /** Recipients with their encryption keys. */
  recipients: Recipient[];
  /** Optional RFC 3161 timestamp token. */
  timestamp?: Uint8Array;

  // --- Advanced: custom key management ---
  /** Custom key wrap callback. When provided, recipients[].encryptionKey is ignored. */
  keyWrap?: WrapCEKFunc;
  /** Custom sign callback. When provided, sender.signingKey is ignored. */
  sign?: SignFunc;
}

/** Options for decrypt(). */
export interface DecryptOptions {
  /** Recipient identity for unwrapping. */
  recipient: RecipientKey;
  /**
   * Sender verification.
   * - Uint8Array: ML-DSA-65 public key (common case)
   * - VerifyFunc: custom verification callback (advanced)
   * - false: skip verification
   */
  verify?: Uint8Array | VerifyFunc | false;

  // --- Advanced: custom key management ---
  /** Custom key unwrap callback. When provided, recipient.decryptionKey is ignored. */
  keyUnwrap?: UnwrapCEKFunc;
}

/** Options for verify(). */
export interface VerifyOptions {
  /** Sender's ML-DSA-65 public key, or custom verify callback. */
  verify?: Uint8Array | VerifyFunc;
}

/** Result of encrypt(). */
export interface EncryptResult {
  /** The .cef container bytes. */
  container: Uint8Array;
  /** Number of files encrypted. */
  fileCount: number;
  /** Whether the container is signed. */
  signed: boolean;
}

/** A decrypted file. */
export interface DecryptedFile {
  originalName: string;
  data: Uint8Array;
  size: number;
}

/** Result of decrypt(). */
export interface DecryptResult {
  /** Decrypted files. */
  files: DecryptedFile[];
  /** Signature verification outcome. */
  signature: 'valid' | 'skipped' | 'failed';
  /** Sender identity from the manifest. */
  sender: { kid: string; x5c?: Uint8Array[]; claims?: SenderClaims };
  /** Container creation time (from sender claims). */
  createdAt?: string;
}

/** Result of verify(). */
export interface VerifyResult {
  signatureValid: boolean;
  senderKid?: string;
  timestampPresent: boolean;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Encrypt files into a signed CEF container.
 *
 * Provide sender signing key, recipient encryption keys, and files.
 * The SDK handles ML-KEM-768 key wrapping, ML-DSA-65 signing,
 * manifest construction, and container packaging automatically.
 *
 * For custom key management (HSM, cloud KMS), provide `keyWrap` and
 * `sign` callbacks instead of raw keys.
 */
export async function encrypt(opts: EncryptOptions): Promise<EncryptResult> {
  if (opts.recipients.length === 0) {
    throw new Error('cef: at least one recipient is required');
  }
  if (opts.files.length === 0) {
    throw new Error('cef: at least one file is required');
  }

  // Build WrapCEK: custom callback or ML-KEM from recipient keys
  let wrapCEK: WrapCEKFunc;
  if (opts.keyWrap) {
    wrapCEK = opts.keyWrap;
  } else {
    const pubKeyMap = new Map<string, Uint8Array>();
    for (const r of opts.recipients) {
      if (!r.encryptionKey || r.encryptionKey.length === 0) {
        throw new Error(`cef: recipient "${r.kid}" has no encryptionKey`);
      }
      pubKeyMap.set(r.kid, r.encryptionKey);
    }
    wrapCEK = mlkemWrapCEK(pubKeyMap);
  }

  // Build SignFunc: custom callback or ML-DSA from sender key
  const signFn: SignFunc = opts.sign ?? mldsaSign(opts.sender.signingKey);

  // Build sender info (x5c and claims mutually exclusive)
  const sender: SenderInfo = { kid: opts.sender.kid };
  if (opts.sender.x5c && opts.sender.x5c.length > 0) {
    sender.x5c = opts.sender.x5c;
  } else {
    sender.claims = {
      ...opts.sender.claims,
      createdAt: new Date().toISOString(),
    };
  }

  // Build COSE recipients
  const coseRecipients = opts.recipients.map(r => ({
    keyId: r.kid,
    algorithm: -70010, // ML-KEM-768+A256KW
    type: r.kind ?? (r.x5c ? 'certificate' : 'key'),
  }));

  const internal: InternalEncryptOptions = {
    recipients: coseRecipients,
    sender,
    signatureAlgorithm: AlgMLDSA65,
    signFn,
    wrapCEK,
    timestamp: opts.timestamp,
  };

  const result: InternalEncryptResult = await encryptFiles(
    opts.files.map(f => ({ name: f.name, data: f.data, contentType: f.contentType } as FileInput)),
    internal,
  );

  return {
    container: result.container,
    fileCount: result.fileCount,
    signed: result.signed,
  };
}

/**
 * Decrypt and verify a CEF container.
 *
 * Provide your recipient key and the sender's public key for verification.
 * For custom key management, provide `keyUnwrap` and `verify` callbacks.
 */
export async function decrypt(
  container: Uint8Array,
  opts: DecryptOptions,
): Promise<DecryptResult> {
  // Build UnwrapCEK: custom callback or ML-KEM from recipient key
  const unwrapCEK: UnwrapCEKFunc = opts.keyUnwrap ?? mlkemUnwrapCEK(opts.recipient.decryptionKey);

  // Build VerifyFunc
  let verifyFn: VerifyFunc | undefined;
  let skipSigVerify = false;

  if (opts.verify === false) {
    skipSigVerify = true;
  } else if (opts.verify instanceof Uint8Array) {
    verifyFn = mldsaVerify(opts.verify);
  } else if (typeof opts.verify === 'function') {
    verifyFn = opts.verify;
  }
  // If opts.verify is undefined, verifyFn stays undefined and
  // skipSigVerify stays false. The exchange layer will fail if the
  // container has a signature and no verifyFn is provided — this is
  // the correct default (fail-closed, don't silently skip).

  const internal: InternalDecryptOptions = {
    recipientKeyId: opts.recipient.kid,
    unwrapCEK,
    verifyFn,
    skipSignatureVerification: skipSigVerify,
  };

  const result: InternalDecryptResult = await decryptContainer(container, internal);

  // Map signature outcome
  let signature: 'valid' | 'skipped' | 'failed';
  if (result.signatureValid === true) signature = 'valid';
  else if (result.signatureValid === null) signature = 'skipped';
  else signature = 'failed';

  return {
    files: result.files.map(f => ({
      originalName: f.originalName,
      data: f.data,
      size: f.size,
    })),
    signature,
    sender: {
      kid: result.senderKid ?? '',
      x5c: result.senderX5c,
      claims: result.senderClaims,
    },
    createdAt: result.createdAt,
  };
}

/**
 * Verify a CEF container's signature without decrypting.
 */
export async function verify(
  container: Uint8Array,
  opts?: VerifyOptions,
): Promise<VerifyResult> {
  let verifyFn: VerifyFunc | undefined;
  if (opts?.verify instanceof Uint8Array) {
    verifyFn = mldsaVerify(opts.verify);
  } else if (typeof opts?.verify === 'function') {
    verifyFn = opts.verify;
  }

  const result: InternalVerifyResult = await verifyContainerInternal(container, { verifyFn });

  return {
    signatureValid: result.signatureValid === true,
    senderKid: result.senderKid,
    timestampPresent: false, // TODO: check container for manifest.tst
  };
}
