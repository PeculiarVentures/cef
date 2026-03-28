/**
 * CEF container format: ZIP archive with COSE-encrypted payloads
 * and CBOR manifest.
 */

import { zipSync, unzipSync, Zippable } from 'fflate';
import { Encoder } from 'cbor-x';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const FormatVersion = '0';

/** COSE algorithm identifier for SHA-256 (RFC 9053 §2.1). */
export const HashAlgSHA256 = -16;
export const PathManifest = 'META-INF/manifest.cbor.cose';
export const PathSignature = 'META-INF/manifest.cose-sign1';
export const PathTimestamp = 'META-INF/manifest.tst';
export const EncryptedPrefix = 'encrypted/';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FileMetadata {
  originalName: string;
  hash: Uint8Array;
  hashAlgorithm: number;        // COSE algorithm ID: -16 = SHA-256 (RFC 9053 §2.1)
  size: number;
  contentType?: string;
}

/**
 * Unverified self-asserted claims for UI display.
 * These MUST NOT be used for access control or trust decisions.
 */
/** Unverified sender claims (UI display only, MUST NOT be used for access control). */
export interface SenderClaims {
  email?: string;
  name?: string;
  createdAt?: string;           // Sender-asserted creation time (RFC 3339)

  // Handling marks — sender-asserted labels for recipient handling guidance.
  // Security enforcement is through backend key policy, not these labels.
  classification?: string;      // e.g. "TOP SECRET"
  sciControls?: string[];       // SCI codewords, e.g. ["HCS", "SI"]
  sapPrograms?: string[];       // SAP identifiers
  dissemination?: string[];     // e.g. ["NOFORN", "ORCON"]
  releasability?: string;       // e.g. "REL TO USA, FVEY"
}

/** Unverified recipient claims (UI display only). */
export interface RecipientClaims {
  email?: string;
  name?: string;
  groupId?: string;
}

/** @deprecated Use SenderClaims or RecipientClaims. */
export type Claims = SenderClaims & RecipientClaims;

/**
 * Sender identity.
 *
 * The kid (key identifier) is verified via the COSE_Sign1 signature.
 * The optional x5c provides verified identity via X.509 certificate chain.
 * The optional claims carry unverified hints for UI display only.
 *
 * This follows the IETF convention (JOSE RFC 7515, COSE RFC 9052):
 * key identifiers and certificate references, not self-asserted identity.
 */
export interface SenderInfo {
  kid: string;                // Key identifier (verified via signature)
  x5c?: Uint8Array[];         // X.509 certificate chain (DER, leaf-first)
  claims?: SenderClaims;      // Unverified hints (mutually exclusive with x5c)
}

/**
 * Recipient reference.
 *
 * The kid identifies the recipient's key for CEK unwrapping.
 * The type hints how the recipient was resolved.
 * The optional x5c and claims follow the same convention as SenderInfo.
 */
export interface RecipientRef {
  kid: string;                // Key identifier (required)
  type?: string;              // "key" | "certificate" | "group"
  x5c?: Uint8Array[];         // X.509 certificate chain (DER, leaf-first)
  claims?: RecipientClaims;   // Unverified hints (mutually exclusive with x5c)
  // Extension fields
  logicalKeyId?: string;
  versionId?: string;
  policyRef?: string;
}

export interface Manifest {
  version: string;
  sender: SenderInfo;
  recipients: RecipientRef[];
  files: Record<string, FileMetadata>;
}

export interface Container {
  manifest: Manifest;
  encryptedFiles: Map<string, Uint8Array>;
  encryptedManifest: Uint8Array | null;
  manifestSignature: Uint8Array | null;
  timestamp: Uint8Array | null;
}

// ---------------------------------------------------------------------------
// Deterministic CBOR
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
// Container operations
// ---------------------------------------------------------------------------

/**
 * Create a new empty container.
 */
export function createContainer(): Container {
  return {
    manifest: {
      version: FormatVersion,
      sender: { kid: '' },
      recipients: [],
      files: {},
    },
    encryptedFiles: new Map(),
    encryptedManifest: null,
    manifestSignature: null,
    timestamp: null,
  };
}

/**
 * Add a file to the container.
 */
export function addFile(
  c: Container,
  obfuscatedName: string,
  metadata: FileMetadata,
  encryptedData: Uint8Array,
): void {
  c.manifest.files[obfuscatedName] = metadata;
  c.encryptedFiles.set(obfuscatedName, encryptedData);
}

/**
 * Sort object keys for deterministic CBOR encoding (RFC 8949 §4.2.1).
 *
 * Core Deterministic Encoding Requirements: map keys sorted by their
 * encoded form — shorter keys first, then lexicographic. For string
 * keys this means shorter strings first, then alphabetic.
 *
 * Applies recursively to nested objects (but not arrays).
 */
function sortKeysForCBOR(obj: Record<string, unknown>): Record<string, unknown> {
  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(obj).sort((a, b) => {
    // Shorter encoded key first, then lexicographic
    if (a.length !== b.length) return a.length - b.length;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  for (const key of keys) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Array.isArray(val) && !(val instanceof Uint8Array)) {
      sorted[key] = sortKeysForCBOR(val as Record<string, unknown>);
    } else if (Array.isArray(val)) {
      sorted[key] = val.map(item =>
        item !== null && typeof item === 'object' && !Array.isArray(item) && !(item instanceof Uint8Array)
          ? sortKeysForCBOR(item as Record<string, unknown>)
          : item
      );
    } else {
      sorted[key] = val;
    }
  }
  return sorted;
}

/**
 * Serialize the manifest to deterministic CBOR (RFC 8949 §4.2.1).
 */
export function marshalManifest(manifest: Manifest): Uint8Array {
  const obj: Record<string, unknown> = {
    version: manifest.version,
    sender: {} as Record<string, unknown>,
    recipients: manifest.recipients.map(r => {
      const rec: Record<string, unknown> = { kid: r.kid };
      if (r.type) rec['type'] = r.type;
      if (r.x5c && r.x5c.length > 0) {
        // Certificate present — identity from cert, skip claims
        rec['x5c'] = r.x5c;
      } else if (r.claims) {
        // No certificate — include unverified claims
        const claims: Record<string, string> = {};
        if (r.claims.email) claims['email'] = r.claims.email;
        if (r.claims.name) claims['name'] = r.claims.name;
        if (r.claims.groupId) claims['group_id'] = r.claims.groupId;
        if (Object.keys(claims).length > 0) rec['claims'] = claims;
      }
      if (r.logicalKeyId) rec['logical_key_id'] = r.logicalKeyId;
      if (r.versionId) rec['version_id'] = r.versionId;
      if (r.policyRef) rec['policy_ref'] = r.policyRef;
      return rec;
    }),
    files: {} as Record<string, Record<string, unknown>>,
  };

  // Sender: kid (required) + x5c OR claims (mutually exclusive per §5.5)
  const sender = obj['sender'] as Record<string, unknown>;
  sender['kid'] = manifest.sender.kid;
  if (manifest.sender.x5c && manifest.sender.x5c.length > 0) {
    // Certificate present — identity comes from the cert, skip claims
    sender['x5c'] = manifest.sender.x5c;
  } else if (manifest.sender.claims) {
    // No certificate — include unverified claims for UI hints
    const claims: Record<string, unknown> = {};
    if (manifest.sender.claims.email) claims['email'] = manifest.sender.claims.email;
    if (manifest.sender.claims.name) claims['name'] = manifest.sender.claims.name;
    if (manifest.sender.claims.createdAt) claims['created_at'] = manifest.sender.claims.createdAt;
    if (manifest.sender.claims.classification) claims['classification'] = manifest.sender.claims.classification;
    if (manifest.sender.claims.sciControls?.length) claims['sci_controls'] = manifest.sender.claims.sciControls;
    if (manifest.sender.claims.sapPrograms?.length) claims['sap_programs'] = manifest.sender.claims.sapPrograms;
    if (manifest.sender.claims.dissemination?.length) claims['dissemination'] = manifest.sender.claims.dissemination;
    if (manifest.sender.claims.releasability) claims['releasability'] = manifest.sender.claims.releasability;
    if (Object.keys(claims).length > 0) sender['claims'] = claims;
  }

  // Files
  const files = obj['files'] as Record<string, Record<string, unknown>>;
  for (const [name, meta] of Object.entries(manifest.files)) {
    const f: Record<string, unknown> = {
      original_name: meta.originalName,
      hash: meta.hash,
      hash_algorithm: meta.hashAlgorithm,
      size: meta.size,
    };
    if (meta.contentType) f['content_type'] = meta.contentType;
    files[name] = f;
  }

  return cborEncode(sortKeysForCBOR(obj));
}

/**
 * Deserialize CBOR bytes to a Manifest.
 */
export function unmarshalManifest(data: Uint8Array): Manifest {
  const decoded = cborDecode(data);
  // cbor-x with mapsAsObjects:false returns Maps with string keys
  const raw = decoded instanceof Map
    ? Object.fromEntries(decoded as Map<string, unknown>)
    : decoded as Record<string, unknown>;

  const version = raw['version'] as string;
  if (!version || version !== '0') {
    throw new Error(`unsupported manifest version: ${version} (expected 0)`);
  }

  const senderDecoded = raw['sender'];
  const senderRaw = senderDecoded instanceof Map
    ? Object.fromEntries(senderDecoded as Map<string, unknown>)
    : (senderDecoded ?? {}) as Record<string, unknown>;
  const senderClaimsDecoded = senderRaw['claims'];
  const senderClaimsRaw = senderClaimsDecoded instanceof Map
    ? Object.fromEntries(senderClaimsDecoded as Map<string, unknown>)
    : senderClaimsDecoded as Record<string, string> | undefined;
  const senderKid = senderRaw['kid'] as string | undefined;
  if (!senderKid) {
    throw new Error('manifest: sender.kid is required');
  }
  const sender: SenderInfo = {
    kid: senderKid,
    x5c: senderRaw['x5c'] as Uint8Array[] | undefined,
    claims: senderClaimsRaw
      ? {
          email: senderClaimsRaw['email'] as string,
          name: senderClaimsRaw['name'] as string,
          createdAt: senderClaimsRaw['created_at'] as string,
          classification: senderClaimsRaw['classification'] as string,
          sciControls: senderClaimsRaw['sci_controls'] as string[],
          sapPrograms: senderClaimsRaw['sap_programs'] as string[],
          dissemination: senderClaimsRaw['dissemination'] as string[],
          releasability: senderClaimsRaw['releasability'] as string,
        }
      : undefined,
  };

  const recipientsDecoded = (raw['recipients'] ?? []) as unknown[];
  const recipients: RecipientRef[] = recipientsDecoded.map(rd => {
    const r = rd instanceof Map
      ? Object.fromEntries(rd as Map<string, unknown>)
      : rd as Record<string, unknown>;
    const claimsDecoded = r['claims'];
    const claims = claimsDecoded instanceof Map
      ? Object.fromEntries(claimsDecoded as Map<string, unknown>)
      : claimsDecoded as Record<string, string> | undefined;
    const recipientKid = r['kid'] as string | undefined;
    if (!recipientKid) {
      throw new Error('manifest: recipient kid is required');
    }
    return {
      kid: recipientKid,
      type: (r['type'] || 'key') as string,
      x5c: r['x5c'] as Uint8Array[] | undefined,
      claims: claims
        ? { email: claims['email'] as string, name: claims['name'] as string, groupId: (claims['group_id'] || claims['groupId']) as string }
        : undefined,
      logicalKeyId: r['logical_key_id'] as string | undefined,
      versionId: r['version_id'] as string | undefined,
      policyRef: r['policy_ref'] as string | undefined,
    };
  });

  const filesDecoded = raw['files'];
  const filesMap = filesDecoded instanceof Map
    ? Object.fromEntries(filesDecoded as Map<string, unknown>)
    : (filesDecoded ?? {}) as Record<string, unknown>;
  const files: Record<string, FileMetadata> = {};
  for (const [name, fd] of Object.entries(filesMap)) {
    const f = fd instanceof Map
      ? Object.fromEntries(fd as Map<string, unknown>)
      : fd as Record<string, unknown>;
    files[name] = {
      originalName: f['original_name'] as string,
      hash: f['hash'] as Uint8Array,
      hashAlgorithm: (f['hash_algorithm'] as number) ?? HashAlgSHA256,
      size: f['size'] as number,
      contentType: f['content_type'] as string | undefined,
    };
  }

  return { version, sender, recipients, files };
}

/**
 * Serialize a container to a ZIP archive.
 */
export function writeContainer(c: Container): Uint8Array {
  if (!c.encryptedManifest) {
    throw new Error('container: encrypted manifest not set');
  }

  const zip: Zippable = {
    [PathManifest]: c.encryptedManifest,
  };

  if (c.manifestSignature) {
    zip[PathSignature] = c.manifestSignature;
  }

  if (c.timestamp) {
    zip[PathTimestamp] = c.timestamp;
  }

  for (const [name, data] of c.encryptedFiles) {
    zip[`${EncryptedPrefix}${name}`] = data;
  }

  return zipSync(zip, { level: 0 }); // No compression (already encrypted)
}

/** Maximum total decompressed size (2 GB). */
const MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024;

/** Maximum number of ZIP entries. */
const MAX_ZIP_ENTRIES = 10000;

/**
 * Maximum compressed input size (500 MB). Checked BEFORE decompression
 * to prevent memory exhaustion from ZIP bombs. Since CEF containers use
 * no compression (level 0), compressed and decompressed sizes are nearly
 * identical. This limit catches pathologically large inputs before
 * fflate allocates memory for decompression.
 */
const MAX_COMPRESSED_SIZE = 500 * 1024 * 1024;

/**
 * Read a container from a ZIP archive.
 *
 * Validates compressed input size before decompression, then checks
 * decompressed sizes and entry counts.
 */
export function readContainer(data: Uint8Array, opts?: { maxDecompressedSize?: number }): Container {
  // Pre-decompression size check — prevents memory exhaustion
  if (data.length > MAX_COMPRESSED_SIZE) {
    throw new Error(`container: compressed input too large (${data.length} > ${MAX_COMPRESSED_SIZE} bytes)`);
  }

  const maxSize = opts?.maxDecompressedSize ?? MAX_DECOMPRESSED_SIZE;
  const zip = unzipSync(data);

  // Post-decompression validation
  const entries = Object.entries(zip);
  if (entries.length > MAX_ZIP_ENTRIES) {
    throw new Error(`container: too many ZIP entries (${entries.length} > ${MAX_ZIP_ENTRIES})`);
  }

  let totalSize = 0;
  for (const [, fileData] of entries) {
    totalSize += fileData.length;
    if (totalSize > maxSize) {
      throw new Error(`container: decompressed size exceeds limit (${maxSize} bytes)`);
    }
  }

  const encryptedManifest = zip[PathManifest];
  if (!encryptedManifest) {
    throw new Error('container: missing ' + PathManifest);
  }

  const manifestSignature = zip[PathSignature] ?? null;
  const timestamp = zip[PathTimestamp] ?? null;

  const encryptedFiles = new Map<string, Uint8Array>();
  for (const [path, fileData] of entries) {
    if (path.startsWith(EncryptedPrefix)) {
      const name = path.slice(EncryptedPrefix.length);
      if (name !== '' && !name.includes('..') && !name.includes('/')) {
        encryptedFiles.set(name, fileData);
      }
    }
  }

  return {
    manifest: {
      version: FormatVersion,
      sender: { kid: '' },
      recipients: [],
      files: {},
    },
    encryptedFiles,
    encryptedManifest,
    manifestSignature,
    timestamp,
  };
}

/**
 * Generate a random obfuscated filename.
 */
export function randomFileName(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('') + '.cose';
}
