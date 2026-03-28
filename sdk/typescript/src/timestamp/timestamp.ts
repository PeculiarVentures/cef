/**
 * RFC 3161 timestamp token utilities for CEF.
 *
 * Uses @peculiar/asn1-tsp for TimeStampReq/TimeStampResp/TSTInfo
 * ASN.1 encoding and parsing. Timestamp tokens are stored as
 * META-INF/manifest.tst in the container.
 *
 * The timestamp proves that the COSE_Sign1 signature existed at a
 * specific point in time, which is required in some regulated
 * environments (eIDAS, legal document exchange).
 */

import 'reflect-metadata';
import * as tsp from '@peculiar/asn1-tsp';
import * as cms from '@peculiar/asn1-cms';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import { sha256 } from '../format/crypto.js';

// SHA-256 OID
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TimestampToken {
  /** DER-encoded TSTInfo bytes (for inclusion in container). */
  raw: Uint8Array;

  /** The time recorded in the TSTInfo. */
  genTime: Date;

  /** SHA-256 hash of the timestamped data. */
  messageImprint: Uint8Array;

  /** Policy OID from the TSTInfo. */
  policy?: string;
}

export interface TimestampRequestOptions {
  /** TSA endpoint URL for HTTP-based timestamping. */
  tsaUrl?: string;

  /** Policy OID to request (optional). */
  policyOid?: string;
}

export interface TimestampVerifyResult {
  valid: boolean;
  genTime?: Date;
  policy?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// TimeStampReq building
// ---------------------------------------------------------------------------

/**
 * Build a DER-encoded RFC 3161 TimeStampReq.
 *
 * This can be sent to a TSA via HTTP POST with
 * Content-Type: application/timestamp-query.
 */
export async function buildTimestampRequest(data: Uint8Array): Promise<Uint8Array> {
  const hash = await sha256(data);

  const req = new tsp.TimeStampReq({
    version: tsp.TimeStampReqVersion.v1,
    messageImprint: new tsp.MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: OID_SHA256 }),
      hashedMessage: new OctetString(hash),
    }),
    certReq: true,
  });

  return new Uint8Array(AsnConvert.serialize(req));
}

// ---------------------------------------------------------------------------
// Timestamp creation (local / offline)
// ---------------------------------------------------------------------------

/**
 * Create a local timestamp token (TSTInfo) without a TSA.
 *
 * This produces a DER-encoded TSTInfo that can be stored in the
 * container. For production use, send the TimeStampReq to a real
 * TSA and use the response instead.
 *
 * For offline use — the token is not signed by a TSA,
 * so it provides format compatibility but not third-party attestation.
 */
export async function createLocalTimestamp(
  data: Uint8Array,
  opts?: TimestampRequestOptions,
): Promise<TimestampToken> {
  const hash = await sha256(data);
  const genTime = new Date();

  // Build serial number from random bytes
  const serial = new Uint8Array(8);
  globalThis.crypto.getRandomValues(serial);

  const tstInfo = new tsp.TSTInfo({
    version: tsp.TSTInfoVersion.v1,
    policy: opts?.policyOid ?? '1.3.6.1.4.1.99999.1', // dummy policy
    messageImprint: new tsp.MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: OID_SHA256 }),
      hashedMessage: new OctetString(hash),
    }),
    serialNumber: serial.buffer as ArrayBuffer,
    genTime,
  });

  const raw = new Uint8Array(AsnConvert.serialize(tstInfo));

  return {
    raw,
    genTime,
    messageImprint: hash,
    policy: tstInfo.policy,
  };
}

/**
 * Request a timestamp from a remote TSA via HTTP.
 *
 * Sends an RFC 3161 TimeStampReq and returns the TSTInfo from the
 * response. Requires network access.
 */
export async function requestTimestamp(
  data: Uint8Array,
  opts: TimestampRequestOptions & { tsaUrl: string },
): Promise<TimestampToken> {
  const reqDer = await buildTimestampRequest(data);

  const response = await fetch(opts.tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: reqDer as unknown as BodyInit,
  });

  if (!response.ok) {
    throw new Error(`TSA request failed: ${response.status} ${response.statusText}`);
  }

  const respBytes = new Uint8Array(await response.arrayBuffer());
  return parseTimestampResponse(respBytes);
}

// ---------------------------------------------------------------------------
// Timestamp parsing and verification
// ---------------------------------------------------------------------------

/**
 * Parse a DER-encoded TimeStampResp and extract the TSTInfo.
 */
export function parseTimestampResponse(der: Uint8Array): TimestampToken {
  const resp = AsnConvert.parse(der, tsp.TimeStampResp);

  if (resp.status.status !== tsp.PKIStatus.granted &&
      resp.status.status !== tsp.PKIStatus.grantedWithMods) {
    throw new Error(`TSA returned status ${resp.status.status}`);
  }

  if (!resp.timeStampToken) {
    throw new Error('TSA response contains no timestamp token');
  }

  // The timeStampToken is a ContentInfo wrapping SignedData wrapping TSTInfo.
  // Path: ContentInfo.content -> SignedData.encapContentInfo.eContent -> TSTInfo
  const tokenDer = new Uint8Array(AsnConvert.serialize(resp.timeStampToken));

  // Try to dig through ContentInfo -> SignedData -> eContent -> TSTInfo
  try {
    const contentInfo = AsnConvert.parse(tokenDer, cms.ContentInfo);
    const signedData = AsnConvert.parse(
      new Uint8Array(contentInfo.content),
      cms.SignedData,
    );
    if (signedData.encapContentInfo?.eContent?.single) {
      const buf = signedData.encapContentInfo.eContent.single.buffer
        ?? signedData.encapContentInfo.eContent.single;
      const tstInfoDer = new Uint8Array(buf as ArrayBuffer);
      return parseTSTInfo(tstInfoDer);
    }
    if (signedData.encapContentInfo?.eContent?.any) {
      const tstInfoDer = new Uint8Array(signedData.encapContentInfo.eContent.any);
      return parseTSTInfo(tstInfoDer);
    }
  } catch {
    // Fall through to direct parse attempt
  }

  // Fallback: try parsing the token directly as TSTInfo
  return parseTSTInfo(tokenDer);
}

/**
 * Parse a DER-encoded TSTInfo.
 */
export function parseTSTInfo(der: Uint8Array): TimestampToken {
  try {
    const tstInfo = AsnConvert.parse(der, tsp.TSTInfo);
    return {
      raw: der,
      genTime: tstInfo.genTime,
      messageImprint: new Uint8Array(tstInfo.messageImprint.hashedMessage.buffer ?? tstInfo.messageImprint.hashedMessage as unknown as ArrayBuffer),
      policy: tstInfo.policy,
    };
  } catch {
    // Might be wrapped in ContentInfo — try direct TSTInfo parse failed,
    // caller should provide raw TSTInfo DER
    throw new Error('failed to parse TSTInfo from DER');
  }
}

/**
 * Verify a timestamp token against the data it claims to timestamp.
 *
 * Checks that the message imprint (SHA-256 hash) in the TSTInfo
 * matches the hash of the provided data.
 *
 * Note: This verifies the hash binding only, not the TSA's signature.
 * Full signature verification would require the TSA's certificate.
 */
export async function verifyTimestamp(
  token: Uint8Array,
  data: Uint8Array,
): Promise<TimestampVerifyResult> {
  try {
    const tstInfo = AsnConvert.parse(token, tsp.TSTInfo);

    // Verify message imprint
    const expectedHash = await sha256(data);
    const actualHash = new Uint8Array(tstInfo.messageImprint.hashedMessage.buffer ?? tstInfo.messageImprint.hashedMessage as unknown as ArrayBuffer);

    if (expectedHash.length !== actualHash.length) {
      return { valid: false, error: 'message imprint length mismatch' };
    }

    let match = true;
    for (let i = 0; i < expectedHash.length; i++) {
      if (expectedHash[i] !== actualHash[i]) {
        match = false;
        break;
      }
    }

    if (!match) {
      return { valid: false, error: 'message imprint does not match data' };
    }

    return {
      valid: true,
      genTime: tstInfo.genTime,
      policy: tstInfo.policy,
    };
  } catch (e) {
    return {
      valid: false,
      error: `timestamp parse error: ${(e as Error).message}`,
    };
  }
}

/**
 * Extract DER-encoded certificates from a TimeStampResp's SignedData.
 * Returns an array of base64-encoded certificates suitable for display
 * in a certificate viewer component.
 */
export function extractTimestampCertificates(der: Uint8Array): string[] {
  try {
    const resp = AsnConvert.parse(der, tsp.TimeStampResp);
    if (!resp.timeStampToken) return [];

    const tokenDer = new Uint8Array(AsnConvert.serialize(resp.timeStampToken));
    const contentInfo = AsnConvert.parse(tokenDer, cms.ContentInfo);
    const signedData = AsnConvert.parse(
      new Uint8Array(contentInfo.content),
      cms.SignedData,
    );

    const certs: string[] = [];
    if (signedData.certificates) {
      for (const certChoice of signedData.certificates) {
        // CertificateChoices can be a Certificate or other types
        const certDer = new Uint8Array(AsnConvert.serialize(certChoice));
        // Convert to base64
        const b64 = btoa(String.fromCharCode(...certDer));
        certs.push(b64);
      }
    }
    return certs;
  } catch {
    return [];
  }
}

