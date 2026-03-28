/**
 * Certificate validation utilities for CEF implementations that use
 * certificate-backed recipients.
 *
 * Uses @peculiar/x509 for real X.509 parsing, key usage checking,
 * and chain validation. Works in browsers and Node.js.
 *
 * This module mirrors sdk/go/goodkey/cert/cert.go.
 */

import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CertificateInfo {
  /** The parsed @peculiar/x509 certificate. */
  cert: x509.X509Certificate;

  /** Subject string (e.g., "CN=Alice"). */
  subject: string;

  /** Issuer string (e.g., "CN=GoodKey CA"). */
  issuer: string;

  /** Serial number (hex-encoded). */
  serialNumber: string;

  /** Subject Key Identifier (hex-encoded, if present). */
  subjectKeyIdentifier?: string;

  /** Not valid before. */
  notBefore: Date;

  /** Not valid after. */
  notAfter: Date;

  /** Public key algorithm name. */
  publicKeyAlgorithm: string;

  /** DER-encoded certificate bytes. */
  raw: Uint8Array;
}

export interface ValidatorOptions {
  checkExpiry?: boolean;
  checkKeyUsage?: boolean;
  allowExpired?: boolean;
}

// ---------------------------------------------------------------------------
// Validator interface
// ---------------------------------------------------------------------------

export interface CertificateValidator {
  validateForEncryption(cert: CertificateInfo): void;
  validateForSigning(cert: CertificateInfo): void;
  validateChain(cert: CertificateInfo, intermediates?: CertificateInfo[], roots?: x509.X509Certificate[]): Promise<void>;
}

// ---------------------------------------------------------------------------
// StandardValidator
// ---------------------------------------------------------------------------

export class StandardValidator implements CertificateValidator {
  private checkExpiry: boolean;
  private checkKeyUsage: boolean;
  private allowExpired: boolean;
  private nowFn: () => Date;

  constructor(opts?: ValidatorOptions & { nowFn?: () => Date }) {
    this.checkExpiry = opts?.checkExpiry ?? true;
    this.checkKeyUsage = opts?.checkKeyUsage ?? true;
    this.allowExpired = opts?.allowExpired ?? false;
    this.nowFn = opts?.nowFn ?? (() => new Date());
  }

  validateForEncryption(info: CertificateInfo): void {
    this.checkExpiryIfEnabled(info);

    if (this.checkKeyUsage) {
      const kuExt = info.cert.getExtension(x509.KeyUsagesExtension);
      if (kuExt) {
        const hasKeyEncipherment = !!(kuExt.usages & x509.KeyUsageFlags.keyEncipherment);
        const hasKeyAgreement = !!(kuExt.usages & x509.KeyUsageFlags.keyAgreement);
        if (!hasKeyEncipherment && !hasKeyAgreement) {
          throw new Error(
            `certificate "${info.subject}" does not have keyEncipherment or keyAgreement usage`,
          );
        }
      }
    }
  }

  validateForSigning(info: CertificateInfo): void {
    this.checkExpiryIfEnabled(info);

    if (this.checkKeyUsage) {
      const kuExt = info.cert.getExtension(x509.KeyUsagesExtension);
      if (kuExt) {
        const hasDigitalSignature = !!(kuExt.usages & x509.KeyUsageFlags.digitalSignature);
        if (!hasDigitalSignature) {
          throw new Error(
            `certificate "${info.subject}" does not have digitalSignature usage`,
          );
        }
      }
    }
  }

  async validateChain(
    info: CertificateInfo,
    intermediates?: CertificateInfo[],
    roots?: x509.X509Certificate[],
  ): Promise<void> {
    this.checkExpiryIfEnabled(info);

    if (roots && roots.length > 0) {
      const chainBuilder = new x509.X509ChainBuilder({
        certificates: intermediates?.map(i => i.cert) ?? [],
      });

      try {
        const chain = await chainBuilder.build(info.cert);
        // Verify the chain ends at a trusted root
        const rootCert = chain[chain.length - 1];
        if (rootCert) {
          const rootMatch = roots.some(r =>
            r.serialNumber === rootCert.serialNumber &&
            r.subject === rootCert.subject
          );
          if (!rootMatch) {
            throw new Error('chain does not terminate at a trusted root');
          }
        }
      } catch (e) {
        throw new Error(`chain verification failed: ${(e as Error).message}`);
      }
    }
  }

  private checkExpiryIfEnabled(info: CertificateInfo): void {
    if (!this.checkExpiry || this.allowExpired) return;

    const now = this.nowFn();
    if (now < info.notBefore) {
      throw new Error(
        `certificate "${info.subject}" not yet valid (notBefore: ${info.notBefore.toISOString()})`,
      );
    }
    if (now > info.notAfter) {
      throw new Error(
        `certificate "${info.subject}" expired (notAfter: ${info.notAfter.toISOString()})`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// NoOpValidator (testing only)
// ---------------------------------------------------------------------------

export class NoOpValidator implements CertificateValidator {
  validateForEncryption(_info: CertificateInfo): void {}
  validateForSigning(_info: CertificateInfo): void {}
  async validateChain(_info: CertificateInfo): Promise<void> {}
}

// ---------------------------------------------------------------------------
// Certificate parsing
// ---------------------------------------------------------------------------

/**
 * Parse a DER-encoded certificate into CertificateInfo.
 */
export function parseCertificateDER(der: Uint8Array): CertificateInfo {
  const cert = new x509.X509Certificate(der as unknown as BufferSource);
  return certToInfo(cert);
}

/**
 * Parse a PEM-encoded certificate into CertificateInfo.
 */
export function parseCertificatePEM(pem: string): CertificateInfo {
  const cert = new x509.X509Certificate(pem);
  return certToInfo(cert);
}

/**
 * Parse a PEM chain (multiple certificates) into CertificateInfo[].
 */
export function parseCertificateChainPEM(pem: string): CertificateInfo[] {
  const certs = x509.PemConverter.decode(pem);
  return certs.map(der => {
    const cert = new x509.X509Certificate(der);
    return certToInfo(cert);
  });
}

function certToInfo(cert: x509.X509Certificate): CertificateInfo {
  const skiExt = cert.getExtension(x509.SubjectKeyIdentifierExtension);

  return {
    cert,
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    subjectKeyIdentifier: skiExt?.keyId,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    publicKeyAlgorithm: cert.publicKey.algorithm.name,
    raw: new Uint8Array(cert.rawData),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Match a certificate by issuer and serial number.
 */
export function matchIssuerAndSerial(
  info: CertificateInfo,
  issuer: string,
  serialNumber: string,
): boolean {
  return info.issuer === issuer && info.serialNumber === serialNumber;
}

/**
 * Create a default StandardValidator with recommended settings.
 */
export function defaultValidator(): StandardValidator {
  return new StandardValidator();
}

/**
 * Generate a self-signed test certificate.
 * Requires crypto provider to be set (Node.js: set in test setup).
 */
export async function generateTestCertificate(opts: {
  subject: string;
  keyUsages?: number;
  notBefore?: Date;
  notAfter?: Date;
}): Promise<CertificateInfo> {
  const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const keys = await globalThis.crypto.subtle.generateKey(
    alg as EcKeyGenParams,
    true,
    ['sign', 'verify'],
  );

  const extensions: x509.Extension[] = [];
  if (opts.keyUsages !== undefined) {
    extensions.push(new x509.KeyUsagesExtension(opts.keyUsages, true));
  }

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Math.floor(Math.random() * 1000000).toString(16),
    name: `CN=${opts.subject}`,
    notBefore: opts.notBefore ?? new Date(),
    notAfter: opts.notAfter ?? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    keys: keys as CryptoKeyPair,
    signingAlgorithm: alg,
    extensions,
  });

  return certToInfo(cert);
}

/** Re-export KeyUsageFlags for convenience. */
export const KeyUsageFlags = x509.KeyUsageFlags;

// ---------------------------------------------------------------------------
// Self-Signed ML-DSA-65 Certificate
// ---------------------------------------------------------------------------

import { AsnConvert } from '@peculiar/asn1-schema';
import * as x509Asn from '@peculiar/asn1-x509';

/** OID for ML-DSA-65 (id-ml-dsa-65 from NIST CSOR) */
const OID_ML_DSA_65 = '2.16.840.1.101.3.4.3.18';

/**
 * Create a self-signed X.509v3 certificate with ML-DSA-65.
 *
 * Builds a certificate using the provided ML-DSA-65 key pair from
 * @noble/post-quantum. The certificate is signed directly with the
 * raw ML-DSA sign function — no WebCrypto needed.
 *
 * @param publicKey  ML-DSA-65 public key (1952 bytes)
 * @param signFn     Raw sign function: (message) => signature
 * @param subject    Subject CN (e.g., "Demo Sender")
 * @returns Base64-encoded DER certificate (for PV certificate viewer)
 */
export function createSelfSignedMLDSACert(
  publicKey: Uint8Array,
  signFn: (msg: Uint8Array) => Uint8Array,
  subject: string,
): string {
  const tbs = new x509Asn.TBSCertificate();
  tbs.version = x509Asn.Version.v3;

  // Random serial number (positive)
  const serial = new Uint8Array(16);
  crypto.getRandomValues(serial);
  serial[0] &= 0x7f;
  tbs.serialNumber = serial.buffer as ArrayBuffer;

  // ML-DSA-65 signature algorithm
  tbs.signature = new x509Asn.AlgorithmIdentifier({ algorithm: OID_ML_DSA_65 });

  // Issuer = Subject (self-signed)
  const name = new x509Asn.Name();
  const rdn = new x509Asn.RelativeDistinguishedName();
  rdn.push(new x509Asn.AttributeTypeAndValue({
    type: '2.5.4.3', // CN
    value: new x509Asn.AttributeValue({ printableString: subject }),
  }));
  name.push(rdn);
  tbs.issuer = name;
  tbs.subject = name;

  // Validity: now → +1 year
  const now = new Date();
  const expiry = new Date(now);
  expiry.setFullYear(expiry.getFullYear() + 1);
  tbs.validity = new x509Asn.Validity({
    notBefore: { utcTime: now } as any,
    notAfter: { utcTime: expiry } as any,
  });

  // ML-DSA-65 public key
  tbs.subjectPublicKeyInfo = new x509Asn.SubjectPublicKeyInfo({
    algorithm: new x509Asn.AlgorithmIdentifier({ algorithm: OID_ML_DSA_65 }),
    subjectPublicKey: publicKey.buffer as ArrayBuffer,
  });

  // Sign the TBSCertificate
  const tbsDer = new Uint8Array(AsnConvert.serialize(tbs));
  const signature = signFn(tbsDer);

  // Assemble the Certificate
  const cert = new x509Asn.Certificate({
    tbsCertificate: tbs,
    signatureAlgorithm: new x509Asn.AlgorithmIdentifier({ algorithm: OID_ML_DSA_65 }),
    signatureValue: signature.buffer as ArrayBuffer,
  });

  const certDer = new Uint8Array(AsnConvert.serialize(cert));
  return btoa(String.fromCharCode(...certDer));
}
