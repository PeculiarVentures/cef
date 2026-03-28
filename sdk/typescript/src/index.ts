// CEF SDK — workflow API (primary entry point)
//
// import { encrypt, decrypt, verify } from '@peculiarventures/cef';
//
// For core COSE/container primitives:
//   import { ... } from '@peculiarventures/cef/core';
//
// For X.509 certificate utilities:
//   import { ... } from '@peculiarventures/cef/x509';
//
// For RFC 3161 timestamp utilities:
//   import { ... } from '@peculiarventures/cef/timestamp';

export {
  // Workflow functions
  encrypt,
  decrypt,
  verify,
  // Types — what developers need
  type CEFFileInput,
  type Sender,
  type Recipient,
  type RecipientKey,
  type EncryptOptions,
  type DecryptOptions,
  type VerifyOptions,
  type EncryptResult,
  type DecryptResult,
  type DecryptedFile,
  type VerifyResult,
} from './cef.js';

// Re-export key generation utilities (developers need these for the workflow API)
export { mlkemKeygen, mldsaKeygen } from './format/pq.js';
export type { MLKEMKeyPair, MLDSAKeyPair } from './format/pq.js';
