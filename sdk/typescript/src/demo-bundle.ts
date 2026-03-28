// Demo bundle entry point.
// Exports the workflow API (primary) and format internals (for inspection).

// Workflow API
export { encrypt, decrypt, verify } from './cef.js';
export type {
  CEFFileInput, Sender, Recipient, RecipientKey,
  EncryptOptions, DecryptOptions, VerifyOptions,
  EncryptResult, DecryptResult, DecryptedFile, VerifyResult,
} from './cef.js';

// Key generation (needed by demo)
export { mlkemKeygen, mldsaKeygen } from './format/pq.js';

// Format internals (needed by demo for inspection panels)
export {
  readContainer, unmarshalEncrypt, unmarshalSign1,
  toHex, randomBytes,
  HeaderAlgorithm, HeaderKeyID, HeaderIV,
} from './format/index.js';
