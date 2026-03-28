//! COSE encryption and signing structures.
//!
//! Implements COSE_Encrypt (RFC 9052 §5.1) and COSE_Sign1 (RFC 9052 §4.2).

use ciborium::Value;
use std::collections::BTreeMap;
use crate::error::CefError;
use super::crypto::{aes_gcm_encrypt, aes_gcm_decrypt, random_bytes, zeroize_bytes};

// COSE algorithm IDs
pub const ALG_A256GCM: i64 = 3;
pub const ALG_MLKEM768_A256KW: i64 = -70010;
pub const ALG_MLDSA65: i64 = -49;

// COSE header labels
pub const HEADER_ALGORITHM: i64 = 1;
pub const HEADER_KEY_ID: i64 = 4;
pub const HEADER_IV: i64 = 5;
pub const HEADER_CEF_RECIPIENT_TYPE: i64 = -70001;

/// Type aliases for callback functions.
pub type WrapCEKFn = Box<dyn Fn(&[u8], &RecipientInfo) -> Result<Vec<u8>, CefError>>;
pub type UnwrapCEKFn = Box<dyn Fn(&[u8], &Recipient) -> Result<Vec<u8>, CefError>>;
pub type SignFn = Box<dyn Fn(&[u8]) -> Result<Vec<u8>, CefError>>;
pub type VerifyFn = Box<dyn Fn(&[u8], &[u8]) -> Result<(), CefError>>;

/// Recipient info for encryption (input).
pub struct RecipientInfo {
    pub key_id: String,
    pub algorithm: i64,
    pub recipient_type: Option<String>,
}

/// COSE_recipient (parsed).
pub struct Recipient {
    pub protected: BTreeMap<i64, Value>,
    pub protected_bytes: Vec<u8>,
    pub unprotected: BTreeMap<i64, Value>,
    pub ciphertext: Vec<u8>,
}

/// COSE_Encrypt message.
pub struct EncryptMessage {
    pub protected: BTreeMap<i64, Value>,
    pub protected_bytes: Vec<u8>,
    pub unprotected: BTreeMap<i64, Value>,
    pub ciphertext: Vec<u8>,
    pub recipients: Vec<Recipient>,
}

/// COSE_Sign1 message.
pub struct Sign1Message {
    pub protected: BTreeMap<i64, Value>,
    pub protected_bytes: Vec<u8>,
    pub unprotected: BTreeMap<i64, Value>,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn cbor_encode(value: &Value) -> Result<Vec<u8>, CefError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| CefError::Cose(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

fn cbor_decode(data: &[u8]) -> Result<Value, CefError> {
    ciborium::from_reader(data)
        .map_err(|e| CefError::Cose(format!("CBOR decode: {e}")))
}

fn encode_protected(header: &BTreeMap<i64, Value>) -> Result<Vec<u8>, CefError> {
    if header.is_empty() {
        return Ok(Vec::new());
    }
    let map: Vec<(Value, Value)> = header
        .iter()
        .map(|(k, v)| (Value::Integer(ciborium::value::Integer::from(*k)), v.clone()))
        .collect();
    cbor_encode(&Value::Map(map))
}

fn decode_protected(data: &[u8]) -> Result<BTreeMap<i64, Value>, CefError> {
    if data.is_empty() {
        return Ok(BTreeMap::new());
    }
    let value = cbor_decode(data)?;
    value_to_header_map(&value)
}

fn value_to_header_map(value: &Value) -> Result<BTreeMap<i64, Value>, CefError> {
    match value {
        Value::Map(entries) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                let key = match k {
                    Value::Integer(i) => {
                        let n: i128 = i128::from(*i);
                        n as i64
                    }
                    _ => return Err(CefError::Cose("header key is not an integer".into())),
                };
                map.insert(key, v.clone());
            }
            Ok(map)
        }
        _ => Err(CefError::Cose("expected CBOR map for header".into())),
    }
}

fn header_map_to_cbor(map: &BTreeMap<i64, Value>) -> Value {
    Value::Map(
        map.iter()
            .map(|(k, v)| (Value::Integer(ciborium::value::Integer::from(*k)), v.clone()))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// COSE structures (Enc_structure, Sig_structure)
// ---------------------------------------------------------------------------

/// Build Enc_structure for AAD (RFC 9052 §5.3).
pub fn build_enc_structure(protected_bytes: &[u8], external_aad: &[u8]) -> Result<Vec<u8>, CefError> {
    let value = Value::Array(vec![
        Value::Text("Encrypt".into()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(external_aad.to_vec()),
    ]);
    cbor_encode(&value)
}

/// Build Sig_structure for signing (RFC 9052 §4.4).
pub fn build_sig_structure(
    protected_bytes: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CefError> {
    let value = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    cbor_encode(&value)
}

// ---------------------------------------------------------------------------
// COSE_Encrypt
// ---------------------------------------------------------------------------

/// Encrypt plaintext into a COSE_Encrypt message.
pub fn encrypt(
    plaintext: &[u8],
    recipients: &[RecipientInfo],
    wrap_cek: &dyn Fn(&[u8], &RecipientInfo) -> Result<Vec<u8>, CefError>,
) -> Result<EncryptMessage, CefError> {
    if recipients.is_empty() {
        return Err(CefError::Cose("at least one recipient is required".into()));
    }

    let mut cek = random_bytes(32);
    let iv = random_bytes(12);

    let result = (|| -> Result<EncryptMessage, CefError> {
        let mut protected = BTreeMap::new();
        protected.insert(HEADER_ALGORITHM, Value::Integer(ciborium::value::Integer::from(ALG_A256GCM)));
        let protected_bytes = encode_protected(&protected)?;

        let mut unprotected = BTreeMap::new();
        unprotected.insert(HEADER_IV, Value::Bytes(iv.clone()));

        let aad = build_enc_structure(&protected_bytes, &[])?;
        let ciphertext = aes_gcm_encrypt(&cek, &iv, plaintext, &aad)?;

        let mut cose_recipients = Vec::new();
        for ri in recipients {
            let mut r_protected = BTreeMap::new();
            r_protected.insert(HEADER_ALGORITHM, Value::Integer(ciborium::value::Integer::from(ri.algorithm)));
            let r_protected_bytes = encode_protected(&r_protected)?;

            let mut r_unprotected = BTreeMap::new();
            r_unprotected.insert(HEADER_KEY_ID, Value::Bytes(ri.key_id.as_bytes().to_vec()));
            if let Some(ref t) = ri.recipient_type {
                r_unprotected.insert(HEADER_CEF_RECIPIENT_TYPE, Value::Text(t.clone()));
            }

            let wrapped_cek = wrap_cek(&cek, ri)?;

            cose_recipients.push(Recipient {
                protected: r_protected,
                protected_bytes: r_protected_bytes,
                unprotected: r_unprotected,
                ciphertext: wrapped_cek,
            });
        }

        Ok(EncryptMessage {
            protected,
            protected_bytes,
            unprotected,
            ciphertext,
            recipients: cose_recipients,
        })
    })();

    zeroize_bytes(&mut cek);
    result
}

/// Decrypt a COSE_Encrypt message.
pub fn decrypt(
    msg: &EncryptMessage,
    recipient_index: usize,
    unwrap_cek: &dyn Fn(&[u8], &Recipient) -> Result<Vec<u8>, CefError>,
) -> Result<Vec<u8>, CefError> {
    if recipient_index >= msg.recipients.len() {
        return Err(CefError::Cose(format!(
            "recipient index {} out of range [0, {})",
            recipient_index,
            msg.recipients.len()
        )));
    }

    let recipient = &msg.recipients[recipient_index];
    let mut cek = unwrap_cek(&recipient.ciphertext, recipient)?;

    let result = (|| -> Result<Vec<u8>, CefError> {
        let iv = match msg.unprotected.get(&HEADER_IV) {
            Some(Value::Bytes(iv)) => iv.clone(),
            _ => return Err(CefError::Cose("missing or invalid IV".into())),
        };
        if iv.len() != 12 {
            return Err(CefError::Cose(format!("IV must be 12 bytes, got {}", iv.len())));
        }

        let aad = build_enc_structure(&msg.protected_bytes, &[])?;
        aes_gcm_decrypt(&cek, &iv, &msg.ciphertext, &aad)
    })();

    zeroize_bytes(&mut cek);
    result
}

/// Find recipient index by key ID.
pub fn find_recipient_index(msg: &EncryptMessage, kid: &str) -> Result<usize, CefError> {
    let kid_bytes = kid.as_bytes();
    for (i, r) in msg.recipients.iter().enumerate() {
        if let Some(Value::Bytes(k)) = r.unprotected.get(&HEADER_KEY_ID) {
            if k == kid_bytes {
                return Ok(i);
            }
        }
    }
    Err(CefError::Cose(format!("recipient '{}' not found", kid)))
}

// ---------------------------------------------------------------------------
// COSE_Sign1
// ---------------------------------------------------------------------------

/// Create a COSE_Sign1 message (tag 18).
pub fn sign1(
    algorithm: i64,
    key_id: &str,
    payload: &[u8],
    detached: bool,
    sign_fn: &dyn Fn(&[u8]) -> Result<Vec<u8>, CefError>,
) -> Result<Sign1Message, CefError> {
    let mut protected = BTreeMap::new();
    protected.insert(HEADER_ALGORITHM, Value::Integer(ciborium::value::Integer::from(algorithm)));
    let protected_bytes = encode_protected(&protected)?;

    let mut unprotected = BTreeMap::new();
    unprotected.insert(HEADER_KEY_ID, Value::Bytes(key_id.as_bytes().to_vec()));

    let sig_structure = build_sig_structure(&protected_bytes, &[], payload)?;
    let signature = sign_fn(&sig_structure)?;

    Ok(Sign1Message {
        protected,
        protected_bytes,
        unprotected,
        payload: if detached { None } else { Some(payload.to_vec()) },
        signature,
    })
}

/// Verify a COSE_Sign1 message.
pub fn verify1(
    msg: &Sign1Message,
    external_payload: Option<&[u8]>,
    verify_fn: &dyn Fn(&[u8], &[u8]) -> Result<(), CefError>,
) -> Result<(), CefError> {
    let payload = match &msg.payload {
        Some(p) if !p.is_empty() => p.as_slice(),
        _ => external_payload
            .ok_or_else(|| CefError::Cose("no payload for verification (detached)".into()))?,
    };

    let sig_structure = build_sig_structure(&msg.protected_bytes, &[], payload)?;
    verify_fn(&sig_structure, &msg.signature)
}

// ---------------------------------------------------------------------------
// CBOR Serialization
// ---------------------------------------------------------------------------

/// Serialize COSE_Encrypt to CBOR with tag 96.
pub fn marshal_encrypt(msg: &EncryptMessage) -> Result<Vec<u8>, CefError> {
    let recipients_cbor: Vec<Value> = msg
        .recipients
        .iter()
        .map(|r| {
            Value::Array(vec![
                Value::Bytes(r.protected_bytes.clone()),
                header_map_to_cbor(&r.unprotected),
                Value::Bytes(r.ciphertext.clone()),
            ])
        })
        .collect();

    let inner = Value::Array(vec![
        Value::Bytes(msg.protected_bytes.clone()),
        header_map_to_cbor(&msg.unprotected),
        Value::Bytes(msg.ciphertext.clone()),
        Value::Array(recipients_cbor),
    ]);

    let tagged = Value::Tag(96, Box::new(inner));
    cbor_encode(&tagged)
}

/// Deserialize CBOR to COSE_Encrypt.
pub fn unmarshal_encrypt(data: &[u8]) -> Result<EncryptMessage, CefError> {
    let value = cbor_decode(data)?;

    let inner = match value {
        Value::Tag(96, inner) => *inner,
        _ => return Err(CefError::Cose("expected CBOR tag 96 for COSE_Encrypt".into())),
    };

    let arr = match inner {
        Value::Array(a) if a.len() == 4 => a,
        _ => return Err(CefError::Cose("COSE_Encrypt must be a 4-element array".into())),
    };

    let protected_bytes = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CefError::Cose("protected must be bstr".into())),
    };
    let protected = decode_protected(&protected_bytes)?;
    let unprotected = value_to_header_map(&arr[1])?;
    let ciphertext = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CefError::Cose("ciphertext must be bstr".into())),
    };

    let recipients_arr = match &arr[3] {
        Value::Array(a) => a,
        _ => return Err(CefError::Cose("recipients must be array".into())),
    };

    let mut recipients = Vec::new();
    for r in recipients_arr {
        let ra = match r {
            Value::Array(a) if a.len() == 3 => a,
            _ => return Err(CefError::Cose("recipient must be 3-element array".into())),
        };
        let r_protected_bytes = match &ra[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(CefError::Cose("recipient protected must be bstr".into())),
        };
        let r_protected = decode_protected(&r_protected_bytes)?;
        let r_unprotected = value_to_header_map(&ra[1])?;
        let r_ciphertext = match &ra[2] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(CefError::Cose("recipient ciphertext must be bstr".into())),
        };
        recipients.push(Recipient {
            protected: r_protected,
            protected_bytes: r_protected_bytes,
            unprotected: r_unprotected,
            ciphertext: r_ciphertext,
        });
    }

    Ok(EncryptMessage {
        protected,
        protected_bytes,
        unprotected,
        ciphertext,
        recipients,
    })
}

/// Serialize COSE_Sign1 to CBOR with tag 18.
pub fn marshal_sign1(msg: &Sign1Message) -> Result<Vec<u8>, CefError> {
    let payload = match &msg.payload {
        Some(p) => Value::Bytes(p.clone()),
        None => Value::Null,
    };

    let inner = Value::Array(vec![
        Value::Bytes(msg.protected_bytes.clone()),
        header_map_to_cbor(&msg.unprotected),
        payload,
        Value::Bytes(msg.signature.clone()),
    ]);

    let tagged = Value::Tag(18, Box::new(inner));
    cbor_encode(&tagged)
}

/// Deserialize CBOR to COSE_Sign1.
pub fn unmarshal_sign1(data: &[u8]) -> Result<Sign1Message, CefError> {
    let value = cbor_decode(data)?;

    let inner = match value {
        Value::Tag(18, inner) => *inner,
        _ => return Err(CefError::Cose("expected CBOR tag 18 for COSE_Sign1".into())),
    };

    let arr = match inner {
        Value::Array(a) if a.len() == 4 => a,
        _ => return Err(CefError::Cose("COSE_Sign1 must be a 4-element array".into())),
    };

    let protected_bytes = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CefError::Cose("protected must be bstr".into())),
    };
    let protected = decode_protected(&protected_bytes)?;
    let unprotected = value_to_header_map(&arr[1])?;

    let payload = match &arr[2] {
        Value::Null => None,
        Value::Bytes(b) if b.is_empty() => None,
        Value::Bytes(b) => Some(b.clone()),
        _ => return Err(CefError::Cose("payload must be bstr or null".into())),
    };

    let signature = match &arr[3] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CefError::Cose("signature must be bstr".into())),
    };

    Ok(Sign1Message {
        protected,
        protected_bytes,
        unprotected,
        payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::crypto::random_bytes;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let ri = RecipientInfo { key_id: "test".into(), algorithm: -1, recipient_type: None };
        let plaintext = b"hello world";
        let wrap = |cek: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(cek.to_vec()) };
        let msg = encrypt(plaintext, &[ri], &wrap).unwrap();
        let unwrap = |wrapped: &[u8], _: &Recipient| -> Result<Vec<u8>, CefError> { Ok(wrapped.to_vec()) };
        let pt = decrypt(&msg, 0, &unwrap).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn marshal_unmarshal_round_trip() {
        let ri = RecipientInfo { key_id: "kid1".into(), algorithm: -1, recipient_type: Some("key".into()) };
        let wrap = |cek: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(cek.to_vec()) };
        let msg = encrypt(b"test data", &[ri], &wrap).unwrap();
        let bytes = marshal_encrypt(&msg).unwrap();
        let msg2 = unmarshal_encrypt(&bytes).unwrap();
        assert_eq!(msg.ciphertext, msg2.ciphertext);
        assert_eq!(msg.recipients.len(), msg2.recipients.len());
        assert_eq!(msg.recipients[0].ciphertext, msg2.recipients[0].ciphertext);
    }

    #[test]
    fn find_recipient_index_works() {
        let recipients = vec![
            RecipientInfo { key_id: "alice".into(), algorithm: -1, recipient_type: None },
            RecipientInfo { key_id: "bob".into(), algorithm: -1, recipient_type: None },
        ];
        let wrap = |cek: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(cek.to_vec()) };
        let msg = encrypt(b"x", &recipients, &wrap).unwrap();
        assert_eq!(find_recipient_index(&msg, "alice").unwrap(), 0);
        assert_eq!(find_recipient_index(&msg, "bob").unwrap(), 1);
        assert!(find_recipient_index(&msg, "eve").is_err());
    }

    #[test]
    fn no_recipients_fails() {
        let wrap = |_: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(vec![]) };
        assert!(encrypt(b"x", &[], &wrap).is_err());
    }

    #[test]
    fn wrong_tag_rejected() {
        let data = cbor_encode(&Value::Tag(99, Box::new(Value::Array(vec![
            Value::Bytes(vec![]), Value::Map(vec![]),
            Value::Bytes(vec![]), Value::Array(vec![]),
        ])))).unwrap();
        assert!(unmarshal_encrypt(&data).is_err());
    }

    #[test]
    fn sign1_round_trip() {
        let sign_fn = |data: &[u8]| -> Result<Vec<u8>, CefError> { Ok(data[..32.min(data.len())].to_vec()) };
        let verify_fn = |data: &[u8], sig: &[u8]| -> Result<(), CefError> {
            if &data[..sig.len().min(data.len())] == sig { Ok(()) } else { Err(CefError::Cose("bad".into())) }
        };
        let msg = sign1(-49, "sender", b"payload", false, &sign_fn).unwrap();
        verify1(&msg, None, &verify_fn).unwrap();
    }

    #[test]
    fn sign1_detached_payload() {
        let sign_fn = |data: &[u8]| -> Result<Vec<u8>, CefError> { Ok(data[..32.min(data.len())].to_vec()) };
        let verify_fn = |data: &[u8], sig: &[u8]| -> Result<(), CefError> {
            if &data[..sig.len().min(data.len())] == sig { Ok(()) } else { Err(CefError::Cose("bad".into())) }
        };
        let msg = sign1(-49, "sender", b"detached", true, &sign_fn).unwrap();
        assert!(msg.payload.is_none());
        verify1(&msg, Some(b"detached"), &verify_fn).unwrap();
        // Wrong external payload fails
        assert!(verify1(&msg, Some(b"wrong"), &verify_fn).is_err());
    }

    #[test]
    fn sign1_marshal_unmarshal() {
        let sign_fn = |_: &[u8]| -> Result<Vec<u8>, CefError> { Ok(vec![1, 2, 3]) };
        let msg = sign1(-49, "kid", b"payload", false, &sign_fn).unwrap();
        let bytes = marshal_sign1(&msg).unwrap();
        let msg2 = unmarshal_sign1(&bytes).unwrap();
        assert_eq!(msg.signature, msg2.signature);
        assert_eq!(msg.payload, msg2.payload);
    }

    #[test]
    fn sign1_wrong_tag_rejected() {
        let data = cbor_encode(&Value::Tag(99, Box::new(Value::Array(vec![
            Value::Bytes(vec![]), Value::Map(vec![]),
            Value::Null, Value::Bytes(vec![]),
        ])))).unwrap();
        assert!(unmarshal_sign1(&data).is_err());
    }

    #[test]
    fn empty_payload_round_trip() {
        let ri = RecipientInfo { key_id: "t".into(), algorithm: -1, recipient_type: None };
        let wrap = |cek: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(cek.to_vec()) };
        let msg = encrypt(b"", &[ri], &wrap).unwrap();
        let unwrap = |w: &[u8], _: &Recipient| -> Result<Vec<u8>, CefError> { Ok(w.to_vec()) };
        let pt = decrypt(&msg, 0, &unwrap).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn recipient_type_preserved() {
        let ri = RecipientInfo { key_id: "t".into(), algorithm: -1, recipient_type: Some("email".into()) };
        let wrap = |cek: &[u8], _: &RecipientInfo| -> Result<Vec<u8>, CefError> { Ok(cek.to_vec()) };
        let msg = encrypt(b"x", &[ri], &wrap).unwrap();
        let bytes = marshal_encrypt(&msg).unwrap();
        let msg2 = unmarshal_encrypt(&bytes).unwrap();
        let t = msg2.recipients[0].unprotected.get(&HEADER_CEF_RECIPIENT_TYPE);
        assert_eq!(t, Some(&Value::Text("email".into())));
    }
}
