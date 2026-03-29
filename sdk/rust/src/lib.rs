//! CEF: COSE Encrypted Files — post-quantum secure file exchange format.
//!
//! # Quick Start
//!
//! ```rust
//! use cef::{encrypt, decrypt, EncryptOptions, DecryptOptions, Sender, Recipient, FileInput};
//! use cef::format::pq::{mlkem_keygen, mldsa_keygen};
//!
//! let sender_kp = mldsa_keygen();
//! let recip_kp = mlkem_keygen();
//!
//! let result = encrypt(EncryptOptions {
//!     files: vec![FileInput { name: "hello.txt".into(), data: b"hello".to_vec(), content_type: None }],
//!     sender: Sender { signing_key: sender_kp.secret_key, kid: "alice".into(), x5c: None, claims: None },
//!     recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip_kp.public_key.clone(), recipient_type: None }],
//!     timestamp: None, key_wrap: None, sign: None,
//! }).unwrap();
//!
//! let dec = decrypt(&result.container, DecryptOptions {
//!     recipient_kid: "bob".into(),
//!     decryption_key: recip_kp.secret_key,
//!     verify_key: Some(sender_kp.public_key),
//!     skip_signature_verification: false, key_unwrap: None, verify_fn: None,
//! }).unwrap();
//!
//! assert_eq!(dec.files[0].original_name, "hello.txt");
//! ```

pub mod error;
pub mod format;

use std::collections::HashMap;

use error::CefError;
use format::container::*;
use format::cose;
use format::crypto;
use format::pq;

/// A file to encrypt.
pub struct FileInput {
    pub name: String,
    pub data: Vec<u8>,
    pub content_type: Option<String>,
}

/// Sender identity for signing.
pub struct Sender {
    pub signing_key: Vec<u8>,
    pub kid: String,
    pub x5c: Option<Vec<Vec<u8>>>,
    pub claims: Option<SenderClaims>,
}

/// A recipient of the encrypted container.
pub struct Recipient {
    pub kid: String,
    pub encryption_key: Vec<u8>,
    pub recipient_type: Option<String>,
}

/// Options for encrypt().
pub struct EncryptOptions {
    pub files: Vec<FileInput>,
    pub sender: Sender,
    pub recipients: Vec<Recipient>,
    pub timestamp: Option<Vec<u8>>,
    /// Custom key wrap callback (HSM, cloud KMS). When set, Recipients[].encryption_key is ignored.
    pub key_wrap: Option<Box<dyn Fn(&[u8], &cose::RecipientInfo) -> Result<Vec<u8>, error::CefError>>>,
    /// Custom sign callback. When set, Sender.signing_key is ignored.
    pub sign: Option<Box<dyn Fn(&[u8]) -> Result<Vec<u8>, error::CefError>>>,
}

/// Result of encrypt().
#[derive(Debug)]
pub struct EncryptResult {
    pub container: Vec<u8>,
    pub file_count: usize,
    pub signed: bool,
}

/// Options for decrypt().
pub struct DecryptOptions {
    pub recipient_kid: String,
    pub decryption_key: Vec<u8>,
    pub verify_key: Option<Vec<u8>>,
    pub skip_signature_verification: bool,
    /// Custom key unwrap callback (HSM, cloud KMS). When set, decryption_key is ignored.
    pub key_unwrap: Option<Box<dyn Fn(&[u8], &cose::Recipient) -> Result<Vec<u8>, error::CefError>>>,
    /// Custom verify callback. When set, verify_key is ignored.
    pub verify_fn: Option<Box<dyn Fn(&[u8], &[u8]) -> Result<(), error::CefError>>>,
}

/// A decrypted file.
#[derive(Debug)]
pub struct DecryptedFile {
    pub original_name: String,
    pub data: Vec<u8>,
    pub size: u64,
}

/// Result of decrypt().
#[derive(Debug)]
pub struct DecryptResult {
    pub files: Vec<DecryptedFile>,
    pub signature_valid: Option<bool>,
    pub sender_kid: String,
    pub sender_x5c: Option<Vec<Vec<u8>>>,
    pub sender_claims: Option<format::container::SenderClaims>,
    pub created_at: Option<String>,
}

/// Options for verify().
pub struct VerifyOptions {
    pub verify_key: Vec<u8>,
}

/// Result of verify().
#[derive(Debug)]
pub struct VerifyResult {
    pub signature_valid: bool,
    pub sender_kid: Option<String>,
    pub timestamp_present: bool,
}

/// Encrypt files into a signed CEF container.
pub fn encrypt(opts: EncryptOptions) -> Result<EncryptResult, CefError> {
    if opts.recipients.is_empty() {
        return Err(CefError::General("cef: at least one recipient is required".into()));
    }
    if opts.files.is_empty() {
        return Err(CefError::General("cef: at least one file is required".into()));
    }

    let mut pub_keys = HashMap::new();
    if opts.key_wrap.is_none() {
        for r in &opts.recipients {
            if r.encryption_key.is_empty() {
                return Err(CefError::General(format!(
                    "cef: recipient \"{}\" has no encryption key", r.kid
                )));
            }
            pub_keys.insert(r.kid.clone(), r.encryption_key.clone());
        }
    }

    let wrap_cek: Box<dyn Fn(&[u8], &cose::RecipientInfo) -> Result<Vec<u8>, CefError>> =
        if let Some(ref custom) = opts.key_wrap {
            Box::new(|cek: &[u8], ri: &cose::RecipientInfo| custom(cek, ri))
        } else {
            let keys = pub_keys.clone();
            Box::new(move |cek: &[u8], ri: &cose::RecipientInfo| {
                let pk = keys.get(&ri.key_id)
                    .ok_or_else(|| CefError::General(format!("cef: no public key for \"{}\"", ri.key_id)))?;
                pq::mlkem_wrap(pk, cek)
            })
        };

    let sign_fn: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, CefError>> =
        if let Some(ref custom) = opts.sign {
            Box::new(|data: &[u8]| custom(data))
        } else {
            let sk = opts.sender.signing_key.clone();
            Box::new(move |sig_structure: &[u8]| pq::mldsa_sign(&sk, sig_structure))
        };

    // Sender info
    let sender_claims = if opts.sender.x5c.is_some() {
        None
    } else {
        let mut claims = opts.sender.claims.clone().unwrap_or_default();
        claims.created_at = Some(iso_now());
        Some(claims)
    };

    let cose_recipients: Vec<cose::RecipientInfo> = opts.recipients.iter().map(|r| {
        cose::RecipientInfo {
            key_id: r.kid.clone(),
            algorithm: cose::ALG_MLKEM768_A256KW,
            recipient_type: r.recipient_type.clone(),
        }
    }).collect();

    // Encrypt each file
    let mut manifest_files = std::collections::BTreeMap::new();
    let mut encrypted_files = std::collections::BTreeMap::new();
    for f in &opts.files {
        let hash = crypto::sha256(&f.data);
        let enc = cose::encrypt(&f.data, &cose_recipients, &wrap_cek)?;
        let enc_bytes = cose::marshal_encrypt(&enc)?;
        let obf = random_file_name();
        manifest_files.insert(obf.clone(), FileMetadata {
            original_name: sanitize_filename(&f.name),
            hash: hash.to_vec(),
            hash_algorithm: HASH_ALG_SHA256,
            size: f.data.len() as u64,
            content_type: f.content_type.clone(),
        });
        encrypted_files.insert(obf, enc_bytes);
    }

    let manifest = Manifest {
        version: FORMAT_VERSION.into(),
        sender: SenderInfo {
            kid: opts.sender.kid.clone(),
            x5c: opts.sender.x5c.clone(),
            claims: sender_claims,
        },
        recipients: opts.recipients.iter().map(|r| RecipientRef {
            kid: r.kid.clone(),
            recipient_type: r.recipient_type.clone().or(Some("key".into())),
        }).collect(),
        files: manifest_files,
    };

    let manifest_bytes = marshal_manifest(&manifest)?;
    let enc_manifest = cose::encrypt(&manifest_bytes, &cose_recipients, &wrap_cek)?;
    let enc_manifest_bytes = cose::marshal_encrypt(&enc_manifest)?;

    let sig = cose::sign1(cose::ALG_MLDSA65, &opts.sender.kid, &enc_manifest_bytes, true, &sign_fn)?;
    let sig_bytes = cose::marshal_sign1(&sig)?;

    let container = Container {
        encrypted_manifest: Some(enc_manifest_bytes),
        manifest_signature: Some(sig_bytes),
        timestamp: opts.timestamp,
        encrypted_files,
        manifest: Some(manifest),
    };

    let bytes = write_container(&container)?;
    Ok(EncryptResult { container: bytes, file_count: opts.files.len(), signed: true })
}

/// Decrypt and verify a CEF container.
pub fn decrypt(data: &[u8], opts: DecryptOptions) -> Result<DecryptResult, CefError> {
    if opts.recipient_kid.is_empty() {
        return Err(CefError::General("cef: recipient kid is required".into()));
    }

    let container = read_container(data)?;

    // Verify signature
    let mut sig_valid: Option<bool> = None;
    if let Some(ref sig_bytes) = container.manifest_signature {
        if !opts.skip_signature_verification {
            let sig1 = cose::unmarshal_sign1(sig_bytes)?;
            let enc_m = container.encrypted_manifest.as_ref()
                .ok_or_else(|| CefError::General("cef: no encrypted manifest".into()))?;
            let vfn: Box<dyn Fn(&[u8], &[u8]) -> Result<(), CefError>> =
                if let Some(ref custom) = opts.verify_fn {
                    Box::new(|ss: &[u8], s: &[u8]| custom(ss, s))
                } else {
                    let vk = opts.verify_key.as_ref().ok_or_else(|| {
                        CefError::General("cef: sender verification key required (or set skip_signature_verification)".into())
                    })?.clone();
                    Box::new(move |ss: &[u8], s: &[u8]| pq::mldsa_verify(&vk, ss, s))
                };
            match cose::verify1(&sig1, Some(enc_m), &*vfn) {
                Ok(()) => sig_valid = Some(true),
                Err(e) => return Err(CefError::General(format!("cef: signature verification failed: {e}"))),
            }
        }
    }

    // Decrypt manifest
    let enc_m_bytes = container.encrypted_manifest.as_ref()
        .ok_or_else(|| CefError::General("cef: no encrypted manifest".into()))?;
    let unwrap: Box<dyn Fn(&[u8], &cose::Recipient) -> Result<Vec<u8>, CefError>> =
        if let Some(ref custom) = opts.key_unwrap {
            Box::new(|w: &[u8], r: &cose::Recipient| custom(w, r))
        } else {
            let dk = opts.decryption_key.clone();
            Box::new(move |w: &[u8], _: &cose::Recipient| pq::mlkem_unwrap(&dk, w))
        };
    let enc_m = cose::unmarshal_encrypt(enc_m_bytes)?;
    let idx = cose::find_recipient_index(&enc_m, &opts.recipient_kid)?;
    let m_bytes = cose::decrypt(&enc_m, idx, &*unwrap)?;
    let manifest = unmarshal_manifest(&m_bytes)?;

    // Truncation check
    for name in manifest.files.keys() {
        if !container.encrypted_files.contains_key(name) {
            return Err(CefError::General(format!(
                "cef: container is missing file \"{}\" listed in manifest (possible truncation)", name
            )));
        }
    }

    // Decrypt files
    let mut files = Vec::new();
    for (enc_name, meta) in &manifest.files {
        let enc_data = container.encrypted_files.get(enc_name)
            .ok_or_else(|| CefError::General(format!("cef: file \"{}\" not found", enc_name)))?;
        let enc_file = cose::unmarshal_encrypt(enc_data)?;
        let fi = cose::find_recipient_index(&enc_file, &opts.recipient_kid)?;
        let plaintext = cose::decrypt(&enc_file, fi, &unwrap)?;

        // Constant-time hash verification
        let hash = crypto::sha256(&plaintext);
        if !meta.hash.is_empty() {
            use subtle::ConstantTimeEq;
            if hash.ct_eq(&meta.hash).unwrap_u8() != 1 {
                return Err(CefError::General(format!("cef: hash mismatch for \"{}\"", meta.original_name)));
            }
        }

        files.push(DecryptedFile {
            original_name: sanitize_filename(&meta.original_name),
            data: plaintext,
            size: meta.size,
        });
    }

    let created_at = manifest.sender.claims.as_ref().and_then(|c| c.created_at.clone());
    Ok(DecryptResult {
        files,
        signature_valid: sig_valid,
        sender_kid: manifest.sender.kid,
        sender_x5c: manifest.sender.x5c,
        sender_claims: manifest.sender.claims,
        created_at,
    })
}

/// Verify a container's signature without decrypting.
pub fn verify(data: &[u8], opts: VerifyOptions) -> Result<VerifyResult, CefError> {
    let container = read_container(data)?;
    let mut result = VerifyResult {
        signature_valid: false,
        sender_kid: None,
        timestamp_present: container.timestamp.is_some(),
    };

    if let Some(ref sig_bytes) = container.manifest_signature {
        let sig1 = cose::unmarshal_sign1(sig_bytes)?;
        if let Some(ciborium::Value::Bytes(kid)) = sig1.unprotected.get(&cose::HEADER_KEY_ID) {
            result.sender_kid = Some(String::from_utf8_lossy(kid).to_string());
        }
        if let Some(ref enc_m) = container.encrypted_manifest {
            let vfn = |ss: &[u8], s: &[u8]| pq::mldsa_verify(&opts.verify_key, ss, s);
            result.signature_valid = cose::verify1(&sig1, Some(enc_m), &vfn).is_ok();
        }
    }

    Ok(result)
}

/// Strip path separators and dangerous patterns from filenames.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if base.is_empty() || base == "." || base == ".." {
        "unnamed".to_string()
    } else {
        base.replace("..", "_")
    }
}

fn iso_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (y, m, d) = days_to_ymd(secs / 86400);
    let t = secs % 86400;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, t/3600, (t%3600)/60, t%60)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    loop {
        let diy = if y%4==0 && (y%100!=0 || y%400==0) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy;
        y += 1;
    }
    let leap = y%4==0 && (y%100!=0 || y%400==0);
    let ms = if leap { [31,29,31,30,31,30,31,31,30,31,30,31] } else { [31,28,31,30,31,30,31,31,30,31,30,31] };
    let mut mo = 1u64;
    for m in ms { if days < m { break; } days -= m; mo += 1; }
    (y, mo, days + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use format::pq::{mlkem_keygen, mldsa_keygen};

    #[test]
    fn encrypt_decrypt_round_trip() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![FileInput {
                name: "hello.txt".into(),
                data: b"hello world".to_vec(),
                content_type: None,
            }],
            sender: Sender {
                signing_key: sender.secret_key,
                kid: "alice".into(),
                x5c: None,
                claims: None,
            },
            recipients: vec![Recipient {
                kid: "bob".into(),
                encryption_key: recip.public_key,
                recipient_type: None,
            }],
            timestamp: None, key_wrap: None, sign: None,
        })
        .unwrap();

        assert!(result.container.len() > 0);
        assert_eq!(result.file_count, 1);
        assert!(result.signed);

        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "bob".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        })
        .unwrap();

        assert_eq!(dec.files.len(), 1);
        assert_eq!(dec.files[0].original_name, "hello.txt");
        assert_eq!(dec.files[0].data, b"hello world");
        assert_eq!(dec.signature_valid, Some(true));
        assert_eq!(dec.sender_kid, "alice");
    }

    #[test]
    fn encrypt_decrypt_multiple_files() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![
                FileInput { name: "a.txt".into(), data: b"file a".to_vec(), content_type: None },
                FileInput { name: "b.txt".into(), data: b"file b".to_vec(), content_type: None },
            ],
            sender: Sender {
                signing_key: sender.secret_key,
                kid: "alice".into(),
                x5c: None,
                claims: None,
            },
            recipients: vec![Recipient {
                kid: "bob".into(),
                encryption_key: recip.public_key,
                recipient_type: None,
            }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();

        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "bob".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();

        assert_eq!(dec.files.len(), 2);
        let names: Vec<&str> = dec.files.iter().map(|f| f.original_name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
    }

    #[test]
    fn multiple_recipients() {
        let sender = mldsa_keygen();
        let bob = mlkem_keygen();
        let carol = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "test.txt".into(), data: b"multi".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "alice".into(), x5c: None, claims: None },
            recipients: vec![
                Recipient { kid: "bob".into(), encryption_key: bob.public_key, recipient_type: None },
                Recipient { kid: "carol".into(), encryption_key: carol.public_key, recipient_type: None },
            ],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();

        // Bob decrypts
        let dec1 = decrypt(&result.container, DecryptOptions {
            recipient_kid: "bob".into(),
            decryption_key: bob.secret_key,
            verify_key: Some(sender.public_key.clone()),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec1.files[0].data, b"multi");

        // Carol decrypts
        let dec2 = decrypt(&result.container, DecryptOptions {
            recipient_kid: "carol".into(),
            decryption_key: carol.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec2.files[0].data, b"multi");
    }

    #[test]
    fn verify_signature() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "alice".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();

        let vr = verify(&result.container, VerifyOptions { verify_key: sender.public_key }).unwrap();
        assert!(vr.signature_valid);
        assert_eq!(vr.sender_kid, Some("alice".into()));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let sender = mldsa_keygen();
        let wrong = mldsa_keygen();
        let recip = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "alice".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();

        let vr = verify(&result.container, VerifyOptions { verify_key: wrong.public_key }).unwrap();
        assert!(!vr.signature_valid);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let sender = mldsa_keygen();
        let bob = mlkem_keygen();
        let eve = mlkem_keygen();

        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"secret".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "alice".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "bob".into(), encryption_key: bob.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();

        let err = decrypt(&result.container, DecryptOptions {
            recipient_kid: "bob".into(),
            decryption_key: eve.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: true, key_unwrap: None, verify_fn: None,
        });
        assert!(err.is_err());
    }

    #[test]
    fn rejects_empty_recipients() {
        let sender = mldsa_keygen();
        let err = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![],
            timestamp: None, key_wrap: None, sign: None,
        });
        assert!(err.is_err());
    }

    #[test]
    fn rejects_empty_files() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let err = encrypt(EncryptOptions {
            files: vec![],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        });
        assert!(err.is_err());
    }

    #[test]
    fn sanitizes_path_traversal() {
        assert_eq!(super::sanitize_filename("../../../etc/passwd"), "etc/passwd".rsplit('/').next().unwrap());
        assert_eq!(super::sanitize_filename("..\\..\\windows\\system32"), "system32");
        assert_eq!(super::sanitize_filename("/etc/shadow"), "shadow");
        assert_eq!(super::sanitize_filename("normal.txt"), "normal.txt");
        assert_eq!(super::sanitize_filename(".."), "unnamed");
        assert_eq!(super::sanitize_filename(""), "unnamed");
    }

    #[test]
    fn path_traversal_in_encrypt_decrypt() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput {
                name: "../../../etc/passwd".into(),
                data: b"not a password file".to_vec(),
                content_type: None,
            }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert!(!dec.files[0].original_name.contains(".."));
        assert!(!dec.files[0].original_name.contains('/'));
    }

    #[test]
    fn skip_signature_verification() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"data".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        // Decrypt without verify key, skipping verification
        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: None,
            skip_signature_verification: true, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec.files[0].data, b"data");
        assert!(dec.signature_valid.is_none());
    }

    #[test]
    fn decrypt_requires_verify_key_when_signed() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        // Decrypt without verify key and without skip → must fail
        let err = decrypt(&result.container, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: None,
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        });
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("verification key required"));
    }

    #[test]
    fn decrypt_corrupted_container() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        // Corrupt the container
        let mut corrupted = result.container.clone();
        if corrupted.len() > 100 {
            corrupted[50] ^= 0xFF;
            corrupted[100] ^= 0xFF;
        }
        let err = decrypt(&corrupted, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: true, key_unwrap: None, verify_fn: None,
        });
        assert!(err.is_err());
    }

    #[test]
    fn encrypt_decrypt_with_sender_claims() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender {
                signing_key: sender.secret_key,
                kid: "alice".into(),
                x5c: None,
                claims: Some(format::container::SenderClaims {
                    email: Some("alice@example.com".into()),
                    name: Some("Alice".into()),
                    classification: Some("SECRET".into()),
                    ..Default::default()
                }),
            },
            recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "bob".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec.sender_kid, "alice");
        let claims = dec.sender_claims.unwrap();
        assert_eq!(claims.email, Some("alice@example.com".into()));
        assert_eq!(claims.name, Some("Alice".into()));
        assert_eq!(claims.classification, Some("SECRET".into()));
        assert!(dec.created_at.is_some());
    }

    #[test]
    fn decrypt_wrong_recipient_kid() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "bob".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        let err = decrypt(&result.container, DecryptOptions {
            recipient_kid: "eve".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: true, key_unwrap: None, verify_fn: None,
        });
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn verify_detects_wrong_sender_key() {
        let sender = mldsa_keygen();
        let wrong = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "t.txt".into(), data: b"x".to_vec(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        // verify() with wrong key
        let vr = verify(&result.container, VerifyOptions { verify_key: wrong.public_key }).unwrap();
        assert!(!vr.signature_valid);
    }

    #[test]
    fn empty_payload_round_trip() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "empty.bin".into(), data: vec![], content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec.files[0].data, b"");
        assert_eq!(dec.files[0].original_name, "empty.bin");
    }

    #[test]
    fn large_payload_round_trip() {
        let sender = mldsa_keygen();
        let recip = mlkem_keygen();
        let large = vec![0xABu8; 1_000_000]; // 1MB
        let result = encrypt(EncryptOptions {
            files: vec![FileInput { name: "big.bin".into(), data: large.clone(), content_type: None }],
            sender: Sender { signing_key: sender.secret_key, kid: "a".into(), x5c: None, claims: None },
            recipients: vec![Recipient { kid: "b".into(), encryption_key: recip.public_key, recipient_type: None }],
            timestamp: None, key_wrap: None, sign: None,
        }).unwrap();
        let dec = decrypt(&result.container, DecryptOptions {
            recipient_kid: "b".into(),
            decryption_key: recip.secret_key,
            verify_key: Some(sender.public_key),
            skip_signature_verification: false, key_unwrap: None, verify_fn: None,
        }).unwrap();
        assert_eq!(dec.files[0].data.len(), 1_000_000);
        assert_eq!(dec.files[0].data, large);
    }
}
