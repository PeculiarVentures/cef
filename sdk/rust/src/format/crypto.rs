//! Shared cryptographic primitives.

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use aes_kw::{KwAes256, cipher::KeyInit as KwKeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::CefError;

pub fn aes_gcm_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CefError> {
    if key.len() != 32 { return Err(CefError::Crypto(format!("AES-256-GCM requires 32-byte key, got {}", key.len()))); }
    if iv.len() != 12 { return Err(CefError::Crypto(format!("AES-GCM requires 12-byte IV, got {}", iv.len()))); }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CefError::Crypto(format!("AES-GCM init: {e}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, Payload { msg: plaintext, aad }).map_err(|e| CefError::Crypto(format!("AES-GCM encrypt: {e}")))
}

pub fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CefError> {
    if key.len() != 32 { return Err(CefError::Crypto(format!("AES-256-GCM requires 32-byte key, got {}", key.len()))); }
    if iv.len() != 12 { return Err(CefError::Crypto(format!("AES-GCM requires 12-byte IV, got {}", iv.len()))); }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CefError::Crypto(format!("AES-GCM init: {e}")))?;
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad }).map_err(|_| CefError::Crypto("AES-GCM: authentication failed".into()))
}

pub fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CefError> {
    if kek.len() != 32 { return Err(CefError::Crypto(format!("AES-KW requires 32-byte KEK, got {}", kek.len()))); }
    let kw = KwAes256::new_from_slice(kek).map_err(|e| CefError::Crypto(format!("AES-KW init: {e}")))?;
    let mut buf = vec![0u8; plaintext.len() + 8];
    let wrapped = kw.wrap_key(plaintext, &mut buf).map_err(|e| CefError::Crypto(format!("AES-KW wrap: {e}")))?;
    Ok(wrapped.to_vec())
}

pub fn aes_key_unwrap(kek: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CefError> {
    if kek.len() != 32 { return Err(CefError::Crypto(format!("AES-KW requires 32-byte KEK, got {}", kek.len()))); }
    let kw = KwAes256::new_from_slice(kek).map_err(|e| CefError::Crypto(format!("AES-KW init: {e}")))?;
    let mut buf = vec![0u8; ciphertext.len() - 8];
    let unwrapped = kw.unwrap_key(ciphertext, &mut buf).map_err(|_| CefError::Crypto("AES-KW: integrity check failed".into()))?;
    Ok(unwrapped.to_vec())
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, CefError> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).map_err(|e| CefError::Crypto(format!("HKDF: {e}")))?;
    Ok(okm)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf
}

pub fn zeroize_bytes(buf: &mut [u8]) { buf.zeroize(); }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aes_gcm_round_trip() {
        let key = random_bytes(32);
        let iv = random_bytes(12);
        let ct = aes_gcm_encrypt(&key, &iv, b"hello", b"aad").unwrap();
        let pt = aes_gcm_decrypt(&key, &iv, &ct, b"aad").unwrap();
        assert_eq!(pt, b"hello");
    }
    #[test]
    fn aes_kw_round_trip() {
        let kek = random_bytes(32);
        let pt = random_bytes(32);
        let w = aes_key_wrap(&kek, &pt).unwrap();
        let u = aes_key_unwrap(&kek, &w).unwrap();
        assert_eq!(u, pt);
    }
    #[test]
    fn hkdf_rfc5869_tc1() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(hex::encode(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }
    #[test]
    fn hkdf_cef_domain_vector() {
        let ss: Vec<u8> = (0..32).collect();
        let kek = hkdf_sha256(&ss, &[], b"CEF-ML-KEM-768-A256KW", 32).unwrap();
        assert_eq!(hex::encode(&kek), "d838a93b048320e5974e7bc3ff9c0c4f9979f0897ffdc88ac749d6010ce488a5");
    }
}
