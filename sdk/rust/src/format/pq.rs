//! Post-quantum cryptographic primitives.

use ml_kem::MlKem768;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::kem::{Encapsulate, Decapsulate, KeyExport};
use ml_dsa::MlDsa65;
use ml_dsa::signature::{Signer, Verifier, Keypair as _};
use zeroize::Zeroize;

use crate::error::CefError;
use super::crypto::{aes_key_wrap, aes_key_unwrap, hkdf_sha256, zeroize_bytes};

const DOMAIN_LABEL: &[u8] = b"CEF-ML-KEM-768-A256KW";

pub struct MLKEMKeyPair { pub public_key: Vec<u8>, pub secret_key: Vec<u8> }
pub struct MLDSAKeyPair { pub public_key: Vec<u8>, pub secret_key: Vec<u8> }

pub fn mlkem_keygen() -> MLKEMKeyPair {
    use rand::Rng;
    let mut seed = [0u8; 64];
    rand::rng().fill(&mut seed);
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(seed));
    let ek = dk.encapsulation_key().clone();
    MLKEMKeyPair {
        public_key: ek.to_bytes().to_vec(),
        secret_key: seed.to_vec(),
    }
}

pub fn mldsa_keygen() -> MLDSAKeyPair {
    use getrandom::SysRng;
    use rand_core::UnwrapErr;
    let sk: ml_dsa::SigningKey<MlDsa65> = <MlDsa65 as ml_dsa::KeyGen>::key_gen(&mut UnwrapErr(SysRng));
    let vk = sk.verifying_key().clone();
    let seed = sk.to_seed();
    MLDSAKeyPair {
        public_key: vk.encode().to_vec(),
        secret_key: seed.to_vec(),
    }
}

fn derive_kek(ss: &[u8]) -> Result<Vec<u8>, CefError> {
    hkdf_sha256(ss, &[], DOMAIN_LABEL, 32)
}

pub fn mlkem_wrap(public_key: &[u8], cek: &[u8]) -> Result<Vec<u8>, CefError> {
    if public_key.len() != 1184 {
        return Err(CefError::Crypto(format!("ML-KEM pk: {} bytes, need 1184", public_key.len())));
    }
    let ek_arr: &ml_kem::array::Array<u8, _> = public_key.try_into()
        .map_err(|_| CefError::Crypto("invalid ML-KEM pk".into()))?;
    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(ek_arr)
        .map_err(|e| CefError::Crypto(format!("ML-KEM pk: {e}")))?;

    let (ct, mut ss) = ek.encapsulate_with_rng(&mut rand_core::UnwrapErr(getrandom::SysRng));
    let mut kek = derive_kek(ss.as_ref())?;
    ss.zeroize();
    let wrapped = aes_key_wrap(&kek, cek)?;
    zeroize_bytes(&mut kek);
    let ct_ref: &[u8] = ct.as_ref();
    let mut out = Vec::with_capacity(ct_ref.len() + wrapped.len());
    out.extend_from_slice(ct_ref);
    out.extend_from_slice(&wrapped);
    Ok(out)
}

pub fn mlkem_unwrap(secret_key: &[u8], wrapped_data: &[u8]) -> Result<Vec<u8>, CefError> {
    // Accept both 64-byte seed and 2400-byte expanded key (interop with Go/TS)
    let dk = match secret_key.len() {
        64 => {
            let seed: [u8; 64] = secret_key.try_into().unwrap();
            ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(seed))
        }
        2400 => {
            #[allow(deprecated)]
            let dk_arr: &ml_kem::ExpandedDecapsulationKey<MlKem768> = secret_key.try_into()
                .map_err(|_| CefError::Crypto("invalid 2400-byte ML-KEM key".into()))?;
            #[allow(deprecated)]
            ml_kem::DecapsulationKey::<MlKem768>::from_expanded_bytes(dk_arr)
                .map_err(|e| CefError::Crypto(format!("ML-KEM expanded key: {e}")))?
        }
        n => return Err(CefError::Crypto(format!("ML-KEM sk: {} bytes, need 64 or 2400", n))),
    };
    let ct_size = 1088usize;
    if wrapped_data.len() <= ct_size {
        return Err(CefError::Crypto(format!("wrapped data too short: {}", wrapped_data.len())));
    }
    let ct: &ml_kem::Ciphertext<MlKem768> = wrapped_data[..ct_size].try_into()
        .map_err(|_| CefError::Crypto("invalid ciphertext".into()))?;
    let wrapped_cek = &wrapped_data[ct_size..];
    let mut ss = dk.decapsulate(ct);
    let mut kek = derive_kek(ss.as_ref())?;
    ss.zeroize();
    let cek = aes_key_unwrap(&kek, wrapped_cek)?;
    zeroize_bytes(&mut kek);
    Ok(cek)
}

pub fn mldsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CefError> {
    if secret_key.len() != 32 {
        return Err(CefError::Crypto(format!("ML-DSA seed: {} bytes, need 32", secret_key.len())));
    }
    let seed: [u8; 32] = secret_key.try_into().unwrap();
    let sk = <MlDsa65 as ml_dsa::KeyGen>::from_seed(&ml_dsa::Seed::from(seed));
    let sig = sk.sign(message);
    Ok(sig.encode().to_vec())
}

pub fn mldsa_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CefError> {
    if public_key.len() != 1952 {
        return Err(CefError::Crypto(format!("ML-DSA pk: {} bytes, need 1952", public_key.len())));
    }
    if signature.len() != 3309 {
        return Err(CefError::Crypto(format!("ML-DSA sig: {} bytes, need 3309", signature.len())));
    }
    let vk_bytes: [u8; 1952] = public_key.try_into().unwrap();
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(
        &ml_dsa::EncodedVerifyingKey::<MlDsa65>::from(vk_bytes)
    );
    let sig_bytes: [u8; 3309] = signature.try_into().unwrap();
    let sig = ml_dsa::Signature::<MlDsa65>::decode(
        &ml_dsa::EncodedSignature::<MlDsa65>::from(sig_bytes)
    ).ok_or_else(|| CefError::Crypto("invalid ML-DSA signature".into()))?;
    vk.verify(message, &sig)
        .map_err(|_| CefError::Crypto("ML-DSA: verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn mlkem_round_trip() {
        let kp = mlkem_keygen();
        let cek = crate::format::crypto::random_bytes(32);
        let w = mlkem_wrap(&kp.public_key, &cek).unwrap();
        assert_eq!(mlkem_unwrap(&kp.secret_key, &w).unwrap(), cek);
    }
    #[test] fn mldsa_sign_verify() {
        let kp = mldsa_keygen();
        let sig = mldsa_sign(&kp.secret_key, b"test").unwrap();
        mldsa_verify(&kp.public_key, b"test", &sig).unwrap();
    }
    #[test] fn mldsa_wrong_key() {
        let k1 = mldsa_keygen(); let k2 = mldsa_keygen();
        let sig = mldsa_sign(&k1.secret_key, b"x").unwrap();
        assert!(mldsa_verify(&k2.public_key, b"x", &sig).is_err());
    }
    #[test] fn mlkem_wrong_key() {
        let k1 = mlkem_keygen(); let k2 = mlkem_keygen();
        let cek = crate::format::crypto::random_bytes(32);
        let w = mlkem_wrap(&k1.public_key, &cek).unwrap();
        assert!(mlkem_unwrap(&k2.secret_key, &w).is_err());
    }

    #[test]
    fn mlkem_expanded_key_unwrap() {
        use rand::Rng;
        let mut seed = [0u8; 64];
        rand::rng().fill(&mut seed);
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(seed));
        let ek = dk.encapsulation_key().clone();
        #[allow(deprecated)]
        let expanded = dk.to_expanded_bytes();

        let pk = ek.to_bytes().to_vec();
        let sk_expanded = expanded.to_vec();
        assert_eq!(sk_expanded.len(), 2400);

        let cek = crate::format::crypto::random_bytes(32);
        let wrapped = mlkem_wrap(&pk, &cek).unwrap();
        let unwrapped = mlkem_unwrap(&sk_expanded, &wrapped).unwrap();
        assert_eq!(unwrapped, cek);
    }
}
