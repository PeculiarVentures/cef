"""Post-quantum cryptographic primitives.

ML-KEM-768 (FIPS 203) key encapsulation and ML-DSA-65 (FIPS 204) signatures.
"""

from dataclasses import dataclass

from pqcrypto.kem.ml_kem_768 import (
    generate_keypair as _kem_generate,
    encrypt as _kem_encapsulate,
    decrypt as _kem_decapsulate,
)
from pqcrypto.sign.ml_dsa_65 import (
    generate_keypair as _dsa_generate,
    sign as _dsa_sign,
    verify as _dsa_verify,
)

from . import crypto

DOMAIN_LABEL = b"CEF-ML-KEM-768-A256KW"

MLKEM768_PK_SIZE = 1184
MLKEM768_SK_SIZE = 2400
MLKEM768_CT_SIZE = 1088
MLDSA65_PK_SIZE = 1952
MLDSA65_SK_SIZE = 4032
MLDSA65_SIG_SIZE = 3309


@dataclass
class MLKEMKeyPair:
    public_key: bytes
    secret_key: bytes


@dataclass
class MLDSAKeyPair:
    public_key: bytes
    secret_key: bytes


def mlkem_keygen() -> MLKEMKeyPair:
    pk, sk = _kem_generate()
    return MLKEMKeyPair(public_key=pk, secret_key=sk)


def mldsa_keygen() -> MLDSAKeyPair:
    pk, sk = _dsa_generate()
    return MLDSAKeyPair(public_key=pk, secret_key=sk)


def _derive_kek(shared_secret: bytes) -> bytes:
    return crypto.hkdf_sha256(shared_secret, b"", DOMAIN_LABEL, 32)


def mlkem_wrap(public_key: bytes, cek: bytes) -> bytes:
    if len(public_key) != MLKEM768_PK_SIZE:
        raise ValueError(f"ML-KEM-768 public key must be {MLKEM768_PK_SIZE} bytes, got {len(public_key)}")
    ct, ss = _kem_encapsulate(public_key)
    ss_buf = bytearray(ss)
    kek = _derive_kek(bytes(ss_buf))
    kek_buf = bytearray(kek)
    crypto.zeroize(ss_buf)
    wrapped = crypto.aes_kw_wrap(bytes(kek_buf), cek)
    crypto.zeroize(kek_buf)
    return ct + wrapped


def mlkem_unwrap(secret_key: bytes, wrapped_data: bytes) -> bytes:
    if len(secret_key) != MLKEM768_SK_SIZE:
        raise ValueError(f"ML-KEM-768 secret key must be {MLKEM768_SK_SIZE} bytes, got {len(secret_key)}")
    if len(wrapped_data) <= MLKEM768_CT_SIZE:
        raise ValueError(f"wrapped data too short: {len(wrapped_data)} bytes")
    ct = wrapped_data[:MLKEM768_CT_SIZE]
    wrapped_cek = wrapped_data[MLKEM768_CT_SIZE:]
    ss = _kem_decapsulate(secret_key, ct)
    ss_buf = bytearray(ss)
    kek = _derive_kek(bytes(ss_buf))
    kek_buf = bytearray(kek)
    crypto.zeroize(ss_buf)
    cek = crypto.aes_kw_unwrap(bytes(kek_buf), wrapped_cek)
    crypto.zeroize(kek_buf)
    return cek


def mldsa_sign(secret_key: bytes, message: bytes) -> bytes:
    if len(secret_key) != MLDSA65_SK_SIZE:
        raise ValueError(f"ML-DSA-65 secret key must be {MLDSA65_SK_SIZE} bytes, got {len(secret_key)}")
    return _dsa_sign(secret_key, message)


def mldsa_verify(public_key: bytes, message: bytes, signature: bytes) -> None:
    if len(public_key) != MLDSA65_PK_SIZE:
        raise ValueError(f"ML-DSA-65 public key must be {MLDSA65_PK_SIZE} bytes, got {len(public_key)}")
    if len(signature) != MLDSA65_SIG_SIZE:
        raise ValueError(f"ML-DSA-65 signature must be {MLDSA65_SIG_SIZE} bytes, got {len(signature)}")
    result = _dsa_verify(public_key, message, signature)
    if result is False:
        raise ValueError("ML-DSA-65: signature verification failed")
