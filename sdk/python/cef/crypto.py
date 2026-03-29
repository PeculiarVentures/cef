"""Shared cryptographic primitives.

AES-256-GCM, AES Key Wrap (RFC 3394), HKDF-SHA256 (RFC 5869), SHA-256.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM requires 32-byte key, got {len(key)}")
    if len(iv) != 12:
        raise ValueError(f"AES-GCM requires 12-byte IV, got {len(iv)}")
    return AESGCM(key).encrypt(iv, plaintext, aad)


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM requires 32-byte key, got {len(key)}")
    if len(iv) != 12:
        raise ValueError(f"AES-GCM requires 12-byte IV, got {len(iv)}")
    return AESGCM(key).decrypt(iv, ciphertext, aad)


def aes_kw_wrap(kek: bytes, plaintext: bytes) -> bytes:
    if len(kek) != 32:
        raise ValueError(f"AES-KW requires 32-byte KEK, got {len(kek)}")
    return aes_key_wrap(kek, plaintext)


def aes_kw_unwrap(kek: bytes, ciphertext: bytes) -> bytes:
    if len(kek) != 32:
        raise ValueError(f"AES-KW requires 32-byte KEK, got {len(kek)}")
    return aes_key_unwrap(kek, ciphertext)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    ).derive(ikm)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
