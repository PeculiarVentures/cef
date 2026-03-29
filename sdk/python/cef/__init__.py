"""CEF: COSE Encrypted Files — post-quantum secure file exchange format.

Usage::

    from cef import encrypt, decrypt, verify
    from cef.pq import mlkem_keygen, mldsa_keygen

    sender = mldsa_keygen()
    recip = mlkem_keygen()

    result = encrypt(
        files=[FileInput("secret.pdf", doc_bytes)],
        sender=Sender(signing_key=sender.secret_key, kid="alice"),
        recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
    )

    dec = decrypt(
        result.container,
        recipient_kid="bob",
        decryption_key=recip.secret_key,
        verify_key=sender.public_key,
    )
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import cose, crypto, pq
from .container import (
    Container, FileMetadata, Manifest, RecipientRef, SenderClaims,
    SenderInfo, marshal_manifest, unmarshal_manifest, random_file_name,
    read_container, sanitize_filename, write_container,
    FORMAT_VERSION, HASH_ALG_SHA256,
)


@dataclass
class FileInput:
    name: str
    data: bytes
    content_type: Optional[str] = None


@dataclass
class Sender:
    signing_key: bytes
    kid: str
    x5c: Optional[list[bytes]] = None
    claims: Optional[SenderClaims] = None


@dataclass
class Recipient:
    kid: str
    encryption_key: bytes
    recipient_type: Optional[str] = None


@dataclass
class EncryptResult:
    container: bytes
    file_count: int
    signed: bool


@dataclass
class DecryptedFile:
    original_name: str
    data: bytes
    size: int


@dataclass
class DecryptResult:
    files: list[DecryptedFile]
    signature_valid: Optional[bool]
    sender_kid: str
    sender_x5c: Optional[list[bytes]] = None
    sender_claims: Optional[SenderClaims] = None
    created_at: Optional[str] = None


@dataclass
class VerifyResult:
    signature_valid: bool
    sender_kid: Optional[str] = None
    timestamp_present: bool = False


def encrypt(
    files: list[FileInput],
    sender: Sender,
    recipients: list[Recipient],
    timestamp: Optional[bytes] = None,
    key_wrap: Optional[callable] = None,
    sign_fn_override: Optional[callable] = None,
) -> EncryptResult:
    if not recipients:
        raise ValueError("cef: at least one recipient is required")
    if not files:
        raise ValueError("cef: at least one file is required")

    if key_wrap:
        wrap_cek = key_wrap
    else:
        pub_keys = {}
        for r in recipients:
            if not r.encryption_key:
                raise ValueError(f'cef: recipient "{r.kid}" has no encryption key')
            pub_keys[r.kid] = r.encryption_key

        def wrap_cek(cek_bytes: bytes, ri: cose.RecipientInfo) -> bytes:
            pk = pub_keys.get(ri.key_id)
            if pk is None:
                raise ValueError(f'cef: no public key for recipient "{ri.key_id}"')
            return pq.mlkem_wrap(pk, cek_bytes)

    if sign_fn_override:
        sign_fn = sign_fn_override
    else:
        def sign_fn(sig_structure: bytes) -> bytes:
            return pq.mldsa_sign(sender.signing_key, sig_structure)

    cose_recipients = [
        cose.RecipientInfo(
            key_id=r.kid,
            algorithm=cose.ALG_MLKEM768_A256KW,
            recipient_type=r.recipient_type,
        )
        for r in recipients
    ]

    # Sender claims
    if sender.x5c:
        sender_claims = None
    else:
        claims = sender.claims or SenderClaims()
        claims.created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sender_claims = claims

    # Encrypt files
    manifest_files = {}
    encrypted_files = {}
    for f in files:
        file_hash = crypto.sha256(f.data)
        enc = cose.encrypt(f.data, cose_recipients, wrap_cek)
        enc_bytes = cose.marshal_encrypt(enc)
        obf = random_file_name()
        manifest_files[obf] = FileMetadata(
            original_name=sanitize_filename(f.name),
            hash=file_hash,
            hash_algorithm=HASH_ALG_SHA256,
            size=len(f.data),
            content_type=f.content_type,
        )
        encrypted_files[obf] = enc_bytes

    manifest = Manifest(
        version=FORMAT_VERSION,
        sender=SenderInfo(kid=sender.kid, x5c=sender.x5c, claims=sender_claims),
        recipients=[
            RecipientRef(kid=r.kid, recipient_type=r.recipient_type or "key")
            for r in recipients
        ],
        files=manifest_files,
    )
    manifest_bytes = marshal_manifest(manifest)
    enc_manifest = cose.encrypt(manifest_bytes, cose_recipients, wrap_cek)
    enc_manifest_bytes = cose.marshal_encrypt(enc_manifest)

    sig = cose.sign1(cose.ALG_MLDSA65, sender.kid, enc_manifest_bytes, True, sign_fn)
    sig_bytes = cose.marshal_sign1(sig)

    container = Container(
        encrypted_manifest=enc_manifest_bytes,
        manifest_signature=sig_bytes,
        timestamp=timestamp,
        encrypted_files=encrypted_files,
    )

    return EncryptResult(
        container=write_container(container),
        file_count=len(files),
        signed=True,
    )


def decrypt(
    container_bytes: bytes,
    recipient_kid: str,
    decryption_key: bytes = b"",
    verify_key: Optional[bytes] = None,
    skip_signature_verification: bool = False,
    key_unwrap: Optional[callable] = None,
    verify_fn_override: Optional[callable] = None,
) -> DecryptResult:
    if not recipient_kid:
        raise ValueError("cef: recipient kid is required")
    if not decryption_key and not key_unwrap:
        raise ValueError("cef: recipient decryption key is required")

    container = read_container(container_bytes)

    # Verify signature
    sig_valid = None
    if container.manifest_signature and not skip_signature_verification:
        if verify_fn_override:
            _verify_fn = verify_fn_override
        elif verify_key:
            _verify_fn = lambda ss, s: pq.mldsa_verify(verify_key, ss, s)
        else:
            raise ValueError(
                "cef: sender verification key required (or set skip_signature_verification)"
            )
        sig1 = cose.unmarshal_sign1(container.manifest_signature)
        try:
            cose.verify1(sig1, container.encrypted_manifest, _verify_fn)
            sig_valid = True
        except Exception as e:
            raise ValueError(f"cef: signature verification failed: {e}") from e

    if not container.encrypted_manifest:
        raise ValueError("cef: no encrypted manifest")

    # Decrypt manifest
    if key_unwrap:
        unwrap = key_unwrap
    else:
        def unwrap(wrapped: bytes, _r: cose.Recipient) -> bytes:
            return pq.mlkem_unwrap(decryption_key, wrapped)

    enc_manifest = cose.unmarshal_encrypt(container.encrypted_manifest)
    idx = cose.find_recipient_index(enc_manifest, recipient_kid)
    manifest_bytes = cose.decrypt(enc_manifest, idx, unwrap)
    manifest = unmarshal_manifest(manifest_bytes)

    # Truncation check
    for name in manifest.files:
        if name not in container.encrypted_files:
            raise ValueError(
                f'cef: container is missing file "{name}" listed in manifest (possible truncation)'
            )

    # Decrypt files
    result_files = []
    for enc_name, meta in manifest.files.items():
        enc_data = container.encrypted_files[enc_name]
        enc_file = cose.unmarshal_encrypt(enc_data)
        fi = cose.find_recipient_index(enc_file, recipient_kid)
        plaintext = cose.decrypt(enc_file, fi, unwrap)

        # Constant-time hash verification
        if meta.hash:
            file_hash = crypto.sha256(plaintext)
            if not crypto.constant_time_compare(file_hash, meta.hash):
                raise ValueError(f'cef: hash mismatch for "{meta.original_name}"')

        result_files.append(DecryptedFile(
            original_name=sanitize_filename(meta.original_name),
            data=plaintext,
            size=meta.size,
        ))

    return DecryptResult(
        files=result_files,
        signature_valid=sig_valid,
        sender_kid=manifest.sender.kid,
        sender_x5c=manifest.sender.x5c,
        sender_claims=manifest.sender.claims,
        created_at=manifest.sender.claims.created_at if manifest.sender.claims else None,
    )


def verify(container_bytes: bytes, verify_key: bytes) -> VerifyResult:
    container = read_container(container_bytes)

    result = VerifyResult(
        signature_valid=False,
        timestamp_present=container.timestamp is not None,
    )

    if container.manifest_signature:
        sig1 = cose.unmarshal_sign1(container.manifest_signature)
        kid_bytes = sig1.unprotected.get(cose.HEADER_KEY_ID)
        if kid_bytes:
            result.sender_kid = kid_bytes.decode("utf-8", errors="replace")

        if container.encrypted_manifest:
            verify_fn = lambda ss, s: pq.mldsa_verify(verify_key, ss, s)
            try:
                cose.verify1(sig1, container.encrypted_manifest, verify_fn)
                result.signature_valid = True
            except Exception:
                pass

    return result
