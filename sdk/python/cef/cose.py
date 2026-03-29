"""COSE encryption and signing structures.

COSE_Encrypt (RFC 9052 §5.1) and COSE_Sign1 (RFC 9052 §4.2).
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

import cbor2

from . import crypto

ALG_A256GCM = 3
ALG_MLKEM768_A256KW = -70010
ALG_MLDSA65 = -49

HEADER_ALGORITHM = 1
HEADER_KEY_ID = 4
HEADER_IV = 5
HEADER_CEF_RECIPIENT_TYPE = -70001

WrapCEKFunc = Callable[[bytes, "RecipientInfo"], bytes]
UnwrapCEKFunc = Callable[[bytes, "Recipient"], bytes]
SignFunc = Callable[[bytes], bytes]
VerifyFunc = Callable[[bytes, bytes], None]


@dataclass
class RecipientInfo:
    key_id: str
    algorithm: int
    recipient_type: Optional[str] = None


@dataclass
class Recipient:
    protected: dict = field(default_factory=dict)
    protected_bytes: bytes = b""
    unprotected: dict = field(default_factory=dict)
    ciphertext: bytes = b""


@dataclass
class EncryptMessage:
    protected: dict = field(default_factory=dict)
    protected_bytes: bytes = b""
    unprotected: dict = field(default_factory=dict)
    ciphertext: bytes = b""
    recipients: list = field(default_factory=list)


@dataclass
class Sign1Message:
    protected: dict = field(default_factory=dict)
    protected_bytes: bytes = b""
    unprotected: dict = field(default_factory=dict)
    payload: Optional[bytes] = None
    signature: bytes = b""


def _encode_protected(header: dict) -> bytes:
    if not header:
        return b""
    return cbor2.dumps(header)


def _decode_protected(data: bytes) -> dict:
    if not data:
        return {}
    return cbor2.loads(data)


def _build_enc_structure(protected_bytes: bytes, external_aad: bytes = b"") -> bytes:
    return cbor2.dumps(["Encrypt", protected_bytes, external_aad])


def _build_sig_structure(protected_bytes: bytes, external_aad: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected_bytes, external_aad, payload])


def encrypt(plaintext: bytes, recipients: list[RecipientInfo],
            wrap_cek: WrapCEKFunc) -> EncryptMessage:
    if not recipients:
        raise ValueError("cef: at least one recipient is required")

    cek = crypto.random_bytes(32)
    iv = crypto.random_bytes(12)

    protected = {HEADER_ALGORITHM: ALG_A256GCM}
    protected_bytes = _encode_protected(protected)
    unprotected = {HEADER_IV: iv}

    aad = _build_enc_structure(protected_bytes)
    ciphertext = crypto.aes_gcm_encrypt(cek, iv, plaintext, aad)

    cose_recipients = []
    for ri in recipients:
        r_protected = {HEADER_ALGORITHM: ri.algorithm}
        r_protected_bytes = _encode_protected(r_protected)
        r_unprotected = {HEADER_KEY_ID: ri.key_id.encode("utf-8")}
        if ri.recipient_type:
            r_unprotected[HEADER_CEF_RECIPIENT_TYPE] = ri.recipient_type
        wrapped_cek = wrap_cek(cek, ri)
        cose_recipients.append(Recipient(
            protected=r_protected,
            protected_bytes=r_protected_bytes,
            unprotected=r_unprotected,
            ciphertext=wrapped_cek,
        ))

    return EncryptMessage(
        protected=protected,
        protected_bytes=protected_bytes,
        unprotected=unprotected,
        ciphertext=ciphertext,
        recipients=cose_recipients,
    )


def decrypt(msg: EncryptMessage, recipient_index: int,
            unwrap_cek: UnwrapCEKFunc) -> bytes:
    if recipient_index >= len(msg.recipients):
        raise ValueError(f"recipient index {recipient_index} out of range")

    recipient = msg.recipients[recipient_index]
    cek = unwrap_cek(recipient.ciphertext, recipient)

    iv = msg.unprotected.get(HEADER_IV)
    if not iv or len(iv) != 12:
        raise ValueError("missing or invalid IV")

    aad = _build_enc_structure(msg.protected_bytes)
    return crypto.aes_gcm_decrypt(cek, iv, msg.ciphertext, aad)


def find_recipient_index(msg: EncryptMessage, kid: str) -> int:
    kid_bytes = kid.encode("utf-8")
    for i, r in enumerate(msg.recipients):
        if r.unprotected.get(HEADER_KEY_ID) == kid_bytes:
            return i
    raise ValueError(f"cef: recipient '{kid}' not found")


def sign1(algorithm: int, key_id: str, payload: bytes, detached: bool,
          sign_fn: SignFunc) -> Sign1Message:
    protected = {HEADER_ALGORITHM: algorithm}
    protected_bytes = _encode_protected(protected)
    unprotected = {HEADER_KEY_ID: key_id.encode("utf-8")}

    sig_structure = _build_sig_structure(protected_bytes, b"", payload)
    signature = sign_fn(sig_structure)

    return Sign1Message(
        protected=protected,
        protected_bytes=protected_bytes,
        unprotected=unprotected,
        payload=None if detached else payload,
        signature=signature,
    )


def verify1(msg: Sign1Message, external_payload: Optional[bytes],
            verify_fn: VerifyFunc) -> None:
    payload = msg.payload
    if not payload:
        if external_payload is None:
            raise ValueError("no payload for verification (detached)")
        payload = external_payload

    sig_structure = _build_sig_structure(msg.protected_bytes, b"", payload)
    verify_fn(sig_structure, msg.signature)


def marshal_encrypt(msg: EncryptMessage) -> bytes:
    recipients_cbor = []
    for r in msg.recipients:
        recipients_cbor.append([r.protected_bytes, r.unprotected, r.ciphertext])

    inner = [msg.protected_bytes, msg.unprotected, msg.ciphertext, recipients_cbor]
    return cbor2.dumps(cbor2.CBORTag(96, inner))


def unmarshal_encrypt(data: bytes) -> EncryptMessage:
    value = cbor2.loads(data)
    if not isinstance(value, cbor2.CBORTag) or value.tag != 96:
        raise ValueError("expected CBOR tag 96 for COSE_Encrypt")

    arr = value.value
    if len(arr) != 4:
        raise ValueError("COSE_Encrypt must be a 4-element array")

    protected_bytes = arr[0]
    protected = _decode_protected(protected_bytes)
    unprotected = arr[1]
    ciphertext = arr[2]

    recipients = []
    for r in arr[3]:
        r_protected_bytes = r[0]
        r_protected = _decode_protected(r_protected_bytes)
        recipients.append(Recipient(
            protected=r_protected,
            protected_bytes=r_protected_bytes,
            unprotected=r[1],
            ciphertext=r[2],
        ))

    return EncryptMessage(
        protected=protected,
        protected_bytes=protected_bytes,
        unprotected=unprotected,
        ciphertext=ciphertext,
        recipients=recipients,
    )


def marshal_sign1(msg: Sign1Message) -> bytes:
    inner = [msg.protected_bytes, msg.unprotected, msg.payload, msg.signature]
    return cbor2.dumps(cbor2.CBORTag(18, inner))


def unmarshal_sign1(data: bytes) -> Sign1Message:
    value = cbor2.loads(data)
    if not isinstance(value, cbor2.CBORTag) or value.tag != 18:
        raise ValueError("expected CBOR tag 18 for COSE_Sign1")

    arr = value.value
    if len(arr) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")

    protected_bytes = arr[0]
    protected = _decode_protected(protected_bytes)
    payload = arr[2]
    if payload == b"":
        payload = None

    return Sign1Message(
        protected=protected,
        protected_bytes=protected_bytes,
        unprotected=arr[1],
        payload=payload,
        signature=arr[3],
    )
