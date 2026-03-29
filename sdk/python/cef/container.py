"""ZIP container and CBOR manifest."""

import io
import zipfile
from dataclasses import dataclass, field
from typing import Optional

import cbor2

from . import crypto

PATH_MANIFEST = "META-INF/manifest.cbor.cose"
PATH_SIGNATURE = "META-INF/manifest.cose-sign1"
PATH_TIMESTAMP = "META-INF/manifest.tst"
ENCRYPTED_PREFIX = "encrypted/"
FORMAT_VERSION = "0"
HASH_ALG_SHA256 = -16


@dataclass
class SenderClaims:
    email: Optional[str] = None
    name: Optional[str] = None
    created_at: Optional[str] = None
    classification: Optional[str] = None
    sci_controls: Optional[list[str]] = None
    sap_programs: Optional[list[str]] = None
    dissemination: Optional[list[str]] = None
    releasability: Optional[str] = None


@dataclass
class SenderInfo:
    kid: str
    x5c: Optional[list[bytes]] = None
    claims: Optional[SenderClaims] = None


@dataclass
class RecipientRef:
    kid: str
    recipient_type: Optional[str] = None


@dataclass
class FileMetadata:
    original_name: str
    hash: bytes
    hash_algorithm: int
    size: int
    content_type: Optional[str] = None


@dataclass
class Manifest:
    version: str
    sender: SenderInfo
    recipients: list[RecipientRef]
    files: dict[str, FileMetadata]


@dataclass
class Container:
    encrypted_manifest: Optional[bytes] = None
    manifest_signature: Optional[bytes] = None
    timestamp: Optional[bytes] = None
    encrypted_files: dict[str, bytes] = field(default_factory=dict)


def random_file_name() -> str:
    return crypto.random_bytes(16).hex() + ".cose"


def sanitize_filename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if not base or base in (".", ".."):
        return "unnamed"
    return base.replace("..", "_")


def write_container(container: Container) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        if container.encrypted_manifest is not None:
            zf.writestr(PATH_MANIFEST, container.encrypted_manifest)
        if container.manifest_signature is not None:
            zf.writestr(PATH_SIGNATURE, container.manifest_signature)
        if container.timestamp is not None:
            zf.writestr(PATH_TIMESTAMP, container.timestamp)
        for name, data in container.encrypted_files.items():
            zf.writestr(ENCRYPTED_PREFIX + name, data)
    return buf.getvalue()


def read_container(data: bytes) -> Container:
    buf = io.BytesIO(data)
    container = Container()
    with zipfile.ZipFile(buf, "r") as zf:
        for name in zf.namelist():
            content = zf.read(name)
            if name == PATH_MANIFEST:
                container.encrypted_manifest = content
            elif name == PATH_SIGNATURE:
                container.manifest_signature = content
            elif name == PATH_TIMESTAMP:
                container.timestamp = content
            elif name.startswith(ENCRYPTED_PREFIX):
                fname = name[len(ENCRYPTED_PREFIX):]
                container.encrypted_files[fname] = content
    return container


def marshal_manifest(manifest: Manifest) -> bytes:
    obj = {"version": manifest.version}

    sender = {"kid": manifest.sender.kid}
    if manifest.sender.x5c:
        sender["x5c"] = manifest.sender.x5c
    elif manifest.sender.claims:
        claims = {}
        c = manifest.sender.claims
        if c.email: claims["email"] = c.email
        if c.name: claims["name"] = c.name
        if c.created_at: claims["created_at"] = c.created_at
        if c.classification: claims["classification"] = c.classification
        if c.sci_controls: claims["sci_controls"] = c.sci_controls
        if c.sap_programs: claims["sap_programs"] = c.sap_programs
        if c.dissemination: claims["dissemination"] = c.dissemination
        if c.releasability: claims["releasability"] = c.releasability
        if claims:
            sender["claims"] = claims
    obj["sender"] = sender

    obj["recipients"] = []
    for r in manifest.recipients:
        rm = {"kid": r.kid}
        if r.recipient_type:
            rm["type"] = r.recipient_type
        obj["recipients"].append(rm)

    files = {}
    for name, meta in manifest.files.items():
        fm = {
            "hash": meta.hash,
            "hash_algorithm": meta.hash_algorithm,
            "original_name": meta.original_name,
            "size": meta.size,
        }
        if meta.content_type:
            fm["content_type"] = meta.content_type
        files[name] = fm
    obj["files"] = files

    return cbor2.dumps(obj)


def unmarshal_manifest(data: bytes) -> Manifest:
    obj = cbor2.loads(data)

    version = obj.get("version")
    if version != FORMAT_VERSION:
        raise ValueError(f"cef: unsupported version '{version}' (expected '{FORMAT_VERSION}')")

    sender_raw = obj["sender"]
    sender_claims = None
    if "claims" in sender_raw:
        c = sender_raw["claims"]
        sender_claims = SenderClaims(
            email=c.get("email"),
            name=c.get("name"),
            created_at=c.get("created_at"),
            classification=c.get("classification"),
            sci_controls=c.get("sci_controls"),
            sap_programs=c.get("sap_programs"),
            dissemination=c.get("dissemination"),
            releasability=c.get("releasability"),
        )

    sender = SenderInfo(
        kid=sender_raw["kid"],
        x5c=sender_raw.get("x5c"),
        claims=sender_claims,
    )

    recipients = []
    for r in obj.get("recipients", []):
        recipients.append(RecipientRef(kid=r["kid"], recipient_type=r.get("type")))

    files = {}
    for name, fm in obj.get("files", {}).items():
        hash_alg = fm.get("hash_algorithm", HASH_ALG_SHA256)
        if hash_alg != HASH_ALG_SHA256:
            raise ValueError(
                f"cef: unsupported hash algorithm {hash_alg} for '{fm.get('original_name')}'"
            )
        files[name] = FileMetadata(
            original_name=fm["original_name"],
            hash=fm.get("hash", b""),
            hash_algorithm=hash_alg,
            size=fm.get("size", 0),
            content_type=fm.get("content_type"),
        )

    return Manifest(version=version, sender=sender, recipients=recipients, files=files)
