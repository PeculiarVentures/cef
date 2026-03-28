//! ZIP container and CBOR manifest.

use ciborium::Value;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use crate::error::CefError;
use super::crypto::random_bytes;

pub const PATH_MANIFEST: &str = "META-INF/manifest.cbor.cose";
pub const PATH_SIGNATURE: &str = "META-INF/manifest.cose-sign1";
pub const PATH_TIMESTAMP: &str = "META-INF/manifest.tst";
pub const ENCRYPTED_PREFIX: &str = "encrypted/";
pub const FORMAT_VERSION: &str = "0";
pub const HASH_ALG_SHA256: i64 = -16;

/// Sender claims (unverified, sender-asserted).
#[derive(Debug, Clone, Default)]
pub struct SenderClaims {
    pub email: Option<String>,
    pub name: Option<String>,
    pub created_at: Option<String>,
    pub classification: Option<String>,
    pub sci_controls: Option<Vec<String>>,
    pub sap_programs: Option<Vec<String>>,
    pub dissemination: Option<Vec<String>>,
    pub releasability: Option<String>,
}

/// Sender identity.
#[derive(Debug, Clone)]
pub struct SenderInfo {
    pub kid: String,
    pub x5c: Option<Vec<Vec<u8>>>,
    pub claims: Option<SenderClaims>,
}

/// Recipient reference.
#[derive(Debug, Clone)]
pub struct RecipientRef {
    pub kid: String,
    pub recipient_type: Option<String>,
}

/// File metadata.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub original_name: String,
    pub hash: Vec<u8>,
    pub hash_algorithm: i64,
    pub size: u64,
    pub content_type: Option<String>,
}

/// CEF manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: String,
    pub sender: SenderInfo,
    pub recipients: Vec<RecipientRef>,
    pub files: BTreeMap<String, FileMetadata>,
}

/// CEF container.
pub struct Container {
    pub encrypted_manifest: Option<Vec<u8>>,
    pub manifest_signature: Option<Vec<u8>>,
    pub timestamp: Option<Vec<u8>>,
    pub encrypted_files: BTreeMap<String, Vec<u8>>,
    pub manifest: Option<Manifest>,
}

impl Default for Container {
    fn default() -> Self { Self::new() }
}

impl Container {
    pub fn new() -> Self {
        Container {
            encrypted_manifest: None,
            manifest_signature: None,
            timestamp: None,
            encrypted_files: BTreeMap::new(),
            manifest: None,
        }
    }
}

/// Generate a random obfuscated filename.
pub fn random_file_name() -> String {
    let bytes = random_bytes(16);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}.cose", hex)
}

// ---------------------------------------------------------------------------
// ZIP I/O
// ---------------------------------------------------------------------------

/// Write a container to bytes.
pub fn write_container(container: &Container) -> Result<Vec<u8>, CefError> {
    let buf = Vec::new();
    let cursor = Cursor::new(buf);
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);

    if let Some(ref manifest) = container.encrypted_manifest {
        zip.start_file(PATH_MANIFEST, options)
            .map_err(|e| CefError::Container(format!("write manifest: {e}")))?;
        zip.write_all(manifest)
            .map_err(|e| CefError::Container(format!("write manifest data: {e}")))?;
    }

    if let Some(ref sig) = container.manifest_signature {
        zip.start_file(PATH_SIGNATURE, options)
            .map_err(|e| CefError::Container(format!("write signature: {e}")))?;
        zip.write_all(sig)
            .map_err(|e| CefError::Container(format!("write signature data: {e}")))?;
    }

    if let Some(ref ts) = container.timestamp {
        zip.start_file(PATH_TIMESTAMP, options)
            .map_err(|e| CefError::Container(format!("write timestamp: {e}")))?;
        zip.write_all(ts)
            .map_err(|e| CefError::Container(format!("write timestamp data: {e}")))?;
    }

    for (name, data) in &container.encrypted_files {
        let path = format!("{}{}", ENCRYPTED_PREFIX, name);
        zip.start_file(&path, options)
            .map_err(|e| CefError::Container(format!("write file {name}: {e}")))?;
        zip.write_all(data)
            .map_err(|e| CefError::Container(format!("write file data {name}: {e}")))?;
    }

    let cursor = zip
        .finish()
        .map_err(|e| CefError::Container(format!("finalize ZIP: {e}")))?;
    Ok(cursor.into_inner())
}

/// Read a container from bytes.
pub fn read_container(data: &[u8]) -> Result<Container, CefError> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| CefError::Container(format!("read ZIP: {e}")))?;

    let mut container = Container::new();

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| CefError::Container(format!("read entry {i}: {e}")))?;
        let name = file.name().to_string();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| CefError::Container(format!("read {name}: {e}")))?;

        if name == PATH_MANIFEST {
            container.encrypted_manifest = Some(buf);
        } else if name == PATH_SIGNATURE {
            container.manifest_signature = Some(buf);
        } else if name == PATH_TIMESTAMP {
            container.timestamp = Some(buf);
        } else if let Some(fname) = name.strip_prefix(ENCRYPTED_PREFIX) {
            container.encrypted_files.insert(fname.to_string(), buf);
        }
    }

    Ok(container)
}

// ---------------------------------------------------------------------------
// Manifest CBOR
// ---------------------------------------------------------------------------

fn cbor_encode(value: &Value) -> Result<Vec<u8>, CefError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| CefError::Manifest(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

fn cbor_decode(data: &[u8]) -> Result<Value, CefError> {
    ciborium::from_reader(data)
        .map_err(|e| CefError::Manifest(format!("CBOR decode: {e}")))
}

/// Serialize manifest to CBOR.
pub fn marshal_manifest(manifest: &Manifest) -> Result<Vec<u8>, CefError> {
    let mut obj = Vec::new();

    obj.push((Value::Text("version".into()), Value::Text(manifest.version.clone())));

    // Sender
    let mut sender_map = Vec::new();
    sender_map.push((Value::Text("kid".into()), Value::Text(manifest.sender.kid.clone())));
    if let Some(ref x5c) = manifest.sender.x5c {
        let certs: Vec<Value> = x5c.iter().map(|c| Value::Bytes(c.clone())).collect();
        sender_map.push((Value::Text("x5c".into()), Value::Array(certs)));
    } else if let Some(ref claims) = manifest.sender.claims {
        let mut claims_map = Vec::new();
        if let Some(ref e) = claims.email {
            claims_map.push((Value::Text("email".into()), Value::Text(e.clone())));
        }
        if let Some(ref n) = claims.name {
            claims_map.push((Value::Text("name".into()), Value::Text(n.clone())));
        }
        if let Some(ref c) = claims.created_at {
            claims_map.push((Value::Text("created_at".into()), Value::Text(c.clone())));
        }
        if let Some(ref c) = claims.classification {
            claims_map.push((Value::Text("classification".into()), Value::Text(c.clone())));
        }
        if let Some(ref s) = claims.sci_controls {
            let arr: Vec<Value> = s.iter().map(|v| Value::Text(v.clone())).collect();
            claims_map.push((Value::Text("sci_controls".into()), Value::Array(arr)));
        }
        if let Some(ref s) = claims.sap_programs {
            let arr: Vec<Value> = s.iter().map(|v| Value::Text(v.clone())).collect();
            claims_map.push((Value::Text("sap_programs".into()), Value::Array(arr)));
        }
        if let Some(ref d) = claims.dissemination {
            let arr: Vec<Value> = d.iter().map(|v| Value::Text(v.clone())).collect();
            claims_map.push((Value::Text("dissemination".into()), Value::Array(arr)));
        }
        if let Some(ref r) = claims.releasability {
            claims_map.push((Value::Text("releasability".into()), Value::Text(r.clone())));
        }
        if !claims_map.is_empty() {
            sender_map.push((Value::Text("claims".into()), Value::Map(claims_map)));
        }
    }
    obj.push((Value::Text("sender".into()), Value::Map(sender_map)));

    // Recipients
    let recipients: Vec<Value> = manifest
        .recipients
        .iter()
        .map(|r| {
            let mut rm = vec![(Value::Text("kid".into()), Value::Text(r.kid.clone()))];
            if let Some(ref t) = r.recipient_type {
                rm.push((Value::Text("type".into()), Value::Text(t.clone())));
            }
            Value::Map(rm)
        })
        .collect();
    obj.push((Value::Text("recipients".into()), Value::Array(recipients)));

    // Files
    let files: Vec<(Value, Value)> = manifest
        .files
        .iter()
        .map(|(name, meta)| {
            let mut fm = vec![
                (Value::Text("hash".into()), Value::Bytes(meta.hash.clone())),
                (
                    Value::Text("hash_algorithm".into()),
                    Value::Integer(meta.hash_algorithm.into()),
                ),
                (
                    Value::Text("original_name".into()),
                    Value::Text(meta.original_name.clone()),
                ),
                (
                    Value::Text("size".into()),
                    Value::Integer((meta.size as i64).into()),
                ),
            ];
            if let Some(ref ct) = meta.content_type {
                fm.push((Value::Text("content_type".into()), Value::Text(ct.clone())));
            }
            // Sort keys for deterministic CBOR
            fm.sort_by(|(a, _), (b, _)| {
                let ak = if let Value::Text(s) = a { s.as_str() } else { "" };
                let bk = if let Value::Text(s) = b { s.as_str() } else { "" };
                ak.len().cmp(&bk.len()).then(ak.cmp(bk))
            });
            (Value::Text(name.clone()), Value::Map(fm))
        })
        .collect();
    obj.push((Value::Text("files".into()), Value::Map(files)));

    cbor_encode(&Value::Map(obj))
}

/// Deserialize CBOR to manifest.
pub fn unmarshal_manifest(data: &[u8]) -> Result<Manifest, CefError> {
    let value = cbor_decode(data)?;
    let map = match &value {
        Value::Map(m) => m,
        _ => return Err(CefError::Manifest("manifest must be a CBOR map".into())),
    };

    fn get_text(map: &[(Value, Value)], key: &str) -> Option<String> {
        map.iter().find_map(|(k, v)| {
            if let (Value::Text(kk), Value::Text(vv)) = (k, v) {
                if kk == key { Some(vv.clone()) } else { None }
            } else { None }
        })
    }

    fn get_map<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Vec<(Value, Value)>> {
        map.iter().find_map(|(k, v)| {
            if let (Value::Text(kk), Value::Map(m)) = (k, v) {
                if kk == key { Some(m) } else { None }
            } else { None }
        })
    }

    // Version
    let version = get_text(map, "version")
        .ok_or_else(|| CefError::Manifest("missing version".into()))?;
    if version != FORMAT_VERSION {
        return Err(CefError::Manifest(format!(
            "unsupported version '{}' (expected '{}')",
            version, FORMAT_VERSION
        )));
    }

    // Sender
    let sender_map = get_map(map, "sender")
        .ok_or_else(|| CefError::Manifest("missing sender".into()))?;
    let sender_kid = get_text(sender_map, "kid")
        .ok_or_else(|| CefError::Manifest("sender.kid is required".into()))?;

    let sender_claims = get_map(sender_map, "claims").map(|cm| {
        SenderClaims {
            email: get_text(cm, "email"),
            name: get_text(cm, "name"),
            created_at: get_text(cm, "created_at"),
            classification: get_text(cm, "classification"),
            sci_controls: None, // TODO: parse arrays
            sap_programs: None,
            dissemination: None,
            releasability: get_text(cm, "releasability"),
        }
    });

    let sender = SenderInfo {
        kid: sender_kid,
        x5c: None, // TODO: parse x5c
        claims: sender_claims,
    };

    // Recipients
    let recipients_arr = map.iter().find_map(|(k, v)| {
        if let (Value::Text(kk), Value::Array(a)) = (k, v) {
            if kk == "recipients" { Some(a) } else { None }
        } else { None }
    }).ok_or_else(|| CefError::Manifest("missing recipients".into()))?;

    let mut recipients = Vec::new();
    for r in recipients_arr {
        if let Value::Map(rm) = r {
            let kid = get_text(rm, "kid")
                .ok_or_else(|| CefError::Manifest("recipient.kid is required".into()))?;
            let rtype = get_text(rm, "type");
            recipients.push(RecipientRef { kid, recipient_type: rtype });
        }
    }

    // Files
    let files_map = get_map(map, "files")
        .ok_or_else(|| CefError::Manifest("missing files".into()))?;

    let mut files = BTreeMap::new();
    for (k, v) in files_map {
        let name = match k {
            Value::Text(s) => s.clone(),
            _ => continue,
        };
        let fm = match v {
            Value::Map(m) => m,
            _ => continue,
        };

        let original_name = get_text(fm, "original_name")
            .ok_or_else(|| CefError::Manifest("file.original_name required".into()))?;
        let hash = fm.iter().find_map(|(k, v)| {
            if let (Value::Text(kk), Value::Bytes(b)) = (k, v) {
                if kk == "hash" { Some(b.clone()) } else { None }
            } else { None }
        }).unwrap_or_default();

        let hash_algorithm = fm.iter().find_map(|(k, v)| {
            if let (Value::Text(kk), Value::Integer(i)) = (k, v) {
                if kk == "hash_algorithm" { let n: i128 = i128::from(*i); Some(n as i64) } else { None }
            } else { None }
        }).unwrap_or(HASH_ALG_SHA256);

        let size = fm.iter().find_map(|(k, v)| {
            if let (Value::Text(kk), Value::Integer(i)) = (k, v) {
                if kk == "size" { let n: i128 = i128::from(*i); Some(n as u64) } else { None }
            } else { None }
        }).unwrap_or(0);

        let content_type = get_text(fm, "content_type");

        // Validate hash algorithm
        if hash_algorithm != HASH_ALG_SHA256 {
            return Err(CefError::Manifest(format!(
                "unsupported hash algorithm {} for '{}' (only SHA-256 = {} supported)",
                hash_algorithm, original_name, HASH_ALG_SHA256
            )));
        }

        files.insert(name, FileMetadata {
            original_name,
            hash,
            hash_algorithm,
            size,
            content_type,
        });
    }

    Ok(Manifest {
        version,
        sender,
        recipients,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        let mut files = BTreeMap::new();
        files.insert("abc123.cose".into(), FileMetadata {
            original_name: "test.pdf".into(),
            hash: vec![1, 2, 3],
            hash_algorithm: HASH_ALG_SHA256,
            size: 1024,
            content_type: Some("application/pdf".into()),
        });
        Manifest {
            version: FORMAT_VERSION.into(),
            sender: SenderInfo {
                kid: "alice".into(),
                x5c: None,
                claims: Some(SenderClaims {
                    email: Some("alice@example.com".into()),
                    name: Some("Alice".into()),
                    classification: Some("SECRET".into()),
                    ..Default::default()
                }),
            },
            recipients: vec![RecipientRef { kid: "bob".into(), recipient_type: Some("key".into()) }],
            files,
        }
    }

    #[test]
    fn manifest_cbor_round_trip() {
        let m = sample_manifest();
        let bytes = marshal_manifest(&m).unwrap();
        let m2 = unmarshal_manifest(&bytes).unwrap();
        assert_eq!(m2.version, "0");
        assert_eq!(m2.sender.kid, "alice");
        assert_eq!(m2.sender.claims.as_ref().unwrap().email, Some("alice@example.com".into()));
        assert_eq!(m2.sender.claims.as_ref().unwrap().classification, Some("SECRET".into()));
        assert_eq!(m2.recipients[0].kid, "bob");
        assert_eq!(m2.files.len(), 1);
        let f = m2.files.values().next().unwrap();
        assert_eq!(f.original_name, "test.pdf");
        assert_eq!(f.size, 1024);
    }

    #[test]
    fn manifest_rejects_wrong_version() {
        let m = Manifest {
            version: "99".into(),
            sender: SenderInfo { kid: "a".into(), x5c: None, claims: None },
            recipients: vec![],
            files: BTreeMap::new(),
        };
        let bytes = marshal_manifest(&m).unwrap();
        let err = unmarshal_manifest(&bytes);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("unsupported version"));
    }

    #[test]
    fn zip_container_round_trip() {
        let mut c = Container::new();
        c.encrypted_manifest = Some(b"manifest data".to_vec());
        c.manifest_signature = Some(b"signature data".to_vec());
        c.encrypted_files.insert("file1.cose".into(), b"encrypted file 1".to_vec());
        c.encrypted_files.insert("file2.cose".into(), b"encrypted file 2".to_vec());

        let bytes = write_container(&c).unwrap();
        let c2 = read_container(&bytes).unwrap();
        assert_eq!(c2.encrypted_manifest, Some(b"manifest data".to_vec()));
        assert_eq!(c2.manifest_signature, Some(b"signature data".to_vec()));
        assert_eq!(c2.encrypted_files.len(), 2);
        assert_eq!(c2.encrypted_files["file1.cose"], b"encrypted file 1");
    }

    #[test]
    fn random_file_name_unique() {
        let a = random_file_name();
        let b = random_file_name();
        assert_ne!(a, b);
        assert!(a.ends_with(".cose"));
        assert_eq!(a.len(), 32 + 5); // 32 hex + ".cose"
    }

    #[test]
    fn handling_marks_round_trip() {
        let mut files = BTreeMap::new();
        files.insert("x.cose".into(), FileMetadata {
            original_name: "doc.txt".into(),
            hash: vec![],
            hash_algorithm: HASH_ALG_SHA256,
            size: 0,
            content_type: None,
        });
        let m = Manifest {
            version: FORMAT_VERSION.into(),
            sender: SenderInfo {
                kid: "a".into(),
                x5c: None,
                claims: Some(SenderClaims {
                    classification: Some("TOP SECRET".into()),
                    releasability: Some("REL TO USA, FVEY".into()),
                    ..Default::default()
                }),
            },
            recipients: vec![],
            files,
        };
        let bytes = marshal_manifest(&m).unwrap();
        let m2 = unmarshal_manifest(&bytes).unwrap();
        let c = m2.sender.claims.unwrap();
        assert_eq!(c.classification, Some("TOP SECRET".into()));
        assert_eq!(c.releasability, Some("REL TO USA, FVEY".into()));
    }

    #[test]
    fn container_with_timestamp() {
        let mut c = Container::new();
        c.encrypted_manifest = Some(b"m".to_vec());
        c.timestamp = Some(b"tst data".to_vec());
        let bytes = write_container(&c).unwrap();
        let c2 = read_container(&bytes).unwrap();
        assert_eq!(c2.timestamp, Some(b"tst data".to_vec()));
    }
}
