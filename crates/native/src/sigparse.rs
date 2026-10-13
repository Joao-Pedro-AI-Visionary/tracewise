//! Parsers for the structures inside a Mach-O code signature: the embedded-signature super blob,
//! code directories, the requirement language, DER entitlements and the CMS signature.
//!
//! Written for hostile input: every offset and length is checked against the buffer, counts are
//! capped, recursion has an explicit depth limit, and nothing here can panic on arbitrary bytes
//! (the former `apple-codesign` based reader asserted on and indexed past malformed headers).
//!
//! Format sources: Apple's `cs_blobs.h` / `Security/requirement.h` layouts as documented in the
//! open-source `Security` and `xnu` trees, and RFC 5652 (CMS) / RFC 3161 (TSTInfo).

use indexmap::IndexMap;

use crate::plistjs::PVal;

pub const MAX_SIGNATURE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOBS: usize = 64;
const MAX_REQUIREMENT_BYTES: usize = 64 * 1024;
/// Deepest requirement-expression and DER-entitlement nesting decoded.
pub const MAX_NESTING: usize = 64;
const MAX_CMS_BYTES: usize = 4 * 1024 * 1024;

pub const MAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
pub const MAGIC_CODE_DIRECTORY: u32 = 0xfade_0c02;
pub const MAGIC_REQUIREMENT_SET: u32 = 0xfade_0c01;
pub const MAGIC_REQUIREMENT: u32 = 0xfade_0c00;
pub const MAGIC_ENTITLEMENTS: u32 = 0xfade_7171;
pub const MAGIC_ENTITLEMENTS_DER: u32 = 0xfade_7172;
pub const MAGIC_CMS: u32 = 0xfade_0b01;

pub const SLOT_CODE_DIRECTORY: u32 = 0;
pub const SLOT_REQUIREMENTS: u32 = 2;
pub const SLOT_ENTITLEMENTS: u32 = 5;
pub const SLOT_ENTITLEMENTS_DER: u32 = 7;
pub const SLOT_ALTERNATE_FIRST: u32 = 0x1000;
pub const SLOT_ALTERNATE_LAST: u32 = 0x1004;
pub const SLOT_CMS: u32 = 0x1_0000;

pub const FLAG_ADHOC: u32 = 0x2;
pub const FLAG_RUNTIME: u32 = 0x1_0000;

pub type SigResult<T> = Result<T, String>;

fn be32(data: &[u8], at: usize) -> SigResult<u32> {
    let end = at.checked_add(4).filter(|end| *end <= data.len()).ok_or("signature data is truncated")?;
    Ok(u32::from_be_bytes(data[at..end].try_into().expect("four bytes")))
}

// ---------------------------------------------------------------------------
// Super blob
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SuperBlob<'a> {
    /// (slot type, blob bytes including its 8-byte header)
    pub blobs: Vec<(u32, &'a [u8])>,
}

/// Split a blob into its magic and the bytes it declares (header included).
fn blob_at(data: &[u8], offset: usize, limit: usize) -> SigResult<(u32, &[u8])> {
    let magic = be32(data, offset)?;
    let length = be32(data, offset + 4)? as usize;
    let end = offset.checked_add(length).filter(|end| length >= 8 && *end <= limit).ok_or("a blob declares a length outside its container")?;
    Ok((magic, &data[offset..end]))
}

pub fn parse_super_blob(data: &[u8]) -> SigResult<SuperBlob<'_>> {
    if data.len() > MAX_SIGNATURE_BYTES {
        return Err("the code signature is too large".to_string());
    }
    let (magic, whole) = blob_at(data, 0, data.len())?;
    if magic != MAGIC_EMBEDDED_SIGNATURE {
        return Err("bad magic for the embedded signature super blob".to_string());
    }
    let count = be32(whole, 8)? as usize;
    if count > MAX_BLOBS {
        return Err(format!("the super blob declares {count} blobs"));
    }
    let mut blobs = Vec::with_capacity(count);
    for index in 0..count {
        let entry = 12 + index * 8;
        let slot = be32(whole, entry)?;
        let offset = be32(whole, entry + 4)? as usize;
        let (_, blob) = blob_at(whole, offset, whole.len())?;
        blobs.push((slot, blob));
    }
    Ok(SuperBlob { blobs })
}

impl<'a> SuperBlob<'a> {
    pub fn slot(&self, slot: u32) -> Option<&'a [u8]> {
        self.blobs.iter().find(|(candidate, _)| *candidate == slot).map(|(_, blob)| *blob)
    }
}

// ---------------------------------------------------------------------------
// Code directory
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DigestType(pub u8);

impl DigestType {
    pub const SHA1: Self = Self(1);
    pub const SHA256: Self = Self(2);

    pub fn label(self) -> &'static str {
        match self.0 {
            0 => "none",
            1 => "sha1",
            2 | 3 => "sha256",
            4 => "sha384",
            5 => "sha512",
            _ => "unknown",
        }
    }

    /// Digest of `data`, or `None` for a type this reader cannot compute.
    pub fn digest(self, data: &[u8]) -> Option<Vec<u8>> {
        use sha2::Digest;
        match self.0 {
            1 => Some(sha1::Sha1::digest(data).to_vec()),
            2 | 3 => Some(sha2::Sha256::digest(data).to_vec()),
            4 => Some(sha2::Sha384::digest(data).to_vec()),
            5 => Some(sha2::Sha512::digest(data).to_vec()),
            _ => None,
        }
    }
}

pub struct CodeDirectory {
    pub flags: u32,
    pub identifier: String,
    pub team: Option<String>,
    pub digest_type: DigestType,
}

fn c_string(blob: &[u8], offset: usize) -> SigResult<String> {
    let tail = blob.get(offset..).ok_or("a code directory string lies outside its blob")?;
    let end = tail.iter().position(|b| *b == 0).ok_or("a code directory string is not terminated")?;
    std::str::from_utf8(&tail[..end]).map(str::to_string).map_err(|_| "a code directory string is not UTF-8".to_string())
}

pub fn parse_code_directory(blob: &[u8]) -> SigResult<CodeDirectory> {
    let (magic, blob) = blob_at(blob, 0, blob.len())?;
    if magic != MAGIC_CODE_DIRECTORY {
        return Err("bad magic for a code directory blob".to_string());
    }
    let version = be32(blob, 8)?;
    let flags = be32(blob, 12)?;
    let ident_offset = be32(blob, 20)? as usize;
    let digest_type = DigestType(*blob.get(37).ok_or("the code directory header is truncated")?);
    let team = if version >= 0x2_0200 {
        match be32(blob, 48)? as usize {
            0 => None,
            offset => Some(c_string(blob, offset)?),
        }
    } else {
        None
    };
    Ok(CodeDirectory { flags, identifier: c_string(blob, ident_offset)?, team, digest_type })
}

// ---------------------------------------------------------------------------
// Requirements
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Match {
    Exists,
    Absent,
    Equal(Value),
    Contains(Value),
    BeginsWith(Value),
    EndsWith(Value),
    LessThan(Value),
    GreaterThan(Value),
    LessThanEqual(Value),
    GreaterThanEqual(Value),
    On(i64),
    Before(i64),
    After(i64),
    OnOrBefore(i64),
    OnOrAfter(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    False,
    True,
    Identifier(String),
    AnchorApple,
    AnchorCertificateHash(i32, Vec<u8>),
    InfoKeyValueLegacy(String, String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    CodeDirectoryHash(Vec<u8>),
    Not(Box<Expr>),
    InfoPlistKeyField(String, Match),
    CertificateField(i32, String, Match),
    CertificateTrusted(i32),
    AnchorTrusted,
    CertificateGeneric(i32, String, Match),
    AnchorAppleGeneric,
    EntitlementsKey(String, Match),
    CertificatePolicy(i32, String, Match),
    NamedAnchor(String),
    NamedCode(String),
    Platform(u32),
    Notarized,
    CertificateFieldDate(i32, String, Match),
    LegacyDeveloperId,
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> SigResult<u32> {
        let value = be32(self.data, self.at)?;
        self.at += 4;
        Ok(value)
    }

    fn i32(&mut self) -> SigResult<i32> {
        Ok(self.u32()? as i32)
    }

    fn i64(&mut self) -> SigResult<i64> {
        let end = self.at.checked_add(8).filter(|end| *end <= self.data.len()).ok_or("requirement is truncated")?;
        let value = i64::from_be_bytes(self.data[self.at..end].try_into().expect("eight bytes"));
        self.at = end;
        Ok(value)
    }

    fn take(&mut self, count: usize) -> SigResult<&'a [u8]> {
        let end = self.at.checked_add(count).filter(|end| *end <= self.data.len()).ok_or("requirement is truncated")?;
        let slice = &self.data[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// u32 length, bytes, padding to a 4-byte boundary.
    fn data(&mut self) -> SigResult<&'a [u8]> {
        let length = self.u32()? as usize;
        let value = self.take(length)?;
        let padding = (4 - length % 4) % 4;
        self.take(padding)?;
        Ok(value)
    }

    fn string(&mut self, what: &str) -> SigResult<String> {
        std::str::from_utf8(self.data()?).map(str::to_string).map_err(|_| format!("{what} is not UTF-8"))
    }

    fn value(&mut self) -> SigResult<Value> {
        let bytes = self.data()?;
        let printable = bytes.iter().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || c.is_ascii_punctuation());
        Ok(if printable { Value::String(String::from_utf8_lossy(bytes).into_owned()) } else { Value::Bytes(bytes.to_vec()) })
    }

    fn oid(&mut self) -> SigResult<String> {
        Ok(oid_text(self.data()?))
    }

    fn match_expression(&mut self) -> SigResult<Match> {
        Ok(match self.u32()? {
            0 => Match::Exists,
            1 => Match::Equal(self.value()?),
            2 => Match::Contains(self.value()?),
            3 => Match::BeginsWith(self.value()?),
            4 => Match::EndsWith(self.value()?),
            5 => Match::LessThan(self.value()?),
            6 => Match::GreaterThan(self.value()?),
            7 => Match::LessThanEqual(self.value()?),
            8 => Match::GreaterThanEqual(self.value()?),
            9 => Match::On(self.i64()?),
            10 => Match::Before(self.i64()?),
            11 => Match::After(self.i64()?),
            12 => Match::OnOrBefore(self.i64()?),
            13 => Match::OnOrAfter(self.i64()?),
            14 => Match::Absent,
            other => return Err(format!("unknown match type {other}")),
        })
    }

    fn expression(&mut self, depth: usize) -> SigResult<Expr> {
        if depth > MAX_NESTING {
            return Err(format!("requirement nesting exceeds {MAX_NESTING} levels"));
        }
        let opcode = self.u32()? & 0x00ff_ffff;
        Ok(match opcode {
            0 => Expr::False,
            1 => Expr::True,
            2 => Expr::Identifier(self.string("the identifier")?),
            3 => Expr::AnchorApple,
            4 => {
                let slot = self.i32()?;
                let length = self.u32()? as usize;
                Expr::AnchorCertificateHash(slot, self.take(length)?.to_vec())
            }
            5 => Expr::InfoKeyValueLegacy(self.string("the info key")?, self.string("the info value")?),
            6 => Expr::And(Box::new(self.expression(depth + 1)?), Box::new(self.expression(depth + 1)?)),
            7 => Expr::Or(Box::new(self.expression(depth + 1)?), Box::new(self.expression(depth + 1)?)),
            8 => Expr::CodeDirectoryHash(self.data()?.to_vec()),
            9 => Expr::Not(Box::new(self.expression(depth + 1)?)),
            10 => Expr::InfoPlistKeyField(self.string("the info key")?, self.match_expression()?),
            11 => {
                let slot = self.i32()?;
                Expr::CertificateField(slot, self.string("the certificate field")?, self.match_expression()?)
            }
            12 => Expr::CertificateTrusted(self.i32()?),
            13 => Expr::AnchorTrusted,
            14 => {
                let slot = self.i32()?;
                Expr::CertificateGeneric(slot, self.oid()?, self.match_expression()?)
            }
            15 => Expr::AnchorAppleGeneric,
            16 => Expr::EntitlementsKey(self.string("the entitlement key")?, self.match_expression()?),
            17 => {
                let slot = self.i32()?;
                Expr::CertificatePolicy(slot, self.oid()?, self.match_expression()?)
            }
            18 => Expr::NamedAnchor(self.string("the named anchor")?),
            19 => Expr::NamedCode(self.string("the named code")?),
            20 => Expr::Platform(self.u32()?),
            21 => Expr::Notarized,
            22 => {
                let slot = self.i32()?;
                Expr::CertificateFieldDate(slot, self.oid()?, self.match_expression()?)
            }
            23 => Expr::LegacyDeveloperId,
            other => return Err(format!("unknown requirement opcode {other}")),
        })
    }
}

/// Dotted-decimal text of a DER-encoded OBJECT IDENTIFIER body.
pub fn oid_text(bytes: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut value: u64 = 0;
    for (index, byte) in bytes.iter().enumerate() {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if parts.is_empty() {
                let first = (value / 40).min(2);
                parts.push(first.to_string());
                parts.push((value - first * 40).to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        } else if index + 1 == bytes.len() || value > (u64::MAX >> 8) {
            break;
        }
    }
    parts.join(".")
}

/// The expressions of a requirement body (the bytes after the blob header).
pub fn parse_requirement_body(body: &[u8]) -> SigResult<Vec<Expr>> {
    if body.len() > MAX_REQUIREMENT_BYTES {
        return Err(format!("requirement exceeds {MAX_REQUIREMENT_BYTES} bytes"));
    }
    let mut reader = Reader { data: body, at: 0 };
    let count = reader.u32()?;
    if count > 16 {
        return Err(format!("requirement declares {count} expressions"));
    }
    let mut expressions = Vec::new();
    for _ in 0..count {
        expressions.push(reader.expression(0)?);
    }
    Ok(expressions)
}

/// Requirement blobs of a requirement set, by requirement type (3 = designated).
pub fn parse_requirement_set(blob: &[u8]) -> SigResult<Vec<(u32, Vec<u8>)>> {
    let (magic, blob) = blob_at(blob, 0, blob.len())?;
    if magic != MAGIC_REQUIREMENT_SET {
        return Err("bad magic for a requirement set blob".to_string());
    }
    let count = be32(blob, 8)? as usize;
    if count > MAX_BLOBS {
        return Err(format!("the requirement set declares {count} requirements"));
    }
    let mut out = Vec::new();
    for index in 0..count {
        let requirement_type = be32(blob, 12 + index * 8)?;
        let offset = be32(blob, 16 + index * 8)? as usize;
        let (magic, requirement) = blob_at(blob, offset, blob.len())?;
        if magic != MAGIC_REQUIREMENT {
            return Err("bad magic for a requirement blob".to_string());
        }
        out.push((requirement_type, requirement[8..].to_vec()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// DER entitlements
// ---------------------------------------------------------------------------

/// (tag, content start, content end) of the DER element at `at`.
fn der_element(data: &[u8], at: usize, limit: usize) -> Option<(u8, usize, usize)> {
    let tag = *data.get(at)?;
    let first = *data.get(at + 1)?;
    let (start, length) = if first < 0x80 {
        (at + 2, first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for i in 0..count {
            length = (length << 8) | *data.get(at + 2 + i)? as usize;
        }
        (at + 2 + count, length)
    };
    let end = start.checked_add(length)?;
    (end <= limit && end <= data.len()).then_some((tag, start, end))
}

fn der_value(data: &[u8], at: usize, limit: usize, depth: usize) -> SigResult<(PVal, usize)> {
    if depth > MAX_NESTING {
        return Err(format!("DER entitlements nest deeper than {MAX_NESTING} levels"));
    }
    let (tag, start, end) = der_element(data, at, limit).ok_or("malformed DER entitlements")?;
    let value = match tag {
        0x01 => PVal::Bool(data.get(start).copied().unwrap_or(0) != 0),
        0x02 => {
            let bytes = &data[start..end];
            if bytes.is_empty() || bytes.len() > 8 {
                return Err("unsupported DER integer".to_string());
            }
            let mut value: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
            for byte in bytes {
                value = (value << 8) | i64::from(*byte);
            }
            PVal::Num(value as f64)
        }
        0x0c => PVal::Str(std::str::from_utf8(&data[start..end]).map_err(|_| "DER string is not UTF-8")?.to_string()),
        // SEQUENCE: an array of values.
        0x30 => {
            let mut items = Vec::new();
            let mut cursor = start;
            while cursor < end {
                let (item, next) = der_value(data, cursor, end, depth + 1)?;
                items.push(item);
                cursor = next;
            }
            PVal::Array(items)
        }
        // [CONTEXT 16] constructed: a dictionary of SEQUENCE { UTF8String key, value }.
        0xb0 => {
            let mut map: IndexMap<String, PVal> = IndexMap::new();
            let mut cursor = start;
            while cursor < end {
                let (entry_tag, entry_start, entry_end) = der_element(data, cursor, end).ok_or("malformed DER entitlements")?;
                if entry_tag != 0x30 {
                    return Err("a DER entitlement entry is not a SEQUENCE".to_string());
                }
                let (key_tag, key_start, key_end) = der_element(data, entry_start, entry_end).ok_or("malformed DER entitlements")?;
                if key_tag != 0x0c {
                    return Err("a DER entitlement key is not a string".to_string());
                }
                let key = std::str::from_utf8(&data[key_start..key_end]).map_err(|_| "DER key is not UTF-8")?.to_string();
                let (item, _) = der_value(data, key_end, entry_end, depth + 1)?;
                map.insert(key, item);
                cursor = entry_end;
            }
            PVal::Dict(map)
        }
        other => return Err(format!("unsupported DER entitlement tag 0x{other:02x}")),
    };
    Ok((value, end))
}

/// The entitlements dictionary of a DER entitlements blob.
pub fn parse_der_entitlements(blob: &[u8]) -> SigResult<PVal> {
    let (magic, blob) = blob_at(blob, 0, blob.len())?;
    if magic != MAGIC_ENTITLEMENTS_DER {
        return Err("bad magic for a DER entitlements blob".to_string());
    }
    let body = &blob[8..];
    // [APPLICATION 16] constructed: INTEGER version, then the dictionary.
    let (tag, start, end) = der_element(body, 0, body.len()).ok_or("malformed DER entitlements")?;
    if tag != 0x70 {
        return Err("DER entitlements do not start with the application tag".to_string());
    }
    let (version_tag, _, version_end) = der_element(body, start, end).ok_or("malformed DER entitlements")?;
    if version_tag != 0x02 {
        return Err("DER entitlements lack a version".to_string());
    }
    Ok(der_value(body, version_end, end, 0)?.0)
}

// ---------------------------------------------------------------------------
// CMS signature
// ---------------------------------------------------------------------------

pub struct CmsFacts {
    /// Common names of the signer certificate and its embedded issuers, leaf first.
    pub authorities: Vec<String>,
    /// `genTime` of the RFC 3161 token in the signer's unsigned attributes.
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

fn name_common_name(name: &x509_cert::name::Name) -> Option<String> {
    use der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    for rdn in name.0.iter() {
        for attribute in rdn.0.iter() {
            if attribute.oid.to_string() == OID_COMMON_NAME {
                let value = &attribute.value;
                if let Ok(text) = value.decode_as::<Utf8StringRef<'_>>() {
                    return Some(text.as_str().to_string());
                }
                if let Ok(text) = value.decode_as::<PrintableStringRef<'_>>() {
                    return Some(text.as_str().to_string());
                }
                if let Ok(text) = value.decode_as::<Ia5StringRef<'_>>() {
                    return Some(text.as_str().to_string());
                }
                if let Ok(text) = value.decode_as::<TeletexStringRef<'_>>() {
                    return Some(text.as_str().to_string());
                }
            }
        }
    }
    None
}

/// `genTime` of an RFC 3161 `TSTInfo`.
fn tst_info_gen_time(tst_info: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let (tag, start, end) = der_element(tst_info, 0, tst_info.len())?;
    if tag != 0x30 {
        return None;
    }
    let mut at = start;
    let mut index = 0;
    while at < end && index < 6 {
        let (item_tag, item_start, item_end) = der_element(tst_info, at, end)?;
        if item_tag == 0x18 {
            let text = std::str::from_utf8(tst_info.get(item_start..item_end)?).ok()?;
            let trimmed = text.trim_end_matches('Z');
            let seconds = trimmed.split_once('.').map_or(trimmed, |(whole, _)| whole);
            let parsed = chrono::NaiveDateTime::parse_from_str(seconds, "%Y%m%d%H%M%S").ok()?;
            return Some(chrono::DateTime::from_naive_utc_and_offset(parsed, chrono::Utc));
        }
        at = item_end;
        index += 1;
    }
    None
}

fn signed_data(content: &[u8]) -> SigResult<cms::signed_data::SignedData> {
    use der::Decode;
    let info = cms::content_info::ContentInfo::from_der(content).map_err(|e| format!("not a CMS ContentInfo ({e})"))?;
    info.content.decode_as::<cms::signed_data::SignedData>().map_err(|e| format!("not CMS SignedData ({e})"))
}

pub fn parse_cms(blob: &[u8]) -> SigResult<CmsFacts> {
    use der::Encode;
    let (magic, blob) = blob_at(blob, 0, blob.len())?;
    if magic != MAGIC_CMS {
        return Err("bad magic for a CMS signature blob".to_string());
    }
    if blob.len() > MAX_CMS_BYTES {
        return Err("the CMS signature is too large".to_string());
    }
    let signed = signed_data(&blob[8..])?;
    let certificates: Vec<&x509_cert::Certificate> = signed
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|choice| match choice {
                    cms::cert::CertificateChoices::Certificate(certificate) => Some(certificate),
                    _ => None,
                })
                .take(64)
                .collect()
        })
        .unwrap_or_default();
    let mut facts = CmsFacts { authorities: Vec::new(), timestamp: None };
    let Some(signer) = signed.signer_infos.0.iter().next() else {
        return Ok(facts);
    };
    if let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(id) = &signer.sid {
        let leaf = certificates
            .iter()
            .copied()
            .find(|certificate| certificate.tbs_certificate.issuer == id.issuer && certificate.tbs_certificate.serial_number == id.serial_number);
        let mut current = leaf;
        let mut guard = 0;
        while let Some(certificate) = current {
            facts
                .authorities
                .push(name_common_name(&certificate.tbs_certificate.subject).unwrap_or_else(|| "(certificate without a common name)".to_string()));
            guard += 1;
            if certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer || guard > 16 {
                break;
            }
            current = certificates.iter().copied().find(|candidate| {
                candidate.tbs_certificate.subject == certificate.tbs_certificate.issuer && !std::ptr::eq(*candidate, certificate)
            });
        }
    }
    if let Some(attributes) = &signer.unsigned_attrs {
        for attribute in attributes.iter() {
            if attribute.oid.to_string() != OID_TIME_STAMP_TOKEN {
                continue;
            }
            let Some(token) = attribute.values.iter().next() else { continue };
            let der_bytes = token.to_der().map_err(|e| format!("timestamp token ({e})"))?;
            let timestamp = signed_data(&der_bytes)?;
            if let Some(content) = &timestamp.encap_content_info.econtent {
                if let Ok(octets) = content.decode_as::<der::asn1::OctetStringRef<'_>>() {
                    facts.timestamp = tst_info_gen_time(octets.as_bytes());
                }
            }
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(opcodes: &[u32]) -> Vec<u8> {
        let mut out = 1u32.to_be_bytes().to_vec();
        for opcode in opcodes {
            out.extend_from_slice(&opcode.to_be_bytes());
        }
        out
    }

    #[test]
    fn a_million_nested_not_opcodes_are_refused_by_size_before_any_recursion() {
        let mut opcodes = vec![9u32; 1_000_000];
        opcodes.push(1);
        let error = parse_requirement_body(&requirement(&opcodes)).unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn nesting_beyond_the_limit_is_refused_and_the_limit_itself_parses() {
        let mut ok = vec![9u32; MAX_NESTING];
        ok.push(1);
        assert!(parse_requirement_body(&requirement(&ok)).is_ok());
        let mut too_deep = vec![9u32; MAX_NESTING + 1];
        too_deep.push(1);
        assert!(parse_requirement_body(&requirement(&too_deep)).unwrap_err().contains("nesting"));
    }

    #[test]
    fn lengths_pointing_past_the_buffer_are_errors() {
        let mut data = requirement(&[4]);
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_requirement_body(&data).unwrap_err().contains("truncated"));
        let mut data = requirement(&[2]);
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_requirement_body(&data).is_err());
        assert!(parse_requirement_body(&u32::MAX.to_be_bytes()).unwrap_err().contains("declares"));
    }

    #[test]
    fn a_super_blob_cannot_declare_what_it_does_not_hold() {
        // Magic, length 12, count 4 billion.
        let mut data = MAGIC_EMBEDDED_SIGNATURE.to_be_bytes().to_vec();
        data.extend_from_slice(&12u32.to_be_bytes());
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_super_blob(&data).unwrap_err().contains("declares"));
        // One index entry pointing far outside the blob.
        let mut data = MAGIC_EMBEDDED_SIGNATURE.to_be_bytes().to_vec();
        data.extend_from_slice(&20u32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
        assert!(parse_super_blob(&data).is_err());
    }

    #[test]
    fn code_directory_with_offsets_outside_the_blob_is_an_error_not_a_panic() {
        let mut blob = MAGIC_CODE_DIRECTORY.to_be_bytes().to_vec();
        blob.extend_from_slice(&64u32.to_be_bytes());
        blob.extend_from_slice(&0x2_0400u32.to_be_bytes());
        blob.resize(64, 0);
        blob[20..24].copy_from_slice(&0x7000_0000u32.to_be_bytes());
        assert!(parse_code_directory(&blob).is_err());
        assert!(parse_code_directory(&blob[..10]).is_err());
    }

    #[test]
    fn der_entitlements_deeper_than_the_limit_are_refused() {
        // 200 nested SEQUENCEs (long-form lengths, so the nesting is not capped by the size).
        let mut deep = vec![0x01, 0x01, 0xff];
        for _ in 0..200 {
            let mut wrapped = vec![0x30, 0x82];
            wrapped.extend_from_slice(&(deep.len() as u16).to_be_bytes());
            wrapped.extend_from_slice(&deep);
            deep = wrapped;
        }
        assert!(der_value(&deep, 0, deep.len(), 0).unwrap_err().contains("nest deeper"));
    }

    #[test]
    fn oid_text_matches_known_oids() {
        // 2.5.4.3 (commonName) and 1.2.840.113635.100.6.2.6
        assert_eq!(oid_text(&[0x55, 0x04, 0x03]), "2.5.4.3");
        assert_eq!(oid_text(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x06]), "1.2.840.113635.100.6.2.6");
    }
}
