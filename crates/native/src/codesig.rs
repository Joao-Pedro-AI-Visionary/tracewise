//! `inspect_signature` (REA `NativeMacOSProvider.#inspectSignature`, `parsers/codesign.ts`):
//! the code-signing identity, hashes, authorities, designated requirement, entitlements and
//! hardened-runtime state of a Mach-O, decoded from its embedded signature instead of from
//! `codesign` output.
//!
//! The embedded signature is parsed by `sigparse` (super blob, code directory, requirements, DER
//! entitlements) and the `cms` / `x509-cert` crates (RustCrypto) for the CMS signature. Certificate
//! trust, revocation and signature validity are not evaluated.

use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::NativeError;
use crate::macho_image::{
    lipo_architecture_name, parse_container, select_slice, slice_bytes, Container, Image,
};
use crate::macho_tools::{native_provenance, read_image_file};
use crate::plistjs::{decode_xml_plist_text, parse_xml_checked, project_plist_value};
use crate::sigparse::{
    self, DigestType, Expr, Match, Value as ReqValue, FLAG_ADHOC, FLAG_RUNTIME, SLOT_ALTERNATE_FIRST,
    SLOT_ALTERNATE_LAST, SLOT_CMS, SLOT_CODE_DIRECTORY, SLOT_ENTITLEMENTS, SLOT_ENTITLEMENTS_DER, SLOT_REQUIREMENTS,
};

const OPERATION: &str = "inspect_signature";
const LC_CODE_SIGNATURE: u32 = 0x1d;

pub struct SignatureObservation {
    pub result: Value,
    pub limitations: Vec<String>,
}

fn output_error(reason: impl Into<String>) -> NativeError {
    NativeError::Output { operation: OPERATION.to_string(), reason: reason.into() }
}

// ---------------------------------------------------------------------------
// Slices and their signatures
// ---------------------------------------------------------------------------

struct SliceSignature<'a> {
    name: Option<String>,
    signature: Option<&'a [u8]>,
}

fn slice_signature<'a>(data: &'a [u8], name: Option<String>) -> Result<SliceSignature<'a>, NativeError> {
    let image = Image::parse(data).map_err(|e| output_error(e.0))?;
    let bytes = image.bytes();
    for command in &image.commands {
        if command.cmd == LC_CODE_SIGNATURE {
            let off = bytes.u32(command.offset + 8).map_err(|e| output_error(e.0))? as usize;
            let size = bytes.u32(command.offset + 12).map_err(|e| output_error(e.0))? as usize;
            if size == 0 {
                return Ok(SliceSignature { name, signature: None });
            }
            let region = data
                .get(off..off.saturating_add(size))
                .ok_or_else(|| output_error("the code signature lies outside its Mach-O slice"))?;
            return Ok(SliceSignature { name, signature: Some(region) });
        }
    }
    Ok(SliceSignature { name, signature: None })
}

// ---------------------------------------------------------------------------
// Requirement text (Apple's `Requirement::Dumper` syntax levels)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum Level {
    Primary = 0,
    And = 1,
    Or = 2,
    Top = 3,
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Bare token for simple alphanumeric text, quoted text otherwise.
fn data_text(text: &str, bare_allowed: bool) -> String {
    let simple = !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if bare_allowed && simple {
        text.to_string()
    } else {
        quote(text)
    }
}

fn value_text(value: &ReqValue, bare_allowed: bool) -> String {
    match value {
        ReqValue::String(text) => data_text(text, bare_allowed),
        ReqValue::Bytes(bytes) => format!("0x{}", hex::encode(bytes)),
    }
}

fn slot_text(slot: i32) -> String {
    match slot {
        0 => "leaf".to_string(),
        -1 => "root".to_string(),
        other => other.to_string(),
    }
}

fn timestamp_text(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0).map(|time| time.to_rfc3339()).unwrap_or_default()
}

fn match_text(expression: &Match) -> String {
    use Match as M;
    match expression {
        M::Exists => " /* exists */".to_string(),
        M::Absent => " absent".to_string(),
        M::Equal(value) => format!(" = {}", value_text(value, true)),
        M::Contains(value) => format!(" ~ {}", value_text(value, false)),
        M::BeginsWith(value) => format!(" = {}*", value_text(value, false)),
        M::EndsWith(value) => format!(" = *{}", value_text(value, false)),
        M::LessThan(value) => format!(" < {}", value_text(value, true)),
        M::GreaterThan(value) => format!(" > {}", value_text(value, true)),
        M::LessThanEqual(value) => format!(" <= {}", value_text(value, true)),
        M::GreaterThanEqual(value) => format!(" >= {}", value_text(value, true)),
        M::On(time) => format!(" = timestamp {}", quote(&timestamp_text(*time))),
        M::Before(time) => format!(" < timestamp {}", quote(&timestamp_text(*time))),
        M::After(time) => format!(" > timestamp {}", quote(&timestamp_text(*time))),
        M::OnOrBefore(time) => format!(" <= timestamp {}", quote(&timestamp_text(*time))),
        M::OnOrAfter(time) => format!(" >= timestamp {}", quote(&timestamp_text(*time))),
    }
}

fn requirement_text(expression: &Expr, level: Level) -> String {
    use Expr as E;
    match expression {
        E::False => "never".to_string(),
        E::True => "always".to_string(),
        E::Identifier(value) => format!("identifier {}", data_text(value, true)),
        E::AnchorApple => "anchor apple".to_string(),
        E::AnchorAppleGeneric => "anchor apple generic".to_string(),
        E::AnchorCertificateHash(slot, digest) => {
            format!("certificate {} = H\"{}\"", slot_text(*slot), hex::encode(digest))
        }
        E::InfoKeyValueLegacy(key, value) => format!("info[{key}] = {}", data_text(value, true)),
        E::And(left, right) => {
            let body = format!("{} and {}", requirement_text(left, Level::And), requirement_text(right, Level::And));
            if level < Level::And {
                format!("({body})")
            } else {
                body
            }
        }
        E::Or(left, right) => {
            let body = format!("{} or {}", requirement_text(left, Level::Or), requirement_text(right, Level::Or));
            if level < Level::Or {
                format!("({body})")
            } else {
                body
            }
        }
        E::CodeDirectoryHash(digest) => format!("cdhash H\"{}\"", hex::encode(digest)),
        E::Not(inner) => format!("! {}", requirement_text(inner, Level::Primary)),
        E::InfoPlistKeyField(key, matching) => format!("info[{}]{}", data_text(key, true), match_text(matching)),
        E::CertificateField(slot, field, matching) => {
            format!("certificate {}[{}]{}", slot_text(*slot), field, match_text(matching))
        }
        E::CertificateTrusted(slot) => format!("certificate {} trusted", slot_text(*slot)),
        E::AnchorTrusted => "anchor trusted".to_string(),
        E::CertificateGeneric(slot, oid, matching) => {
            format!("certificate {}[field.{}]{}", slot_text(*slot), oid, match_text(matching))
        }
        E::EntitlementsKey(key, matching) => format!("entitlement[{}]{}", data_text(key, false), match_text(matching)),
        E::CertificatePolicy(slot, oid, matching) => {
            format!("certificate {}[policy.{}]{}", slot_text(*slot), oid, match_text(matching))
        }
        E::NamedAnchor(name) => format!("anchor apple {name}"),
        E::NamedCode(name) => format!("({name})"),
        E::Platform(platform) => format!("platform = {platform}"),
        E::Notarized => "notarized".to_string(),
        E::CertificateFieldDate(slot, oid, matching) => {
            format!("certificate {}[timestamp.{}]{}", slot_text(*slot), oid, match_text(matching))
        }
        E::LegacyDeveloperId => "legacy".to_string(),
    }
}

// ---------------------------------------------------------------------------
// CMS: authorities and timestamp
// ---------------------------------------------------------------------------

fn format_timestamp(time: chrono::DateTime<chrono::Utc>) -> String {
    time.format("%b %-d, %Y at %H:%M:%S").to_string()
}

struct CmsFacts {
    authorities: Vec<String>,
    timestamp: Option<String>,
    notes: Vec<String>,
}

fn cms_facts(superblob: &sigparse::SuperBlob<'_>) -> CmsFacts {
    let mut facts = CmsFacts { authorities: Vec::new(), timestamp: None, notes: Vec::new() };
    let Some(blob) = superblob.slot(SLOT_CMS) else { return facts };
    match sigparse::parse_cms(blob) {
        Ok(parsed) => {
            facts.authorities = parsed.authorities;
            facts.timestamp = parsed.timestamp.map(format_timestamp);
        }
        Err(error) => facts.notes.push(format!("The CMS signature could not be decoded: {error}.")),
    }
    facts
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn entitlements_value(superblob: &sigparse::SuperBlob<'_>, notes: &mut Vec<String>) -> Option<Value> {
    if let Some(blob) = superblob.slot(SLOT_ENTITLEMENTS) {
        let text = String::from_utf8_lossy(blob.get(8..).unwrap_or_default()).into_owned();
        let start = text.find("<?xml")?;
        let end = text.rfind("</plist>")? + "</plist>".len();
        if end < start {
            return None;
        }
        let decoded = decode_xml_plist_text(&text.as_bytes()[start..end]).ok()?;
        return match parse_xml_checked(&decoded) {
            Ok((value, omitted)) => {
                if omitted != 0 {
                    notes.push(format!("Entitlements: {}", crate::plistjs::omitted_prototype_keys_limitation(omitted)));
                }
                project_plist_value(&value).ok().map(|projected| projected.value)
            }
            Err(error) => {
                notes.push(format!("The entitlements could not be decoded: {}.", error.message));
                None
            }
        };
    }
    let blob = superblob.slot(SLOT_ENTITLEMENTS_DER)?;
    match sigparse::parse_der_entitlements(blob) {
        Ok(value) => project_plist_value(&value).ok().map(|projected| projected.value),
        Err(error) => {
            notes.push(format!("The DER entitlements could not be decoded: {error}."));
            None
        }
    }
}

fn designated_requirement(
    superblob: &sigparse::SuperBlob<'_>,
    adhoc_cdhash: Option<String>,
    notes: &mut Vec<String>,
) -> Option<String> {
    if let Some(blob) = superblob.slot(SLOT_REQUIREMENTS) {
        match sigparse::parse_requirement_set(blob) {
            Ok(set) => {
                if let Some((_, body)) = set.iter().find(|(kind, _)| *kind == DESIGNATED_REQUIREMENT) {
                    return match sigparse::parse_requirement_body(body) {
                        Ok(expressions) => expressions.first().map(|first| requirement_text(first, Level::Top)),
                        Err(error) => {
                            notes.push(format!("The designated requirement could not be decoded: {error}."));
                            None
                        }
                    };
                }
            }
            Err(error) => notes.push(format!("The requirement set could not be decoded: {error}.")),
        }
    }
    // codesign derives `cdhash H"..."` for an ad hoc signature that carries no requirement.
    if let Some(cdhash) = adhoc_cdhash {
        return Some(format!("cdhash H\"{cdhash}\""));
    }
    notes.push("The signature embeds no designated requirement; the implicit requirement derived from the certificate chain is not computed.".to_string());
    None
}

const DESIGNATED_REQUIREMENT: u32 = 3;

pub fn inspect_signature(
    path: &Path,
    expected_sha256: &str,
    requested_architecture: Option<&str>,
    alias: &str,
) -> Result<SignatureObservation, NativeError> {
    let data = read_image_file(path, OPERATION)?;
    let observed = hex::encode(Sha256::digest(&data));
    if observed != expected_sha256 {
        return Err(NativeError::ArtifactChanged {
            operation: OPERATION.to_string(),
            path: path.to_string_lossy().into_owned(),
            reason: format!(
                "Signature target digest changed: {}; expected {expected_sha256}, observed {observed}",
                path.display()
            ),
        });
    }
    let container = parse_container(&data).map_err(|e| output_error(e.0))?;
    let mut slices: Vec<SliceSignature<'_>> = Vec::new();
    let format;
    match &container {
        Container::Thin => {
            let image = Image::parse(&data).map_err(|e| output_error(e.0))?;
            let name = lipo_architecture_name(image.header.cputype, image.header.cpusubtype).map(String::from);
            format = format!("Mach-O thin ({})", name.clone().unwrap_or_else(|| "unknown".to_string()));
            slices.push(slice_signature(&data, name)?);
        }
        Container::Fat { arches, .. } => {
            let mut names = Vec::new();
            for arch in arches {
                let name = lipo_architecture_name(arch.cputype, arch.cpusubtype).map(String::from);
                let end = (arch.offset as usize).saturating_add(arch.size as usize);
                let region = data
                    .get(arch.offset as usize..end)
                    .ok_or_else(|| output_error("a universal slice lies outside the file"))?;
                names.push(name.clone().unwrap_or_else(|| "unknown".to_string()));
                slices.push(slice_signature(region, name)?);
            }
            format = if arches.len() == 1 {
                format!("Mach-O thin ({})", names[0])
            } else {
                format!("Mach-O universal ({})", names.join(" "))
            };
        }
    }
    // The slice the aggregate fields describe.
    let selection = select_slice(
        &data,
        &container,
        match &container {
            Container::Fat { arches, .. } if arches.len() >= 2 => requested_architecture,
            _ => None,
        },
    )
    .map_err(|e| output_error(e.0))?;
    let selected_index = match &container {
        Container::Thin => 0,
        Container::Fat { arches, .. } => arches.iter().position(|a| a.offset == selection.offset).unwrap_or(0),
    };
    let _ = slice_bytes;
    let selected = &slices[selected_index];

    let signed_names: Vec<String> =
        slices.iter().filter(|s| s.signature.is_some()).map(|s| s.name.clone().unwrap_or_default()).collect();
    let unsigned_names: Vec<String> =
        slices.iter().filter(|s| s.signature.is_none()).map(|s| s.name.clone().unwrap_or_default()).collect();

    let Some(signature_bytes) = selected.signature else {
        let mut limitations = vec!["Artifact is not signed.".to_string()];
        if !signed_names.is_empty() {
            limitations.push(format!("Signed Mach-O slices: {}.", signed_names.join(", ")));
        }
        limitations.push(
            "Inspected a digest-verified read of the Mach-O bytes; certificate trust and signature validity are not examined."
                .to_string(),
        );
        let result = json!({
            "signed": false,
            "identifier": null,
            "team_identifier": null,
            "format": null,
            "cdhashes": [],
            "hash_algorithms": [],
            "authorities": [],
            "designated_requirement": null,
            "entitlements": null,
            "timestamp": null,
            "hardened_runtime": null,
            "provenance": [native_provenance(OPERATION, alias)],
            "limitations": limitations,
        });
        return Ok(SignatureObservation { limitations, result });
    };

    let superblob = sigparse::parse_super_blob(signature_bytes).map_err(|error| {
        output_error(format!("{}: invalid or unsupported format for signature ({error})", path.display()))
    })?;
    // Code directories: the primary slot and up to five alternates.
    let mut directories: Vec<(&[u8], sigparse::CodeDirectory)> = Vec::new();
    for slot in std::iter::once(SLOT_CODE_DIRECTORY).chain(SLOT_ALTERNATE_FIRST..=SLOT_ALTERNATE_LAST) {
        if let Some(blob) = superblob.slot(slot) {
            let directory = sigparse::parse_code_directory(blob).map_err(|error| {
                output_error(format!("{}: invalid or unsupported format for signature ({error})", path.display()))
            })?;
            directories.push((blob, directory));
        }
    }
    // Same preference as codesign: SHA-256, then SHA-1, then the primary directory.
    let preferred_index = directories
        .iter()
        .position(|(_, cd)| cd.digest_type == DigestType::SHA256)
        .or_else(|| directories.iter().position(|(_, cd)| cd.digest_type == DigestType::SHA1))
        .or_else(|| directories.iter().position(|_| true))
        .ok_or_else(|| output_error(format!("{}: the signature has no code directory", path.display())))?;
    let (preferred_blob, preferred) = &directories[preferred_index];

    // CDHash: hash of the preferred code directory blob, truncated to 20 bytes.
    let cdhash = preferred
        .digest_type
        .digest(preferred_blob)
        .map(|digest| hex::encode(&digest[..digest.len().min(20)]));

    let mut hash_types: Vec<DigestType> = directories.iter().map(|(_, cd)| cd.digest_type).collect();
    hash_types.sort();
    hash_types.dedup();
    let hash_algorithms: Vec<&'static str> = hash_types.iter().map(|t| t.label()).collect();

    let cms = cms_facts(&superblob);
    let adhoc = preferred.flags & FLAG_ADHOC != 0 || (cms.authorities.is_empty() && superblob.slot(SLOT_CMS).is_none());
    let mut notes: Vec<String> = cms.notes.clone();
    let mixed = !unsigned_names.is_empty();
    let (requirement, entitlements) = if mixed {
        (None, None)
    } else {
        let requirement = designated_requirement(&superblob, if adhoc { cdhash.clone() } else { None }, &mut notes);
        let entitlements = entitlements_value(&superblob, &mut notes);
        (requirement, entitlements)
    };

    let mut limitations: Vec<String> = vec![
        "Signature fields are read from the embedded code signature; certificate trust, revocation and signature validity are not evaluated.".to_string(),
        "Inspected a digest-verified read of the Mach-O bytes.".to_string(),
    ];
    if !cms.authorities.is_empty() {
        limitations.push("Authorities list the certificates embedded in the CMS signature; trust anchors that are not embedded (for example Apple Root CA) are not added.".to_string());
    }
    limitations.extend(notes);
    if mixed {
        limitations.push(format!("Unsigned Mach-O slices: {}.", unsigned_names.join(", ")));
        limitations.push("The aggregate designated requirement is unavailable because Mach-O slices have mixed signing states.".to_string());
        limitations.push("The aggregate entitlements are unavailable because Mach-O slices have mixed signing states.".to_string());
    }

    let result = json!({
        "signed": true,
        "identifier": preferred.identifier,
        "team_identifier": preferred.team,
        "format": format,
        "cdhashes": cdhash.into_iter().collect::<Vec<_>>(),
        "hash_algorithms": hash_algorithms,
        "authorities": cms.authorities,
        "designated_requirement": requirement,
        "entitlements": entitlements,
        "timestamp": cms.timestamp,
        "hardened_runtime": preferred.flags & FLAG_RUNTIME != 0,
        "provenance": [native_provenance(OPERATION, alias)],
        "limitations": limitations,
    });
    Ok(SignatureObservation { result, limitations })
}

#[cfg(test)]
mod requirement_tests {
    use super::*;

    fn body(opcodes: &[u32]) -> Vec<u8> {
        let mut out = 1u32.to_be_bytes().to_vec();
        for opcode in opcodes {
            out.extend_from_slice(&opcode.to_be_bytes());
        }
        out
    }

    fn text(data: &[u8]) -> Result<Option<String>, String> {
        sigparse::parse_requirement_body(data).map(|expressions| expressions.first().map(|e| requirement_text(e, Level::Top)))
    }

    #[test]
    fn the_deepest_allowed_nesting_formats_without_overflowing_the_stack() {
        let mut ok = vec![9u32; sigparse::MAX_NESTING];
        ok.push(1);
        assert_eq!(text(&body(&ok)).unwrap().unwrap().matches('!').count(), sigparse::MAX_NESTING);
    }

    #[test]
    fn a_real_requirement_still_decodes() {
        // identifier "a" and anchor apple
        let mut data = body(&[6, 2]);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(b"a\0\0\0");
        data.extend_from_slice(&3u32.to_be_bytes());
        assert_eq!(text(&data).unwrap().unwrap(), "identifier a and anchor apple");
    }

    #[test]
    fn a_hash_and_a_time_match_format_like_codesign() {
        // certificate leaf[subject.CN] = "x" style: field match with a timestamp.
        let mut data = body(&[22]);
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&3u32.to_be_bytes());
        data.extend_from_slice(&[0x2a, 0x03, 0x04, 0x00]);
        data.extend_from_slice(&9u32.to_be_bytes());
        data.extend_from_slice(&86_400i64.to_be_bytes());
        assert_eq!(text(&data).unwrap().unwrap(), "certificate leaf[timestamp.1.2.3.4] = timestamp \"1970-01-02T00:00:00+00:00\"");
    }
}
