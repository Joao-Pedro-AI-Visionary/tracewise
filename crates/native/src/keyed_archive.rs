//! `inspect_keyed_archive` (port of REA `domain/apple/keyedArchive.ts` and
//! `artifacts/apple/KeyedArchiveReader.ts`).

use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::dylib::open_nofollow;
use crate::error::{ArtifactReason, InputIssue, NativeError, NativeResult};
use crate::plistjs::{
    binary_plist_number_literals, decode_xml_plist_text, estimate_binary_plist_expansion, is_safe_integer,
    omitted_prototype_keys_limitation, parse_binary, parse_xml_property_list, project_plist_value,
    value_f64, xml_plist_number_literals, Bounds, ExpansionFailure, ExpansionKind, PVal, PlistError,
    PlistNumberProjection,
};

const OPERATION: &str = "inspect_keyed_archive";
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECODE_BYTES: f64 = (8 * MAX_BYTES) as f64;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyedArchiveSelection {
    pub root: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug)]
pub enum KeyedFailure {
    /// `KeyedArchiveKindError`: intact file of another kind.
    Kind { message: String, nib: bool },
    /// Caller selection failure (`AnalysisInputError`).
    Input(InputIssue),
    /// Everything else (`TypeError` / `RangeError`).
    Plist(PlistError),
}

impl From<PlistError> for KeyedFailure {
    fn from(error: PlistError) -> Self {
        KeyedFailure::Plist(error)
    }
}

fn record(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// A UID decodes as a one-key `UID` (binary) or `CF$UID` (XML) dictionary with a numeric value.
fn uid(value: Option<&Value>) -> Option<f64> {
    let object = record(value)?;
    if object.len() != 1 {
        return None;
    }
    let marker = if object.contains_key("UID") {
        object.get("UID")
    } else {
        object.get("CF$UID")
    };
    marker.and_then(|m| if m.is_number() { value_f64(m) } else { None })
}

fn archiver_mismatch(archive: Option<&Map<String, Value>>) -> String {
    let Some(archive) = archive else {
        return "its root is not a dictionary".to_string();
    };
    if !archive.contains_key("$archiver") {
        return "it has no $archiver key".to_string();
    }
    match archive.get("$archiver") {
        Some(Value::String(text)) => format!("its $archiver is {}", serde_json::to_string(text).unwrap_or_default()),
        _ => "its $archiver is not a string".to_string(),
    }
}

fn safe_index(target: f64) -> Option<usize> {
    if is_safe_integer(target) && target >= 0.0 {
        Some(target as usize)
    } else {
        None
    }
}

fn compare_utf16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

struct Link {
    source: Option<usize>,
    path: Vec<Value>,
    target: Option<usize>,
    status: &'static str,
    raw: Value,
}

/// Interpret serialized Foundation references without instantiating archive classes.
pub fn project_keyed_archive(value: &Value, selection: &KeyedArchiveSelection) -> Result<Value, KeyedFailure> {
    let archive = record(Some(value));
    if archive.and_then(|a| a.get("$archiver")) != Some(&Value::String("NSKeyedArchiver".to_string())) {
        return Err(KeyedFailure::Kind {
            message: format!(
                "Selected property list is not an NSKeyedArchiver archive: {}",
                archiver_mismatch(archive)
            ),
            nib: false,
        });
    }
    let archive = archive.expect("checked above");
    let Some(Value::Array(table)) = archive.get("$objects") else {
        return Err(PlistError::type_error("Expected NSKeyedArchiver with an $objects array").into());
    };
    if table.len() > 200_000 {
        return Err(PlistError::range_error("Archive exceeds 200000 object-table entries").into());
    }
    let top = record(archive.get("$top"));
    let Some(top) = top.filter(|t| !t.is_empty()) else {
        return Err(PlistError::type_error("Keyed archive has no $top roots").into());
    };
    if let Some(root) = &selection.root {
        if !top.contains_key(root) {
            return Err(KeyedFailure::Input(InputIssue {
                path: vec![json!("root")],
                reason: "invalid_value".to_string(),
                message: Some(format!(
                    "Archive root does not exist: {root}. Select one of the archive's $top roots or omit root."
                )),
                expected: Some(Value::Array(top.keys().map(|k| json!(k)).collect())),
            }));
        }
    }
    let roots: Value = match &selection.root {
        None => Value::Object(top.clone()),
        Some(root) => {
            let mut selected = Map::new();
            selected.insert(root.clone(), top.get(root).cloned().unwrap_or(Value::Null));
            Value::Object(selected)
        }
    };
    let mut references: Vec<Link> = Vec::new();
    let scan = |source: Option<usize>, initial: &Value, references: &mut Vec<Link>| -> Result<(), PlistError> {
        struct Item<'a> {
            value: &'a Value,
            path: Vec<Value>,
        }
        let mut pending: Vec<Item<'_>> = vec![Item {
            value: initial,
            path: Vec::new(),
        }];
        let mut visited = 0usize;
        while let Some(item) = pending.pop() {
            visited += 1;
            if visited > 200_000 || item.path.len() > 128 {
                return Err(PlistError::range_error(
                    "Archive exceeds 200000 values per object or 128 nesting levels",
                ));
            }
            if let Some(target) = uid(Some(item.value)) {
                let index = safe_index(target);
                references.push(Link {
                    source,
                    path: item.path.clone(),
                    target: index,
                    raw: item.value.clone(),
                    status: match index {
                        None => "malformed",
                        Some(i) if i >= table.len() => "unresolved",
                        Some(0) if table.first() == Some(&Value::String("$null".to_string())) => "nil",
                        Some(_) => "resolved",
                    },
                });
            } else if let Value::Array(children) = item.value {
                for index in (0..children.len()).rev() {
                    let mut path = item.path.clone();
                    path.push(json!(index));
                    pending.push(Item {
                        value: &children[index],
                        path,
                    });
                }
            } else if let Some(fields) = record(Some(item.value)) {
                let mut keys: Vec<&String> = fields.keys().collect();
                keys.sort_by(|a, b| compare_utf16(a, b));
                keys.reverse();
                for key in keys {
                    let mut path = item.path.clone();
                    path.push(json!(key));
                    pending.push(Item {
                        value: &fields[key],
                        path,
                    });
                }
            }
            if references.len() > 200_000 {
                return Err(PlistError::range_error("Archive exceeds 200000 reference edges"));
            }
        }
        Ok(())
    };
    scan(None, &roots, &mut references)?;
    struct ObjectRow {
        id: usize,
        kind: &'static str,
        class_id: Option<usize>,
        class_name: Option<String>,
        status: &'static str,
        value: Value,
    }
    let mut objects: Vec<ObjectRow> = Vec::with_capacity(table.len());
    for (id, value) in table.iter().enumerate() {
        scan(Some(id), value, &mut references)?;
        let fields = record(Some(value));
        let class_uid = uid(fields.and_then(|f| f.get("$class")));
        let class_id = class_uid.and_then(safe_index);
        let descriptor = class_id.and_then(|index| record(table.get(index)));
        let class_name = descriptor
            .and_then(|d| d.get("$classname"))
            .and_then(|n| n.as_str())
            .map(str::to_string);
        let is_nil = id == 0 && value == &Value::String("$null".to_string());
        let kind = if is_nil {
            "nil"
        } else if value.is_array() {
            "array"
        } else if let Some(fields) = fields {
            if fields.get("$classname").map(|c| c.is_string()).unwrap_or(false) {
                "class-descriptor"
            } else if fields.contains_key("$class") {
                "archived-object"
            } else {
                "dictionary"
            }
        } else {
            "scalar"
        };
        let status = if is_nil {
            "nil"
        } else if fields.map(|f| f.contains_key("$class")).unwrap_or(false) {
            if class_name.is_none() {
                "unresolved-class"
            } else {
                "unknown-class"
            }
        } else {
            "observed"
        };
        objects.push(ObjectRow {
            id,
            kind,
            class_id,
            class_name,
            status,
            value: value.clone(),
        });
    }
    let end = objects.len().min(selection.offset.saturating_add(selection.limit));
    let start = selection.offset.min(objects.len());
    let page: Vec<&ObjectRow> = objects[start..end.max(start)].iter().collect();
    let ids: std::collections::HashSet<usize> = page.iter().map(|o| o.id).collect();
    let references_json: Vec<Value> = references
        .iter()
        .filter(|link| link.source.map(|s| ids.contains(&s)).unwrap_or(true))
        .map(|link| {
            json!({
                "source": link.source,
                "path": link.path,
                "target": link.target,
                "status": link.status,
                "raw": link.raw,
            })
        })
        .collect();
    Ok(json!({
        "roots": roots,
        "objects": page.iter().map(|o| json!({
            "id": o.id,
            "kind": o.kind,
            "class_id": o.class_id,
            "class_name": o.class_name,
            "status": o.status,
            "value": o.value,
        })).collect::<Vec<_>>(),
        "references": references_json,
        "total_objects": objects.len(),
        "total_references": references.len(),
        "offset": selection.offset,
        "next_offset": if end < objects.len() { json!(end) } else { Value::Null },
        "truncated": page.len() != objects.len(),
        "limitations": [
            "Archive classes are never instantiated. Class names and serialized fields are observed; class-specific semantics are unknown.",
            "Conditional references serialized as UID 0 cannot be distinguished from ordinary nil references. Missing fields remain absent in the raw serialized value.",
            "Root selection selects the named $top entry; object pagination retains original indices and does not recursively expand references.",
        ],
    }))
}

/// Parse inert plist bytes, preserving data and dates with explicit typed values.
pub fn decode_keyed_archive_bytes(bytes: &[u8], selection: &KeyedArchiveSelection) -> Result<Value, KeyedFailure> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(PlistError::range_error("Keyed archive exceeds 64 MiB").into());
    }
    if bytes.len() >= 10 && &bytes[..10] == b"NIBArchive" {
        return Err(KeyedFailure::Kind {
            message: "Selected file is a compiled NIBArchive, not a Foundation plist archive; decode it with decode_interface_builder".to_string(),
            nib: true,
        });
    }
    let binary = bytes.len() >= 8 && &bytes[..8] == b"bplist00";
    let xml_text = if binary { None } else { Some(decode_xml_plist_text(bytes)?) };
    if binary {
        if let Err(failure) =
            estimate_binary_plist_expansion(bytes, MAX_DECODE_BYTES, "the keyed archive decode budget", Bounds::Decoder)
        {
            return Err(match failure {
                ExpansionFailure::Budget { kind, message } => {
                    if kind == ExpansionKind::Cycle {
                        PlistError::type_error(
                            "binary plist object references form a cycle, which a property list cannot represent",
                        )
                    } else {
                        PlistError::range_error(message)
                    }
                }
                ExpansionFailure::Malformed(message) => PlistError::type_error(message),
            }
            .into());
        }
    }
    let (parsed, omitted_prototype_keys): (PVal, usize) = if binary {
        (parse_binary(bytes)?, 0)
    } else {
        parse_xml_property_list(xml_text.as_deref().unwrap_or(""))?
    };
    let projected = project_plist_value(&parsed)?;
    let graph = project_keyed_archive(&projected.value, selection)?;
    let literals = if binary {
        binary_plist_number_literals(bytes)
    } else {
        xml_plist_number_literals(xml_text.as_deref().unwrap_or(""))
    };
    let mut numbers = PlistNumberProjection::new(&literals);
    let graph_map = graph.as_object().expect("graph is an object");
    let roots = match graph_map.get("roots") {
        Some(Value::Object(roots)) => {
            let mut out = Map::new();
            for (name, value) in roots {
                out.insert(name.clone(), numbers.project(value));
            }
            Value::Object(out)
        }
        _ => json!({}),
    };
    let objects: Vec<Value> = graph_map
        .get("objects")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let mut row = row.as_object().cloned().unwrap_or_default();
                    let projected_value = numbers.project(row.get("value").unwrap_or(&Value::Null));
                    row.insert("value".to_string(), projected_value);
                    Value::Object(row)
                })
                .collect()
        })
        .unwrap_or_default();
    let mut limitations: Vec<Value> = graph_map
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    limitations.extend(numbers.limitations().into_iter().map(Value::String));
    if omitted_prototype_keys != 0 {
        limitations.push(Value::String(omitted_prototype_keys_limitation(omitted_prototype_keys)));
    }
    if projected.unknown_real_count != 0 {
        limitations.push(Value::String(format!(
            "{} non-finite real value(s) are reported as {{ \"$plist_type\": \"real\", \"value\": null }} because JSON evidence cannot preserve NaN vs infinity.",
            projected.unknown_real_count
        )));
    }
    let mut result = Map::new();
    result.insert(
        "archive_format".into(),
        json!(if binary { "binary-plist" } else { "xml-plist" }),
    );
    for (key, value) in graph_map {
        match key.as_str() {
            "roots" => result.insert("roots".into(), roots.clone()),
            "objects" => result.insert("objects".into(), Value::Array(objects.clone())),
            "limitations" => result.insert("limitations".into(), Value::Array(limitations.clone())),
            _ => result.insert(key.clone(), value.clone()),
        };
    }
    Ok(Value::Object(result))
}

fn path_error(reason: &str, message: impl Into<String>) -> NativeError {
    NativeError::Input {
        operation: OPERATION.to_string(),
        issues: vec![InputIssue {
            path: vec![json!("path")],
            reason: reason.to_string(),
            message: Some(message.into()),
            expected: None,
        }],
    }
}

fn remediation(nib: bool) -> String {
    if nib {
        "Decode compiled NIBArchive files with decode_interface_builder on the app bundle.".to_string()
    } else {
        // The server track runs on every host; the macOS-only workflow is unavailable off-darwin.
        if cfg!(target_os = "macos") {
            "Inspect an ordinary property list with inspect_plist; inspect_keyed_archive decodes NSKeyedArchiver archives only.".to_string()
        } else {
            "Select an NSKeyedArchiver archive; inspect_keyed_archive decodes only those.".to_string()
        }
    }
}

pub struct KeyedArchiveRequest<'a> {
    pub bundle_path: &'a Path,
    pub target_sha256: &'a str,
    pub path: String,
    pub root: Option<String>,
    pub offset: usize,
    pub limit: usize,
    /// Remediation text for `property-list` kind failures on hosts where `inspect_plist` is unavailable.
    pub plist_remediation: Option<String>,
}

#[derive(Debug, PartialEq)]
enum EntryKind {
    File(u64),
    Directory,
    Symlink,
}

/// Read exactly one regular, contained bundle entry without following symlinks.
pub fn inspect_bundle_keyed_archive(request: &KeyedArchiveRequest<'_>) -> NativeResult<Value> {
    let selected = &request.path;
    if selected.starts_with('/') || selected.split('/').any(|part| part == ".." || part == "." || part.is_empty()) {
        return Err(path_error(
            "invalid_format",
            if selected == "." {
                "Select a keyed archive path relative to the active app bundle.".to_string()
            } else {
                format!(
                    "Archive path must be a canonical relative bundle path without empty, '.', or '..' segments: {selected}"
                )
            },
        ));
    }
    let root = fs::canonicalize(request.bundle_path).map_err(|_| NativeError::artifact(
        OPERATION,
        ArtifactReason::Io,
        format!("Could not resolve artifact root at {}", request.bundle_path.display()),
    ))?;
    let wanted: String = selected.nfc().collect();
    let mut found: Option<(String, u64)> = None;
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        let mut children: Vec<(String, fs::DirEntry)> = Vec::new();
        let reader = fs::read_dir(&directory).map_err(|e| NativeError::artifact(
            OPERATION,
            ArtifactReason::Io,
            format!("Could not open directory at {} ({})", directory.display(), os_code(&e)),
        ))?;
        for child in reader {
            let child = child.map_err(|e| NativeError::artifact(
                OPERATION,
                ArtifactReason::Io,
                format!("Could not read directory at {} ({})", directory.display(), os_code(&e)),
            ))?;
            let absolute = child.path();
            let relative = absolute
                .strip_prefix(&root)
                .map(|p| {
                    p.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_default();
            children.push((relative, child));
        }
        let mut descend: Vec<std::path::PathBuf> = Vec::new();
        for (relative, child) in children {
            let absolute = child.path();
            let metadata = fs::symlink_metadata(&absolute).map_err(|e| NativeError::artifact(
                OPERATION,
                ArtifactReason::Io,
                format!("Could not inspect entry at {} ({})", absolute.display(), os_code(&e)),
            ))?;
            let kind = if metadata.file_type().is_symlink() {
                EntryKind::Symlink
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else if metadata.is_file() {
                EntryKind::File(metadata.len())
            } else {
                continue;
            };
            let normalized: String = relative.nfc().collect();
            if normalized == wanted {
                match kind {
                    EntryKind::File(size) => {
                        if size > MAX_BYTES {
                            return Err(NativeError::artifact(OPERATION, ArtifactReason::Limit, "Keyed archive exceeds 64 MiB"));
                        }
                        if found.is_some() {
                            return Err(path_error(
                                "invalid_value",
                                format!("Archive path matches multiple Unicode-equivalent bundle entries; selection is ambiguous: {selected}"),
                            ));
                        }
                        found = Some((relative.clone(), size));
                    }
                    EntryKind::Directory => {
                        return Err(path_error(
                            "invalid_value",
                            format!("Archive path selects a directory, not a regular file: {selected}"),
                        ))
                    }
                    EntryKind::Symlink => {
                        return Err(path_error(
                            "invalid_value",
                            format!("Archive path selects a symlink, not a regular file: {selected}"),
                        ))
                    }
                }
            }
            if kind == EntryKind::Directory && wanted.starts_with(&format!("{normalized}/")) {
                descend.push(absolute);
            }
        }
        descend.reverse();
        pending.extend(descend);
    }
    let Some((entry_path, _)) = found else {
        return Err(path_error(
            "invalid_value",
            format!("No regular file exists at {selected} in the active app bundle."),
        ));
    };
    let absolute = root.join(&entry_path);
    let mut file = open_nofollow(&absolute).map_err(|e| NativeError::artifact(
        OPERATION,
        ArtifactReason::Io,
        format!("Could not open entry at {} ({})", absolute.display(), os_code(&e)),
    ))?;
    let mut bytes = Vec::new();
    let mut limited = (&mut file).take(MAX_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::artifact_bare(OPERATION, ArtifactReason::Io))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(NativeError::artifact(OPERATION, ArtifactReason::Limit, "Keyed archive exceeds 64 MiB"));
    }
    let selection = KeyedArchiveSelection {
        root: request.root.clone(),
        offset: request.offset,
        limit: request.limit,
    };
    let decoded = match decode_keyed_archive_bytes(&bytes, &selection) {
        Ok(decoded) => decoded,
        Err(KeyedFailure::Input(issue)) => {
            return Err(NativeError::Input {
                operation: OPERATION.to_string(),
                issues: vec![issue],
            })
        }
        Err(KeyedFailure::Kind { message, nib }) => {
            let path = request.bundle_path.join(&entry_path);
            return Err(NativeError::UnsupportedTarget {
                operation: OPERATION.to_string(),
                path: path.to_string_lossy().into_owned(),
                reason: message,
                remediation: Some(match (&request.plist_remediation, nib) {
                    (Some(text), false) => text.clone(),
                    _ => remediation(nib),
                }),
            });
        }
        Err(KeyedFailure::Plist(error)) => {
            return Err(NativeError::artifact(
                OPERATION,
                if error.range { ArtifactReason::Limit } else { ArtifactReason::Format },
                format!("Cannot decode selected Foundation keyed archive: {}", error.message),
            ))
        }
    };
    let archive_sha256 = hex::encode(Sha256::digest(&bytes));
    let mut result = Map::new();
    result.insert("target_sha256".into(), json!(request.target_sha256));
    result.insert("archive_path".into(), json!(entry_path));
    result.insert("archive_sha256".into(), json!(archive_sha256));
    if let Value::Object(decoded) = decoded {
        for (key, value) in decoded {
            result.insert(key, value);
        }
    }
    Ok(Value::Object(result))
}

fn os_code(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "ENOENT".to_string(),
        std::io::ErrorKind::PermissionDenied => "EACCES".to_string(),
        _ => format!("{:?}", error.raw_os_error()),
    }
}
