//! `inspect_plist` (REA `NativeMacOSProvider.#inspectPlist`, `parsers/plist.ts`): normalized JSON
//! of a property list plus the bundle identity fields, decoded in-process instead of by `plutil`.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::bounded_read::{read_bounded, Bounded};
use crate::error::{InputIssue, NativeError};
use crate::macho_tools::native_provenance;
use crate::plistjs::{
    binary_plist_number_literals, decode_xml_plist_text, omitted_prototype_keys_limitation, parse_binary_checked,
    parse_xml_checked, project_plist_value, xml_plist_number_literals, PVal, PlistNumberProjection,
};

const OPERATION: &str = "inspect_plist";
const PROVIDER_ID: &str = "native-macos";
const MAX_PLIST_BYTES: u64 = 64 * 1024 * 1024;

pub struct PlistRequest<'a> {
    /// The caller-selected path (relative to the target root or absolute).
    pub requested: Option<&'a str>,
    /// `target.sourcePath ?? target.path`.
    pub source_path: &'a Path,
    /// `target.path` (the program file for bundles).
    pub target_path: &'a Path,
    /// `target.bundleInfoPlist`.
    pub bundle_info_plist: Option<&'a Path>,
}

pub struct PlistObservation {
    pub result: Value,
    pub limitations: Vec<String>,
    pub source_path: String,
}

/// Node's `path.resolve(...)` on POSIX: join, normalize `.`/`..`, no symlink resolution.
pub fn resolve_path(base: &Path, relative: &str) -> PathBuf {
    let joined = if Path::new(relative).is_absolute() { PathBuf::from(relative) } else { base.join(relative) };
    let mut out = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn unreadable_plist(path: &str, requested: Option<&str>, reason: &str) -> NativeError {
    let sentence = if reason.ends_with('.') { reason.to_string() } else { format!("{reason}.") };
    match requested {
        None => {
            let message = format!(
                "The target has no readable Contents/Info.plist at {path}: {sentence} Select another plist in the target with the path input (CLI: --relative-path)."
            );
            NativeError::Capability {
                provider_id: PROVIDER_ID.to_string(),
                operation: OPERATION.to_string(),
                reason: message,
                user_message: true,
            }
        }
        Some(_) => NativeError::Input {
            operation: OPERATION.to_string(),
            issues: vec![InputIssue::invalid(
                vec![json!("path")],
                format!("Cannot inspect {path}: {sentence}"),
            )],
        },
    }
}

fn resolve_plist_path(request: &PlistRequest<'_>) -> Result<PathBuf, NativeError> {
    if let Some(requested) = request.requested {
        if Path::new(requested).is_absolute() {
            return Ok(resolve_path(Path::new("/"), requested));
        }
    }
    let metadata = std::fs::metadata(request.source_path)
        .map_err(|e| NativeError::Output { operation: OPERATION.to_string(), reason: e.to_string() })?;
    let root = if metadata.is_dir() {
        request.source_path.to_path_buf()
    } else {
        request.target_path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"))
    };
    if let Some(requested) = request.requested {
        return Ok(resolve_path(&root, requested));
    }
    match request.bundle_info_plist {
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(resolve_path(&root, "Contents/Info.plist")),
    }
}

fn read_regular_plist(path: &Path, requested: Option<&str>) -> Result<Vec<u8>, NativeError> {
    let display = path.to_string_lossy().into_owned();
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(match error.kind() {
                std::io::ErrorKind::NotFound => unreadable_plist(&display, requested, "no file exists there"),
                std::io::ErrorKind::PermissionDenied => NativeError::Target {
                    path: display,
                    reason: "permission denied while reading plist (EACCES)".to_string(),
                },
                _ => {
                    if error.raw_os_error() == Some(20) {
                        unreadable_plist(&display, requested, "no file exists there")
                    } else {
                        NativeError::Output { operation: OPERATION.to_string(), reason: error.to_string() }
                    }
                }
            })
        }
    };
    if !metadata.is_file() {
        return Err(unreadable_plist(&display, requested, "it is not a regular file"));
    }
    if metadata.len() > MAX_PLIST_BYTES {
        return Err(NativeError::Resource {
            operation: OPERATION.to_string(),
            resource: "memory".to_string(),
            reason: format!("Property list exceeds {MAX_PLIST_BYTES} bytes."),
            reported_limits: json!({ "max_file_bytes": MAX_PLIST_BYTES }),
        });
    }
    let mut file = File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => NativeError::Target {
            path: display.clone(),
            reason: "permission denied while reading plist (EACCES)".to_string(),
        },
        _ => NativeError::Output { operation: OPERATION.to_string(), reason: error.to_string() },
    })?;
    // The length from metadata is advisory (the file can grow, special files report 0): read at most the limit.
    match read_bounded(&mut file, MAX_PLIST_BYTES)
        .map_err(|error| NativeError::Output { operation: OPERATION.to_string(), reason: error.to_string() })?
    {
        Bounded::Complete(data) => Ok(data),
        Bounded::TooLarge => Err(NativeError::Resource {
            operation: OPERATION.to_string(),
            resource: "memory".to_string(),
            reason: format!("Property list exceeds {MAX_PLIST_BYTES} bytes."),
            reported_limits: json!({ "max_file_bytes": MAX_PLIST_BYTES }),
        }),
    }
}

/// Remove `__proto__` dictionary entries (REA results cannot carry that key); count them.
fn strip_prototype_keys(value: &Value, omitted: &mut usize) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|item| strip_prototype_keys(item, omitted)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                if key == "__proto__" {
                    *omitted += 1;
                    continue;
                }
                out.insert(key.clone(), strip_prototype_keys(item, omitted));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn contains_json_inexpressible(value: &PVal) -> bool {
    match value {
        PVal::Data(_) | PVal::Date(_) => true,
        PVal::Num(number) => !number.is_finite(),
        PVal::Array(items) => items.iter().any(contains_json_inexpressible),
        PVal::Dict(map) => map.values().any(contains_json_inexpressible),
        _ => false,
    }
}

fn project_bundle(value: &Value) -> Value {
    let field = |name: &str| -> Value {
        match value.get(name) {
            Some(Value::String(text)) => Value::String(text.clone()),
            _ => Value::Null,
        }
    };
    json!({
        "identifier": field("CFBundleIdentifier"),
        "executable": field("CFBundleExecutable"),
        "name": field("CFBundleName"),
        "version": field("CFBundleVersion"),
        "short_version": field("CFBundleShortVersionString"),
    })
}

enum Kind {
    Binary,
    Xml,
    Json,
}

fn classify(data: &[u8]) -> Option<Kind> {
    if data.starts_with(b"bplist") {
        return Some(Kind::Binary);
    }
    let text_start: &[u8] = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    let first = text_start.iter().find(|b| !b.is_ascii_whitespace())?;
    match first {
        b'<' => Some(Kind::Xml),
        b'{' | b'[' => Some(Kind::Json),
        _ => {
            // UTF-16 XML starts with a BOM.
            if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
                Some(Kind::Xml)
            } else {
                None
            }
        }
    }
}

pub fn inspect_plist(request: &PlistRequest<'_>) -> Result<PlistObservation, NativeError> {
    let path = resolve_plist_path(request)?;
    let display = path.to_string_lossy().into_owned();
    let data = read_regular_plist(&path, request.requested)?;
    let undecodable = |detail: String| {
        unreadable_plist(
            &display,
            request.requested,
            &format!("it could not be decoded as a property list ({detail})"),
        )
    };
    let Some(kind) = classify(&data) else {
        return Err(undecodable("Unexpected character at line 1".to_string()));
    };
    let (format, value, mut limitations) = match kind {
        Kind::Binary | Kind::Xml => {
            let binary = matches!(kind, Kind::Binary);
            let (parsed, omitted_xml, literals) = if binary {
                let parsed = parse_binary_checked(&data).map_err(|e| undecodable(e.message))?;
                (parsed, 0usize, binary_plist_number_literals(&data))
            } else {
                let text = decode_xml_plist_text(&data).map_err(|e| undecodable(e.message))?;
                let (parsed, omitted) = parse_xml_checked(&text).map_err(|e| undecodable(e.message))?;
                (parsed, omitted, xml_plist_number_literals(&text))
            };
            let inexpressible = contains_json_inexpressible(&parsed);
            let projected = project_plist_value(&parsed).map_err(|e| undecodable(e.message))?;
            let mut numbers = PlistNumberProjection::new(&literals);
            let mapped = numbers.project(&projected.value);
            let mut limitations: Vec<String> = Vec::new();
            if inexpressible {
                limitations.push("This plist contains data, date or non-finite real values that JSON cannot express, so those values are typed objects such as { \"$plist_type\": \"data\", \"base64\": ... }.".to_string());
            }
            if projected.unknown_real_count != 0 {
                limitations.push(format!(
                    "{} non-finite real value(s) are reported as {{ \"$plist_type\": \"real\", \"value\": null }} because the decoder does not distinguish NaN from infinity.",
                    projected.unknown_real_count
                ));
            }
            let exact = numbers.exact_integer_count();
            let ambiguous = numbers.ambiguous_number_count();
            if exact != 0 {
                limitations.push(format!(
                    "{exact} integer value(s) exceed the exact range of a JSON number and are reported as {{ \"$plist_type\": \"integer\", \"decimal\": \"<exact digits>\" }}."
                ));
            }
            if ambiguous != 0 {
                limitations.push(format!(
                    "{ambiguous} number(s) beyond the exact range of a JSON number are reported as decoded because the literal they came from, a rounded <integer> or a <real>, cannot be identified."
                ));
            }
            if omitted_xml != 0 {
                limitations.push(omitted_prototype_keys_limitation(omitted_xml));
            }
            (if binary { "binary" } else { "xml" }, mapped, limitations)
        }
        Kind::Json => {
            let text = String::from_utf8_lossy(data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&data)).into_owned();
            let value: Value = serde_json::from_str(&text).map_err(|e| undecodable(e.to_string()))?;
            ("json", value, Vec::new())
        }
    };
    let mut omitted = 0usize;
    let value = strip_prototype_keys(&value, &mut omitted);
    if omitted != 0 {
        limitations.push(omitted_prototype_keys_limitation(omitted));
    }
    // Prototype keys can be counted twice when an XML plist already reported them; keep one.
    limitations.dedup();
    let bundle = project_bundle(&value);
    let result = json!({
        "format": format,
        "value": value,
        "bundle": bundle,
        "source_path": display,
        "provenance": [native_provenance(OPERATION, "$PLIST")],
        "limitations": limitations,
    });
    Ok(PlistObservation { result, limitations, source_path: display })
}
