//! Artifact-confined path resolution without filesystem access (REA
//! `JavaScriptArtifactPathResolution.ts`).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use super::model::ArtifactFile;
use super::posix::{
    admits_canonical_path_syntax, decode_uri_component, dirname, has_scheme, html_url_text, join,
    logical_path_escapes_root, looks_external, normalize_joined_logical_path,
    percent_decode_url_path, strip_query_and_fragment,
};

/// Files of one application by artifact path.
pub struct Files<'a> {
    map: HashMap<&'a str, &'a ArtifactFile>,
}

impl<'a> Files<'a> {
    pub fn new(files: impl IntoIterator<Item = &'a ArtifactFile>) -> Self {
        Files { map: files.into_iter().map(|f| (f.path.as_str(), f)).collect() }
    }

    pub fn get(&self, path: &str) -> Option<&'a ArtifactFile> {
        self.map.get(path).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&&'a str, &&'a ArtifactFile)> {
        self.map.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathContext {
    PackageEntrypoint,
    FilesystemExpression,
    ModuleSpecifier,
    HtmlReference,
    UrlReference,
}

impl PathContext {
    pub fn as_str(self) -> &'static str {
        match self {
            PathContext::PackageEntrypoint => "package-entrypoint",
            PathContext::FilesystemExpression => "filesystem-expression",
            PathContext::ModuleSpecifier => "module-specifier",
            PathContext::HtmlReference => "html-reference",
            PathContext::UrlReference => "url-reference",
        }
    }

    /// Parse a context name coming from static analysis (`module-specifier` or
    /// `filesystem-expression`).
    pub fn parse(name: &str) -> PathContext {
        match name {
            "package-entrypoint" => PathContext::PackageEntrypoint,
            "filesystem-expression" => PathContext::FilesystemExpression,
            "html-reference" => PathContext::HtmlReference,
            "url-reference" => PathContext::UrlReference,
            _ => PathContext::ModuleSpecifier,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Import,
    Require,
}

impl ModuleKind {
    pub fn parse(name: &str) -> ModuleKind {
        if name == "require" {
            ModuleKind::Require
        } else {
            ModuleKind::Import
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ModuleKind::Import => "import",
            ModuleKind::Require => "require",
        }
    }
}

/// `resolved`, `not-found`, `unavailable`, `external`, `rejected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Resolved,
    NotFound,
    Unavailable,
    External,
    Rejected,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Resolved => "resolved",
            Status::NotFound => "not-found",
            Status::Unavailable => "unavailable",
            Status::External => "external",
            Status::Rejected => "rejected",
        }
    }
}

/// Explicit outcome of artifact-confined path resolution (`ArtifactPathResolution`).
#[derive(Clone, Debug)]
pub struct Resolution {
    pub declared_path: String,
    pub context: PathContext,
    pub resolved_path: Option<String>,
    pub status: Status,
    pub limitations: Vec<String>,
}

impl Resolution {
    /// The `{declared_path, resolution_context, resolved_path, resolution_status, limitations}`
    /// fields REA spreads into node and edge properties.
    pub fn to_properties(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("declared_path".into(), json!(self.declared_path));
        map.insert("resolution_context".into(), json!(self.context.as_str()));
        map.insert("resolved_path".into(), json!(self.resolved_path));
        map.insert("resolution_status".into(), json!(self.status.as_str()));
        map.insert("limitations".into(), json!(self.limitations));
        map
    }
}

pub struct ResolveInput<'a, 'f> {
    pub declared_path: &'a str,
    pub source_path: &'a str,
    pub context: PathContext,
    pub files: &'a Files<'f>,
    pub html_base_href: Option<&'a str>,
    pub module_kind: Option<ModuleKind>,
}

impl<'a, 'f> ResolveInput<'a, 'f> {
    pub fn new(declared: &'a str, source: &'a str, context: PathContext, files: &'a Files<'f>) -> Self {
        ResolveInput {
            declared_path: declared,
            source_path: source,
            context,
            files,
            html_base_href: None,
            module_kind: None,
        }
    }
}

const EXTENSIONS: [&str; 8] = [".js", ".cjs", ".mjs", ".ts", ".tsx", ".json", ".html", ".node"];

struct Candidate {
    resolved: Option<String>,
    status: Status,
    limitations: Vec<String>,
}

fn unresolved(status: Status, limitations: Vec<String>) -> Candidate {
    Candidate { resolved: None, status, limitations }
}

fn resolved(path: String) -> Candidate {
    Candidate { resolved: Some(path), status: Status::Resolved, limitations: Vec::new() }
}

/// A candidate path or an already decided outcome.
enum Path {
    Value(String),
    Done(Candidate),
}

/// Resolve one declaration while preserving its original input identity.
pub fn resolve_artifact_path_by_context(input: &ResolveInput<'_, '_>) -> Resolution {
    let outcome = resolve_path(input);
    Resolution {
        declared_path: input.declared_path.to_string(),
        context: input.context,
        resolved_path: outcome.resolved,
        status: outcome.status,
        limitations: outcome.limitations,
    }
}

/// Convenience used by many callers: only the resolved path.
pub fn resolve_artifact_path(
    specifier: &str,
    source_path: &str,
    files: &Files<'_>,
    module_kind: Option<ModuleKind>,
) -> Option<String> {
    let mut input = ResolveInput::new(specifier, source_path, PathContext::ModuleSpecifier, files);
    input.module_kind = module_kind;
    resolve_artifact_path_by_context(&input).resolved_path
}

fn resolve_path(input: &ResolveInput<'_, '_>) -> Candidate {
    if let Some(rejected) = reject_declaration(input.declared_path) {
        return rejected;
    }
    let candidate = match contextual_candidate(input) {
        Path::Value(value) => value,
        Path::Done(done) => return done,
    };
    let confined = match confine_candidate(&candidate) {
        Path::Value(value) => value,
        Path::Done(done) => return done,
    };
    if input.context == PathContext::HtmlReference {
        return resolve_file_candidates(input, std::slice::from_ref(&confined)).unwrap_or_else(|| {
            unresolved(
                Status::NotFound,
                vec![format!(
                    "The exact HTML resource {confined} was not found among the selected application files."
                )],
            )
        });
    }
    resolve_candidate(input, &confined, &HashSet::new())
}

fn reject_declaration(declared: &str) -> Option<Candidate> {
    if declared.is_empty() {
        return Some(unresolved(Status::Rejected, vec!["The declared path is empty.".into()]));
    }
    if declared.contains('\0') || declared.contains('\\') {
        return Some(unresolved(
            Status::Rejected,
            vec!["NUL and backslash path syntax are not admitted for canonical artifact paths.".into()],
        ));
    }
    if !admits_canonical_path_syntax(declared) {
        return Some(unresolved(
            Status::Rejected,
            vec!["Encoded dot or separator bytes are rejected before artifact path resolution.".into()],
        ));
    }
    None
}

fn contextual_candidate(input: &ResolveInput<'_, '_>) -> Path {
    let context = input.context;
    let mut declared = if context == PathContext::HtmlReference
        || context == PathContext::UrlReference
        || (context == PathContext::ModuleSpecifier && input.module_kind != Some(ModuleKind::Require))
    {
        strip_query_and_fragment(input.declared_path)
    } else {
        input.declared_path.to_string()
    };
    if context == PathContext::HtmlReference {
        return html_candidate(input);
    }
    if context == PathContext::ModuleSpecifier {
        if let Some(file_url) = file_url_path(&declared) {
            return Path::Value(file_url);
        }
        if has_scheme(&declared) {
            return Path::Done(unresolved(
                Status::External,
                vec!["URL and Node builtin schemes are outside static artifact module resolution.".into()],
            ));
        }
        if !declared.starts_with('.') && !declared.starts_with('/') {
            return Path::Done(bare_module_candidate(input, &declared));
        }
        if input.module_kind != Some(ModuleKind::Require) {
            match decode_module_url_path(&declared) {
                Ok(decoded) => declared = decoded,
                Err(done) => return Path::Done(done),
            }
        }
    } else if looks_external(&declared) {
        return Path::Done(unresolved(
            Status::External,
            vec!["URL schemes and protocol-relative URLs are outside this local artifact path context.".into()],
        ));
    }
    Path::Value(relative_candidate(input.source_path, &declared))
}

fn decode_module_url_path(declared: &str) -> Result<String, Candidate> {
    let Some(decoded) = decode_uri_component(declared) else {
        return Err(unresolved(
            Status::Rejected,
            vec!["The module URL path contains malformed percent encoding.".into()],
        ));
    };
    if decoded.contains('\0') {
        return Err(unresolved(
            Status::Rejected,
            vec!["The decoded module URL path contains NUL.".into()],
        ));
    }
    Ok(decoded)
}

fn relative_candidate(source_path: &str, declared: &str) -> String {
    match declared.strip_prefix('/') {
        Some(rest) => rest.to_string(),
        None => join(&[&dirname(source_path), declared]),
    }
}

fn is_builtin(name: &str) -> bool {
    const PLAIN: &[&str] = &[
        "_http_agent", "_http_client", "_http_common", "_http_incoming", "_http_outgoing",
        "_http_server", "_stream_duplex", "_stream_passthrough", "_stream_readable",
        "_stream_transform", "_stream_wrap", "_stream_writable", "_tls_common", "_tls_wrap",
        "assert", "assert/strict", "async_hooks", "buffer", "child_process", "cluster", "console",
        "constants", "crypto", "dgram", "diagnostics_channel", "dns", "dns/promises", "domain",
        "events", "fs", "fs/promises", "http", "http2", "https", "inspector", "inspector/promises",
        "module", "net", "os", "path", "path/posix", "path/win32", "perf_hooks", "process",
        "punycode", "querystring", "readline", "readline/promises", "repl", "stream",
        "stream/consumers", "stream/promises", "stream/web", "string_decoder", "sys", "timers",
        "timers/promises", "tls", "trace_events", "tty", "url", "util", "util/types", "v8", "vm",
        "wasi", "worker_threads", "zlib",
    ];
    const SCHEME_ONLY: &[&str] = &["sea", "sqlite", "test", "test/reporters"];
    match name.strip_prefix("node:") {
        Some(rest) => PLAIN.contains(&rest) || SCHEME_ONLY.contains(&rest),
        None => PLAIN.contains(&name),
    }
}

fn bare_package_name(specifier: &str) -> Option<String> {
    let segments: Vec<&str> = specifier.split('/').collect();
    if specifier.starts_with('@') {
        return if segments.len() >= 2 && !segments[0].is_empty() && !segments[1].is_empty() {
            Some(format!("{}/{}", segments[0], segments[1]))
        } else {
            None
        };
    }
    if segments[0].is_empty() {
        None
    } else {
        Some(segments[0].to_string())
    }
}

fn bare_module_candidate(input: &ResolveInput<'_, '_>, declared: &str) -> Candidate {
    let package_name = bare_package_name(declared);
    let package_name = match package_name {
        Some(name) if !is_builtin(declared) && !declared.starts_with('#') => name,
        _ => {
            return unresolved(
                Status::External,
                vec!["The bare specifier is a Node builtin, package import map, or invalid package name.".into()],
            )
        }
    };
    let subpath = if declared == package_name {
        ".".to_string()
    } else {
        format!(".{}", &declared[package_name.len()..])
    };
    let source = input.files.get(input.source_path);
    let mut directory = dirname(input.source_path);
    loop {
        let candidate = join(&[&directory, "node_modules", &package_name]);
        if subpath == "." {
            if let Some(direct) = resolve_file_candidates(input, &file_candidates(&candidate)) {
                return direct;
            }
        }
        if has_container_directory(input.files, &candidate, source.map(|s| s.container_sha256.as_str())) {
            return resolve_package_specifier(input, &candidate, &subpath);
        }
        if directory == "." || directory.is_empty() {
            break;
        }
        directory = dirname(&directory);
    }
    unresolved(
        Status::External,
        vec!["No matching bare package was inventoried in an enclosing node_modules directory.".into()],
    )
}

fn resolve_package_specifier(input: &ResolveInput<'_, '_>, directory: &str, subpath: &str) -> Candidate {
    let metadata = read_package_metadata(input, directory);
    if let PackageMetadata::Unavailable(limitation) = &metadata {
        return unresolved(Status::Unavailable, vec![limitation.clone()]);
    }
    let raw_exports = match &metadata {
        PackageMetadata::Available { value, .. } => get_prop(value, "exports").cloned(),
        _ => None,
    };
    let exports = match raw_exports {
        None | Some(Value::Null) => {
            if subpath == "." {
                return resolve_directory(input, directory, &metadata, &HashSet::new());
            }
            return match confine_candidate(&join(&[directory, &subpath[2..]])) {
                Path::Value(candidate) => resolve_candidate(input, &candidate, &HashSet::new()),
                Path::Done(done) => done,
            };
        }
        Some(value) => value,
    };
    let exported = select_package_export(&exports, subpath, input.module_kind);
    let package_path = join(&[directory, "package.json"]);
    match exported {
        ExportOutcome::Rejected(limitation) => unresolved(
            Status::Rejected,
            vec![format!("Package metadata {package_path}: {limitation}")],
        ),
        ExportOutcome::Unmatched(declared) => {
            let target = if subpath == "." {
                "for the active conditions".to_string()
            } else {
                format!("for subpath {subpath}")
            };
            let declared_text = if declared.is_empty() {
                "a root target only".to_string()
            } else {
                declared.join(", ")
            };
            unresolved(
                Status::External,
                vec![format!(
                    "Directory package metadata {package_path} declares no exports target {target}; exports encapsulation permits no file or index lookup. It declares {declared_text}."
                )],
            )
        }
        ExportOutcome::Blocked => unresolved(
            Status::External,
            vec![format!(
                "Directory package metadata {package_path} blocks subpath {subpath} with an explicit null exports target."
            )],
        ),
        ExportOutcome::Value(target) => resolve_export_target(input, &package_path, &target),
    }
}

fn resolve_export_target(input: &ResolveInput<'_, '_>, package_path: &str, target: &str) -> Candidate {
    if let Some(rejected) = reject_declaration(target) {
        return rejected;
    }
    let decoded = match decode_module_url_path(&strip_query_and_fragment(target)) {
        Ok(decoded) => decoded,
        Err(done) => return done,
    };
    let candidate = match confine_candidate(&relative_candidate(package_path, &decoded)) {
        Path::Value(value) => value,
        Path::Done(done) => return done,
    };
    resolve_file_candidates(input, std::slice::from_ref(&candidate)).unwrap_or_else(|| {
        unresolved(
            Status::NotFound,
            vec![format!(
                "The selected package exports target {candidate} does not exist in the inventoried artifact container; exports targets are exact files, so no extension or directory index was tried."
            )],
        )
    })
}

fn has_container_directory(files: &Files<'_>, candidate: &str, container: Option<&str>) -> bool {
    let mut probes = index_candidates(candidate);
    probes.push(join(&[candidate, "package.json"]));
    for path in probes {
        if let Some(file) = files.get(&path) {
            if container.is_none_or(|c| file.container_sha256 == c) {
                return true;
            }
        }
    }
    let prefix = format!("{candidate}/");
    files.iter().any(|(path, file)| {
        path.starts_with(&prefix) && container.is_none_or(|c| file.container_sha256 == c)
    })
}

fn html_candidate(input: &ResolveInput<'_, '_>) -> Path {
    let declared = strip_query_and_fragment(&html_url_text(input.declared_path));
    if looks_external(&declared) {
        return Path::Done(unresolved(
            Status::External,
            vec!["External HTML references are not mapped to local artifact assets.".into()],
        ));
    }
    let base = input
        .html_base_href
        .map(|raw| strip_query_and_fragment(&html_url_text(raw)));
    if let Some(base) = &base {
        if looks_external(base) {
            return Path::Done(unresolved(
                Status::External,
                vec!["The document base href is external, so its script reference is not a local artifact path.".into()],
            ));
        }
    }
    if !admits_canonical_path_syntax(&declared) {
        return Path::Done(unresolved(
            Status::Rejected,
            vec!["Encoded dot or separator bytes are rejected before artifact path resolution.".into()],
        ));
    }
    let Some(declared_path) = percent_decode_url_path(&declared) else {
        return Path::Done(unresolved(
            Status::Rejected,
            vec!["The HTML reference path percent-decodes to NUL or to bytes that are not UTF-8.".into()],
        ));
    };
    if let Some(rest) = declared_path.strip_prefix('/') {
        return Path::Value(rest.to_string());
    }
    let base = match base {
        None => {
            return Path::Value(if declared_path.is_empty() {
                input.source_path.to_string()
            } else {
                join(&[&dirname(input.source_path), &declared_path])
            })
        }
        Some(base) if base.is_empty() => {
            return Path::Value(if declared_path.is_empty() {
                input.source_path.to_string()
            } else {
                join(&[&dirname(input.source_path), &declared_path])
            })
        }
        Some(base) => base,
    };
    if !admits_canonical_path_syntax(&base) {
        return Path::Done(unresolved(
            Status::Rejected,
            vec!["The document base href uses NUL, backslash, or encoded dot and separator bytes that are not admitted for canonical artifact paths.".into()],
        ));
    }
    let Some(decoded_base) = percent_decode_url_path(&base) else {
        return Path::Done(unresolved(
            Status::Rejected,
            vec!["The document base href path percent-decodes to NUL or to bytes that are not UTF-8.".into()],
        ));
    };
    let base_path = match decoded_base.strip_prefix('/') {
        Some(rest) => rest.to_string(),
        None => join(&[&dirname(input.source_path), &decoded_base]),
    };
    if declared_path.is_empty() {
        return empty_html_reference(&decoded_base, &base_path);
    }
    Path::Value(join(&[&html_base_directory(&decoded_base, &base_path), &declared_path]))
}

fn empty_html_reference(base: &str, base_path: &str) -> Path {
    if !html_base_is_directory(base) {
        return Path::Value(base_path.to_string());
    }
    match confine_candidate(base_path) {
        Path::Value(confined) => Path::Done(unresolved(
            Status::NotFound,
            vec![format!(
                "The HTML reference resolves to directory {}, not an exact selected application file.",
                if confined.is_empty() { ".".to_string() } else { confined }
            )],
        )),
        done @ Path::Done(_) => done,
    }
}

fn html_base_is_directory(base: &str) -> bool {
    base.ends_with('/') || base.ends_with("/.") || base.ends_with("/..") || base == "." || base == ".."
}

fn html_base_directory(base: &str, base_path: &str) -> String {
    if html_base_is_directory(base) {
        base_path.to_string()
    } else {
        dirname(base_path)
    }
}

fn confine_candidate(candidate: &str) -> Path {
    let normalized = normalize_joined_logical_path(candidate);
    if logical_path_escapes_root(&normalized) {
        return Path::Done(unresolved(
            Status::Rejected,
            vec!["The resolved candidate escapes the canonical artifact root.".into()],
        ));
    }
    Path::Value(if normalized == "." { String::new() } else { normalized })
}

enum PackageMetadata {
    Available { path: String, value: Value },
    Absent,
    Unavailable(String),
}

fn read_package_metadata(input: &ResolveInput<'_, '_>, directory: &str) -> PackageMetadata {
    let path = join(&[directory, "package.json"]);
    let file = input.files.get(&path);
    let source = input.files.get(input.source_path);
    let Some(file) = file else {
        return PackageMetadata::Absent;
    };
    if let Some(source) = source {
        if file.container_sha256 != source.container_sha256 {
            return PackageMetadata::Absent;
        }
    }
    let Some(text) = &file.text else {
        return PackageMetadata::Unavailable(format!(
            "Directory package metadata {path} was inventoried but its text is unavailable: {}.",
            file.text_reason.unwrap_or("not-applicable")
        ));
    };
    match serde_json::from_str::<Value>(text) {
        Ok(value @ (Value::Object(_) | Value::Array(_))) => PackageMetadata::Available { path, value },
        _ => PackageMetadata::Unavailable(format!(
            "Directory package metadata {path} is not valid package JSON."
        )),
    }
}

/// `Reflect.get(value, key)` on a parsed JSON value.
fn get_prop<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|map| map.get(key))
}

fn resolve_candidate(input: &ResolveInput<'_, '_>, candidate: &str, chain: &HashSet<String>) -> Candidate {
    resolve_file_candidates(input, &file_candidates(candidate)).unwrap_or_else(|| {
        let metadata = read_package_metadata(input, candidate);
        resolve_directory(input, candidate, &metadata, chain)
    })
}

fn resolve_directory(
    input: &ResolveInput<'_, '_>,
    directory: &str,
    metadata: &PackageMetadata,
    chain: &HashSet<String>,
) -> Candidate {
    let (metadata_path, value) = match metadata {
        PackageMetadata::Absent => {
            return resolve_file_candidates(input, &index_candidates(directory)).unwrap_or_else(not_found_candidate)
        }
        PackageMetadata::Unavailable(limitation) => {
            return unresolved(Status::Unavailable, vec![limitation.clone()])
        }
        PackageMetadata::Available { path, value } => (path, value),
    };
    if chain.contains(metadata_path) {
        return unresolved(
            Status::Unavailable,
            vec![format!("Directory package entrypoint cycle includes {metadata_path}.")],
        );
    }
    let mut preferred: Vec<Option<&Value>> = vec![get_prop(value, "main")];
    if input.module_kind.is_none() {
        preferred.push(get_prop(value, "module"));
    }
    let Some(entry) = preferred.into_iter().flatten().next() else {
        return resolve_file_candidates(input, &index_candidates(directory)).unwrap_or_else(not_found_candidate);
    };
    let entry = match entry.as_str() {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => {
            return unresolved(
                Status::Unavailable,
                vec![format!("Directory package metadata {metadata_path} is not valid package JSON.")],
            )
        }
    };
    let mut entry_input = ResolveInput::new(&entry, metadata_path, PathContext::PackageEntrypoint, input.files);
    entry_input.module_kind = input.module_kind;
    if let Some(rejected) = reject_declaration(&entry) {
        return rejected;
    }
    let candidate = match contextual_candidate(&entry_input) {
        Path::Value(value) => value,
        Path::Done(done) => return done,
    };
    let confined = match confine_candidate(&candidate) {
        Path::Value(value) => value,
        Path::Done(done) => return done,
    };
    let mut probes = file_candidates(&confined);
    probes.extend(index_candidates(&confined));
    if let Some(selected) = resolve_file_candidates(&entry_input, &probes)
        .or_else(|| resolve_file_candidates(input, &index_candidates(directory)))
    {
        return selected;
    }
    let mut next_chain = chain.clone();
    next_chain.insert(metadata_path.clone());
    resolve_candidate(&entry_input, &confined, &next_chain)
}

fn resolve_file_candidates(input: &ResolveInput<'_, '_>, candidates: &[String]) -> Option<Candidate> {
    let source = input.files.get(input.source_path);
    for path in candidates {
        if let Some(target) = input.files.get(path) {
            if source.is_none_or(|s| target.container_sha256 == s.container_sha256) {
                return Some(resolved(path.clone()));
            }
        }
    }
    None
}

fn file_candidates(candidate: &str) -> Vec<String> {
    let mut out = vec![candidate.to_string()];
    out.extend(EXTENSIONS.iter().map(|extension| format!("{candidate}{extension}")));
    out
}

fn index_candidates(candidate: &str) -> Vec<String> {
    EXTENSIONS
        .iter()
        .map(|extension| join(&[candidate, &format!("index{extension}")]))
        .collect()
}

fn not_found_candidate() -> Candidate {
    unresolved(
        Status::NotFound,
        vec!["No extension, directory package, or index candidate exists in the inventoried artifact container.".into()],
    )
}

// ---- package exports -----------------------------------------------------------------------

enum ExportOutcome {
    Value(String),
    Rejected(String),
    Blocked,
    Unmatched(Vec<String>),
}

/// `Object.keys` order: array-index keys ascending, then the others in insertion order.
fn js_keys(map: &Map<String, Value>) -> Vec<&String> {
    let mut indexed: Vec<(u64, &String)> = Vec::new();
    let mut named: Vec<&String> = Vec::new();
    for key in map.keys() {
        match array_index(key) {
            Some(index) => indexed.push((index, key)),
            None => named.push(key),
        }
    }
    indexed.sort_by_key(|(index, _)| *index);
    indexed.into_iter().map(|(_, key)| key).chain(named).collect()
}

/// Canonical array index (`String(Number(key)) === key`, below 2^32 - 1).
fn array_index(key: &str) -> Option<u64> {
    if key.is_empty() || (key.len() > 1 && key.starts_with('0')) || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = key.parse().ok()?;
    (value < 0xffff_ffff).then_some(value)
}

fn select_package_export(value: &Value, subpath: &str, module_kind: Option<ModuleKind>) -> ExportOutcome {
    let mut target: Value = value.clone();
    let mut declared: Vec<String> = Vec::new();
    match value {
        Value::Object(map) => {
            let keys = js_keys(map);
            let has_subpaths = keys.iter().any(|key| key.starts_with('.'));
            if has_subpaths && keys.iter().any(|key| !key.starts_with('.')) {
                return ExportOutcome::Rejected(
                    "The package exports configuration mixes subpath keys and condition keys.".into(),
                );
            }
            declared = keys.iter().map(|key| (*key).clone()).collect();
            if has_subpaths {
                if subpath.ends_with('/') || subpath.contains('*') || !map.contains_key(subpath) {
                    return ExportOutcome::Unmatched(declared);
                }
                target = map.get(subpath).cloned().unwrap_or(Value::Null);
            } else if subpath != "." {
                return ExportOutcome::Unmatched(declared);
            }
        }
        _ => {
            if subpath != "." {
                return ExportOutcome::Unmatched(declared);
            }
        }
    }
    match select_export_target(&target, &package_export_conditions(module_kind)) {
        TargetOutcome::Invalid(limitation) | TargetOutcome::InvalidConfig(limitation) => {
            ExportOutcome::Rejected(limitation)
        }
        TargetOutcome::Unmatched => ExportOutcome::Unmatched(match &target {
            Value::Object(map) => js_keys(map).into_iter().cloned().collect(),
            _ => declared,
        }),
        TargetOutcome::Blocked => ExportOutcome::Blocked,
        TargetOutcome::Value(text) => ExportOutcome::Value(text),
    }
}

enum TargetOutcome {
    Value(String),
    Blocked,
    Unmatched,
    Invalid(String),
    InvalidConfig(String),
}

fn invalid_export_target(value: &Value, reason: &str) -> TargetOutcome {
    let shown = match value {
        Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };
    TargetOutcome::Invalid(format!("The package exports target {shown} {reason}."))
}

/// Node checks raw target segments before URL normalization.
fn forbidden_export_segment(value: &str) -> Option<String> {
    let rest: String = value.chars().skip(2).collect();
    rest.split(['\\', '/'])
        .find(|raw| {
            let segment = decode_latin1_escapes(raw);
            segment == "." || segment == ".." || segment.to_lowercase() == "node_modules"
        })
        .map(str::to_string)
}

/// `raw.replace(/%[0-9a-f]{2}/giu, enc => String.fromCharCode(parseInt(enc.slice(1), 16)))`.
fn decode_latin1_escapes(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            if let (Some(hi), Some(lo)) = (chars[i + 1].to_digit(16), chars[i + 2].to_digit(16)) {
                out.push(char::from_u32(hi * 16 + lo).unwrap_or('\u{fffd}'));
                i += 3;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn select_export_target(value: &Value, conditions: &HashSet<&'static str>) -> TargetOutcome {
    match value {
        Value::String(text) => {
            if !text.starts_with("./") {
                return invalid_export_target(value, "must start with \"./\"");
            }
            match forbidden_export_segment(text) {
                None => TargetOutcome::Value(text.clone()),
                Some(forbidden) => invalid_export_target(
                    value,
                    &format!(
                        "contains forbidden path segment {} before URL normalization",
                        serde_json::to_string(&forbidden).unwrap_or_default()
                    ),
                ),
            }
        }
        Value::Null => TargetOutcome::Blocked,
        Value::Array(entries) => {
            let mut invalid: Option<String> = None;
            for entry in entries {
                let nested = select_export_target(entry, conditions);
                match nested {
                    TargetOutcome::InvalidConfig(_) => return nested,
                    TargetOutcome::Invalid(limitation) => {
                        invalid = Some(limitation);
                        continue;
                    }
                    TargetOutcome::Unmatched => continue,
                    other => {
                        invalid = None;
                        if matches!(other, TargetOutcome::Value(_)) {
                            return other;
                        }
                    }
                }
            }
            match invalid {
                None => TargetOutcome::Blocked,
                Some(limitation) => TargetOutcome::Invalid(limitation),
            }
        }
        Value::Object(map) => {
            for key in js_keys(map) {
                if array_index(key).is_some() {
                    return TargetOutcome::InvalidConfig(format!(
                        "The package exports configuration contains numeric condition key {}.",
                        serde_json::to_string(key).unwrap_or_default()
                    ));
                }
            }
            for key in js_keys(map) {
                if !conditions.contains(key.as_str()) {
                    continue;
                }
                let nested = select_export_target(&map[key.as_str()], conditions);
                if !matches!(nested, TargetOutcome::Unmatched) {
                    return nested;
                }
            }
            TargetOutcome::Unmatched
        }
        other => invalid_export_target(other, "must be a relative string, object, array, or null"),
    }
}

fn package_export_conditions(module_kind: Option<ModuleKind>) -> HashSet<&'static str> {
    let mut set: HashSet<&'static str> = ["node", "node-addons", "module-sync", "default"].into_iter().collect();
    if let Some(kind) = module_kind {
        set.insert(kind.as_str());
    }
    set
}

/// `fileUrlPath`: a `file:` URL without host as an artifact path.
fn file_url_path(value: &str) -> Option<String> {
    if !value.starts_with("file://") {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if url.scheme() != "file" || url.host_str().is_some_and(|h| !h.is_empty()) {
        return None;
    }
    let decoded = decode_uri_component(url.path())?;
    Some(decoded.trim_start_matches('/').to_string())
}
