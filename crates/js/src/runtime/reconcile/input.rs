//! Input validation and Evidence parsing for `reconcile_javascript_runtime`
//! (port of REA javascriptRuntimeReconciliationSchemas.ts input schema,
//! JavaScriptRuntimeReconciliationService.ts root normalization,
//! javascriptRuntimeReconciliationParsing.ts, ...CaptureParsing.ts,
//! ...Active.ts and ...InputValidation.ts).
//!
//! Nested producer results are checked structurally for the fields the
//! reconciliation reads; REA additionally re-parses them with the producer's
//! full zod schema.

use std::path::Path;

use serde_json::{json, Value};
use tracewise_domain::evidence::{Evidence, EvidenceAuthority, EvidenceConfidence};
use tracewise_web::browser_observation::{parse_cdp_endpoint, parse_exact_origin};
use url::Url;

use crate::digest::digest_canonical_value;
use crate::error::JsError;
use crate::runtime::inspector::RUNTIME_KINDS;
use crate::unicode::compare_unicode_code_points;

use super::paths::{is_portable_absolute_path, posix_resolve};

/// Caller-declared translation from an authorized runtime location to a layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMapping {
    FileRoot { root: String, artifact_prefix: String },
    UrlPrefix { prefix: String, artifact_prefix: String },
}

impl RuntimeMapping {
    fn key(&self) -> String {
        match self {
            Self::FileRoot { root, artifact_prefix } => format!("file-root\0{root}\0{artifact_prefix}"),
            Self::UrlPrefix { prefix, artifact_prefix } => format!("url-prefix\0{prefix}\0{artifact_prefix}"),
        }
    }

    pub fn artifact_prefix(&self) -> &str {
        match self {
            Self::FileRoot { artifact_prefix, .. } | Self::UrlPrefix { artifact_prefix, .. } => artifact_prefix,
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::FileRoot { root, artifact_prefix } => {
                json!({ "kind": "file-root", "root": root, "artifact_prefix": artifact_prefix })
            }
            Self::UrlPrefix { prefix, artifact_prefix } => {
                json!({ "kind": "url-prefix", "prefix": prefix, "artifact_prefix": artifact_prefix })
            }
        }
    }
}

/// One verified static application-analysis layer.
#[derive(Debug, Clone)]
pub struct StaticLayer {
    pub layer_id: String,
    pub role: String,
    pub evidence: Evidence,
    pub graph: Value,
    pub input_path: String,
    pub format: String,
    pub root_artifact_sha256: String,
    pub runtime_mappings: Vec<RuntimeMapping>,
}

impl StaticLayer {
    pub fn coverage_complete(&self) -> bool {
        self.graph["coverage"]["status"] == "complete"
    }

    pub fn coverage_truncated(&self) -> bool {
        self.graph["coverage"]["truncated"] == true
    }
}

/// Runtime location of one captured entity.
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeLoc {
    File(String),
    Url(String),
    /// The complete `{kind: "unresolved", reported_url, reason}` object.
    Unresolved(Value),
}

impl RuntimeLoc {
    pub fn value(&self) -> String {
        match self {
            Self::File(v) | Self::Url(v) => v.clone(),
            Self::Unresolved(location) => location["reported_url"].as_str().unwrap_or_default().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetView {
    pub target_id: String,
    pub target_type: String,
    pub title: String,
    pub attached: bool,
    pub location: RuntimeLoc,
}

#[derive(Debug, Clone)]
pub struct FrameView {
    pub frame_id: String,
    pub parent_frame_id: Value,
    pub location: RuntimeLoc,
}

#[derive(Debug, Clone)]
pub struct ScriptView {
    pub script_key: String,
    pub frame_id: Option<String>,
    pub location: RuntimeLoc,
    pub cdp_hash: Value,
    pub length: Value,
    pub is_module: Value,
    pub language: Value,
    pub source_sha256: Option<String>,
    /// Present only for browser captures, which declare source maps.
    pub source_map_url: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct WorkerView {
    pub target_id: String,
    pub worker_type: String,
    pub attached: bool,
    pub opener_target_id: Value,
    pub parent_frame_id: Option<String>,
    pub location: RuntimeLoc,
}

/// Normalized passive inspection consumed by reconciliation.
#[derive(Debug, Clone)]
pub struct Inspection {
    pub target: TargetView,
    pub frames: Vec<FrameView>,
    pub scripts: Vec<ScriptView>,
    pub workers: Vec<WorkerView>,
    pub completeness: Value,
}

impl Inspection {
    pub fn truncated_section(&self, section: &str) -> bool {
        string_list(&self.completeness["truncated_sections"]).iter().any(|s| s == section)
    }

    pub fn unavailable_section(&self, section: &str) -> bool {
        string_list(&self.completeness["unavailable_sections"]).iter().any(|s| s == section)
    }

    pub fn has_condition(&self, condition: &str) -> bool {
        string_list(&self.completeness["conditions"]).iter().any(|s| s == condition)
    }

    pub fn complete_within_window(&self) -> bool {
        self.completeness["status"] == "complete_within_window"
    }

    pub fn has_unavailable_sections(&self) -> bool {
        !string_list(&self.completeness["unavailable_sections"]).is_empty()
    }
}

/// One verified passive runtime capture.
#[derive(Debug, Clone)]
pub struct RuntimeCapture {
    pub kind: &'static str,
    pub evidence: Evidence,
    pub inspection: Inspection,
    pub capture_sha256: String,
    pub scripts_complete_within_scope: bool,
}

/// Verified caller input plus the facts parsed from it.
#[derive(Debug, Clone)]
pub struct ParsedReconciliationInput {
    /// `{role, evidence_id, runtime_mappings}` per input layer, in input order.
    pub parameter_layers: Vec<Value>,
    pub runtime_evidence_ids: Vec<String>,
    pub layers: Vec<StaticLayer>,
    pub captures: Vec<RuntimeCapture>,
}

fn invalid(path: &str, message: &str) -> JsError {
    JsError::InvalidInput(format!("{path}: {message}"))
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Validate and parse one `reconcile_javascript_runtime` request.
pub fn parse_reconciliation_input(args: &Value) -> Result<ParsedReconciliationInput, JsError> {
    let object = args.as_object().ok_or_else(|| invalid("input", "Expected an object"))?;
    if let Some(key) = object.keys().find(|key| *key != "static_layers" && *key != "runtime_observations") {
        return Err(invalid(key, &format!("Unrecognized key: \"{key}\"")));
    }
    let raw_layers = object
        .get("static_layers")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid("static_layers", "Expected a non-empty array"))?;
    let raw_observations = object
        .get("runtime_observations")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid("runtime_observations", "Expected a non-empty array"))?;

    let mut declared = Vec::new();
    for (index, raw) in raw_layers.iter().enumerate() {
        declared.push(parse_layer_declaration(raw, &format!("static_layers.{index}"))?);
    }
    let mut observations = Vec::new();
    for (index, raw) in raw_observations.iter().enumerate() {
        observations.push(parse_evidence(raw, &format!("runtime_observations.{index}"))?);
    }
    if declared.iter().filter(|(role, _, _)| role == "application").count() != 1 {
        return Err(invalid("static_layers", "Exactly one application static layer is required"));
    }
    let static_ids: Vec<&str> = declared.iter().map(|(_, evidence, _)| evidence.evidence_id.as_str()).collect();
    if has_duplicates(&static_ids) {
        return Err(invalid("static_layers", "Static layer Evidence must be unique"));
    }
    let runtime_ids: Vec<&str> = observations.iter().map(|evidence| evidence.evidence_id.as_str()).collect();
    if has_duplicates(&runtime_ids) {
        return Err(invalid("runtime_observations", "Runtime observation Evidence must be unique"));
    }

    let parameter_layers = declared
        .iter()
        .map(|(role, evidence, mappings)| {
            json!({
                "role": role,
                "evidence_id": evidence.evidence_id,
                "runtime_mappings": mappings.iter().map(RuntimeMapping::to_json).collect::<Vec<_>>(),
            })
        })
        .collect();
    let runtime_evidence_ids = observations.iter().map(|evidence| evidence.evidence_id.clone()).collect();

    let mut layers = Vec::new();
    for (index, (role, evidence, mappings)) in declared.into_iter().enumerate() {
        layers.push(parse_static_layer(role, evidence, mappings, &format!("static_layers.{index}.analysis"))?);
    }
    layers.sort_by(|left, right| compare_unicode_code_points(&left.layer_id, &right.layer_id));

    let mut captures = Vec::new();
    for (index, evidence) in observations.into_iter().enumerate() {
        captures.push(parse_runtime_capture(evidence, &format!("runtime_observations.{index}"))?);
    }
    captures.sort_by(|left, right| compare_unicode_code_points(&left.evidence.evidence_id, &right.evidence.evidence_id));

    Ok(ParsedReconciliationInput {
        parameter_layers,
        runtime_evidence_ids,
        layers,
        captures,
    })
}

fn has_duplicates(values: &[&str]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().any(|value| !seen.insert(*value))
}

fn parse_evidence(value: &Value, path: &str) -> Result<Evidence, JsError> {
    let evidence: Evidence =
        serde_json::from_value(value.clone()).map_err(|error| invalid(path, &format!("Invalid Evidence: {error}")))?;
    evidence
        .verify()
        .map_err(|error| invalid(path, &format!("Evidence is not authentic: {error}")))?;
    Ok(evidence)
}

fn parse_layer_declaration(raw: &Value, path: &str) -> Result<(String, Evidence, Vec<RuntimeMapping>), JsError> {
    let object = raw.as_object().ok_or_else(|| invalid(path, "Expected an object"))?;
    if let Some(key) = object.keys().find(|key| !["role", "analysis", "runtime_mappings"].contains(&key.as_str())) {
        return Err(invalid(path, &format!("Unrecognized key: \"{key}\"")));
    }
    let role = match object.get("role") {
        None => "application".to_string(),
        Some(Value::String(role)) if ["application", "cache", "assets"].contains(&role.as_str()) => role.clone(),
        Some(_) => return Err(invalid(&format!("{path}.role"), "Expected application, cache, or assets")),
    };
    let analysis = object.get("analysis").ok_or_else(|| invalid(&format!("{path}.analysis"), "Required"))?;
    let evidence = parse_evidence(analysis, &format!("{path}.analysis"))?;
    let mut mappings = Vec::new();
    match object.get("runtime_mappings") {
        None => {}
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                mappings.push(parse_mapping(item, &format!("{path}.runtime_mappings.{index}"))?);
            }
        }
        Some(_) => return Err(invalid(&format!("{path}.runtime_mappings"), "Expected an array")),
    }
    Ok((role, evidence, normalize_runtime_mappings(mappings)))
}

fn parse_mapping(raw: &Value, path: &str) -> Result<RuntimeMapping, JsError> {
    let object = raw.as_object().ok_or_else(|| invalid(path, "Expected an object"))?;
    let artifact_prefix = match object.get("artifact_prefix") {
        None => String::new(),
        Some(Value::String(prefix)) if is_safe_prefix(prefix) => prefix.clone(),
        Some(_) => {
            return Err(invalid(
                &format!("{path}.artifact_prefix"),
                "Artifact prefix must be empty or a safe relative POSIX path",
            ))
        }
    };
    let text = |key: &str| match object.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(invalid(&format!("{path}.{key}"), "Expected a non-empty string")),
    };
    match object.get("kind").and_then(Value::as_str) {
        Some("file-root") => {
            reject_extra(object, &["kind", "root", "artifact_prefix"], path)?;
            let root = text("root")?;
            // REA resolves relative roots against the server working directory.
            let root = if is_portable_absolute_path(&root) { root } else { posix_resolve(&root) };
            Ok(RuntimeMapping::FileRoot { root, artifact_prefix })
        }
        Some("url-prefix") => {
            reject_extra(object, &["kind", "prefix", "artifact_prefix"], path)?;
            let prefix = normalize_runtime_url_prefix(&text("prefix")?).ok_or_else(|| {
                invalid(
                    &format!("{path}.prefix"),
                    "Runtime URL prefix must be HTTP(S) without credentials, query, or fragment",
                )
            })?;
            Ok(RuntimeMapping::UrlPrefix { prefix, artifact_prefix })
        }
        _ => Err(invalid(&format!("{path}.kind"), "Expected file-root or url-prefix")),
    }
}

fn reject_extra(object: &serde_json::Map<String, Value>, keys: &[&str], path: &str) -> Result<(), JsError> {
    match object.keys().find(|key| !keys.contains(&key.as_str())) {
        Some(key) => Err(invalid(path, &format!("Unrecognized key: \"{key}\""))),
        None => Ok(()),
    }
}

fn is_safe_prefix(value: &str) -> bool {
    value.is_empty()
        || (!value.starts_with('/')
            && !value.contains('\\')
            && value.split('/').all(|part| !["", ".", ".."].contains(&part)))
}

fn normalize_runtime_url_prefix(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if (url.scheme() != "http" && url.scheme() != "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !url.query().unwrap_or("").is_empty()
        || !url.fragment().unwrap_or("").is_empty()
    {
        return None;
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Some(url.to_string())
}

fn normalize_runtime_mappings(mappings: Vec<RuntimeMapping>) -> Vec<RuntimeMapping> {
    let mut unique: Vec<RuntimeMapping> = Vec::new();
    for mapping in mappings {
        if let Some(existing) = unique.iter_mut().find(|item| item.key() == mapping.key()) {
            *existing = mapping;
        } else {
            unique.push(mapping);
        }
    }
    unique.sort_by(|left, right| compare_unicode_code_points(&left.key(), &right.key()));
    unique
}

struct ExpectedIdentity<'a> {
    operation: &'a str,
    predicate: &'a str,
    provider_id: &'a str,
    provider_name: &'a str,
    provider_version: &'a str,
    authority: EvidenceAuthority,
    confidence: EvidenceConfidence,
}

fn assert_evidence_identity(evidence: &Evidence, expected: ExpectedIdentity<'_>, path: &str) -> Result<(), JsError> {
    if evidence.operation != expected.operation
        || evidence.predicate_type != expected.predicate
        || evidence.provider.id != expected.provider_id
        || evidence.provider.name != expected.provider_name
        || evidence.provider.version.as_deref() != Some(expected.provider_version)
        || evidence.authority != expected.authority
        || evidence.confidence != expected.confidence
    {
        return Err(invalid(
            path,
            &format!("Evidence does not match the supported {} contract", expected.operation),
        ));
    }
    Ok(())
}

fn parse_static_layer(role: String, evidence: Evidence, mappings: Vec<RuntimeMapping>, path: &str) -> Result<StaticLayer, JsError> {
    let result = &evidence.normalized_result;
    let text = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| invalid(&format!("{path}.normalized_result.{key}"), "Required"))
    };
    let root_artifact_sha256 = text("root_artifact_sha256")?;
    let format = text("format")?;
    let input_path = text("input_path")?;
    let graph = result
        .get("graph")
        .filter(|graph| graph.is_object())
        .cloned()
        .ok_or_else(|| invalid(&format!("{path}.normalized_result.graph"), "Required"))?;
    for key in ["nodes", "edges", "root_node_ids"] {
        if !graph[key].is_array() {
            return Err(invalid(&format!("{path}.normalized_result.graph.{key}"), "Expected an array"));
        }
    }
    if !graph["coverage"].is_object() || !graph["graph_id"].is_string() {
        return Err(invalid(&format!("{path}.normalized_result.graph"), "Invalid JavaScript Application Graph"));
    }
    assert_evidence_identity(
        &evidence,
        ExpectedIdentity {
            operation: "analyze_javascript_application",
            predicate: "rea.javascript-application-analysis",
            provider_id: "rea-javascript-application",
            provider_name: "REA JavaScript application analyzer",
            provider_version: "1",
            authority: EvidenceAuthority::ShippedArtifact,
            confidence: EvidenceConfidence::Derived,
        },
        path,
    )?;
    let subject_agrees = evidence.subject.as_ref().is_some_and(|subject| {
        subject.digest.sha256 == root_artifact_sha256 && subject.format == format && subject.local_path == input_path
    });
    if !subject_agrees {
        return Err(invalid(
            &format!("{path}.subject"),
            "JavaScript application Evidence subject disagrees with its result",
        ));
    }
    let layer_id = format!(
        "jrl_{}",
        digest_canonical_value(&json!({
            "role": role,
            "evidence_id": evidence.evidence_id,
            "runtime_mappings": mappings.iter().map(RuntimeMapping::to_json).collect::<Vec<_>>(),
        }))?
    );
    Ok(StaticLayer {
        layer_id,
        role,
        evidence,
        graph,
        input_path,
        format,
        root_artifact_sha256,
        runtime_mappings: mappings,
    })
}

fn parse_runtime_capture(evidence: Evidence, path: &str) -> Result<RuntimeCapture, JsError> {
    match evidence.operation.as_str() {
        "inspect_web_page" => parse_cdp_capture(evidence, path, true),
        "inspect_electron_page" => parse_cdp_capture(evidence, path, false),
        "observe_javascript_runtime" => parse_v8_capture(evidence, path),
        "capture_electron_scenario" => parse_active_electron_capture(evidence, path),
        _ => Err(invalid(
            path,
            "Runtime reconciliation requires inspect_web_page, inspect_electron_page, observe_javascript_runtime, or capture_electron_scenario Evidence",
        )),
    }
}

fn required_str(value: &Value, key: &str, path: &str) -> Result<String, JsError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid(&format!("{path}.{key}"), "Expected a string"))
}

fn required_bool(value: &Value, key: &str, path: &str) -> Result<bool, JsError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("{path}.{key}"), "Expected a boolean"))
}

fn optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Browser entities carry `url`; Electron entities carry `file_path`.
fn cdp_location(value: &Value, browser: bool, path: &str) -> Result<RuntimeLoc, JsError> {
    if browser {
        Ok(RuntimeLoc::Url(required_str(value, "url", path)?))
    } else {
        Ok(RuntimeLoc::File(required_str(value, "file_path", path)?))
    }
}

fn items<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>, JsError> {
    value.as_array().ok_or_else(|| invalid(path, "Expected an array"))
}

fn scripts_complete(completeness: &Value) -> bool {
    let has = |key: &str| string_list(&completeness[key]).iter().any(|s| s == "scripts");
    !has("truncated_sections") && !has("unavailable_sections") && completeness["dropped_events"]["scripts"] == 0
}

fn parse_cdp_capture(evidence: Evidence, path: &str, browser: bool) -> Result<RuntimeCapture, JsError> {
    if browser {
        assert_evidence_identity(
            &evidence,
            ExpectedIdentity {
                operation: "inspect_web_page",
                predicate: "rea.web-page-inspection",
                provider_id: "rea-cdp-browser",
                provider_name: "REA Chrome DevTools Protocol observation provider",
                provider_version: "2",
                authority: EvidenceAuthority::ExternalService,
                confidence: EvidenceConfidence::Observed,
            },
            path,
        )?;
    } else {
        assert_evidence_identity(
            &evidence,
            ExpectedIdentity {
                operation: "inspect_electron_page",
                predicate: "rea.electron-page-inspection",
                provider_id: "rea-cdp-electron",
                provider_name: "REA Electron file-page CDP observation provider",
                provider_version: "1",
                authority: EvidenceAuthority::ExternalService,
                confidence: EvidenceConfidence::Observed,
            },
            path,
        )?;
    }
    let result_path = format!("{path}.normalized_result");
    let result = &evidence.normalized_result;
    let raw_target = result.get("target").ok_or_else(|| invalid(&format!("{result_path}.target"), "Required"))?;
    let target_path = format!("{result_path}.target");
    let target = TargetView {
        target_id: required_str(raw_target, "target_id", &target_path)?,
        target_type: required_str(raw_target, "type", &target_path)?,
        title: required_str(raw_target, "title", &target_path)?,
        attached: required_bool(raw_target, "attached", &target_path)?,
        location: cdp_location(raw_target, browser, &target_path)?,
    };
    let mut frames = Vec::new();
    for (index, frame) in items(&result["frames"], &format!("{result_path}.frames"))?.iter().enumerate() {
        let frame_path = format!("{result_path}.frames.{index}");
        frames.push(FrameView {
            frame_id: required_str(frame, "frame_id", &frame_path)?,
            parent_frame_id: frame.get("parent_frame_id").cloned().unwrap_or(Value::Null),
            location: cdp_location(frame, browser, &frame_path)?,
        });
    }
    let mut scripts = Vec::new();
    let mut source_included = false;
    for (index, script) in items(&result["scripts"]["items"], &format!("{result_path}.scripts.items"))?
        .iter()
        .enumerate()
    {
        let script_path = format!("{result_path}.scripts.items.{index}");
        let included = script["source"]["included"] == true;
        source_included |= included;
        let source_sha256 = if included {
            Some(required_str(&script["source"]["artifact"], "sha256", &format!("{script_path}.source.artifact"))?)
        } else {
            None
        };
        scripts.push(ScriptView {
            script_key: required_str(script, "script_key", &script_path)?,
            frame_id: optional_string(script, "frame_id"),
            location: cdp_location(script, browser, &script_path)?,
            cdp_hash: script.get("cdp_hash").cloned().unwrap_or(Value::Null),
            length: script.get("length").cloned().unwrap_or(Value::Null),
            is_module: script.get("is_module").cloned().unwrap_or(Value::Null),
            language: script.get("language").cloned().unwrap_or(Value::Null),
            source_sha256,
            source_map_url: browser.then(|| script.get("source_map_url").cloned().unwrap_or(Value::Null)),
        });
    }
    let mut workers = Vec::new();
    for (index, worker) in items(&result["workers"], &format!("{result_path}.workers"))?.iter().enumerate() {
        let worker_path = format!("{result_path}.workers.{index}");
        workers.push(WorkerView {
            target_id: required_str(worker, "target_id", &worker_path)?,
            worker_type: required_str(worker, "type", &worker_path)?,
            attached: required_bool(worker, "attached", &worker_path)?,
            opener_target_id: worker.get("opener_target_id").cloned().unwrap_or(Value::Null),
            parent_frame_id: optional_string(worker, "parent_frame_id"),
            location: cdp_location(worker, browser, &worker_path)?,
        });
    }
    let completeness = result
        .get("completeness")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| invalid(&format!("{result_path}.completeness"), "Required"))?;

    let parameters = &evidence.parameters;
    let parameters_path = format!("{path}.parameters");
    let parameter_target = match parameters.get("target_id") {
        Some(Value::String(id)) if !id.trim().is_empty() => id.trim().to_string(),
        _ => return Err(invalid(&format!("{parameters_path}.target_id"), "Expected a non-empty string")),
    };
    if !parameters
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .is_some_and(|endpoint| parse_cdp_endpoint(endpoint).is_some())
    {
        return Err(invalid(&format!("{parameters_path}.cdp_endpoint"), "Invalid CDP endpoint"));
    }
    let include_sources = parameters
        .get("include_script_sources")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("{parameters_path}.include_script_sources"), "Expected a boolean"))?;
    if browser {
        let mut origins = Vec::new();
        match parameters.get("allowed_origins") {
            None => {}
            Some(Value::Array(values)) => {
                for value in values {
                    origins.push(value.as_str().and_then(parse_exact_origin).ok_or_else(|| {
                        invalid(&format!("{parameters_path}.allowed_origins"), "Expected exact HTTP(S) origins")
                    })?);
                }
            }
            Some(_) => return Err(invalid(&format!("{parameters_path}.allowed_origins"), "Expected an array")),
        }
        if parameter_target != target.target_id {
            return Err(invalid(
                &format!("{parameters_path}.target_id"),
                "Runtime Evidence target disagrees with its captured result",
            ));
        }
        let target_origin = required_str(raw_target, "origin", &target_path)?;
        if !origins.contains(&target_origin) {
            return Err(invalid(
                &format!("{parameters_path}.allowed_origins"),
                "Browser Evidence target is outside its recorded origin scope",
            ));
        }
    } else if parameter_target != target.target_id {
        return Err(invalid(
            &format!("{parameters_path}.target_id"),
            "Runtime Evidence target disagrees with its captured result",
        ));
    }
    if source_included && !include_sources {
        return Err(invalid(
            &format!("{parameters_path}.include_script_sources"),
            "Runtime Evidence contains source without source-capture selection",
        ));
    }
    let capture_sha256 = digest_canonical_value(result)?;
    let scripts_complete_within_scope = scripts_complete(&completeness);
    Ok(RuntimeCapture {
        kind: if browser { "browser" } else { "electron" },
        inspection: Inspection {
            target,
            frames,
            scripts,
            workers,
            completeness,
        },
        capture_sha256,
        scripts_complete_within_scope,
        evidence,
    })
}

/// V8 Inspector locations as reconciliation locations; builtins keep their specifier.
fn v8_location(location: &Value, path: &str) -> Result<RuntimeLoc, JsError> {
    match location["kind"].as_str() {
        Some("unresolved") => Ok(RuntimeLoc::Unresolved(location.clone())),
        Some("file") => Ok(RuntimeLoc::File(required_str(location, "file_path", path)?)),
        Some("url") => Ok(RuntimeLoc::Url(required_str(location, "sanitized_url", path)?)),
        Some("builtin") => {
            let specifier = required_str(location, "specifier", path)?;
            if !specifier.starts_with("node:") {
                return Err(invalid(path, "Runtime Evidence contains an invalid builtin location"));
            }
            Ok(RuntimeLoc::Url(specifier))
        }
        _ => Err(invalid(path, "Invalid runtime location")),
    }
}

fn parse_v8_capture(evidence: Evidence, path: &str) -> Result<RuntimeCapture, JsError> {
    assert_evidence_identity(
        &evidence,
        ExpectedIdentity {
            operation: "observe_javascript_runtime",
            predicate: "rea.javascript-runtime-observation",
            provider_id: "rea-v8-inspector",
            provider_name: "REA passive Node/Electron V8 Inspector provider",
            provider_version: "1",
            authority: EvidenceAuthority::ExternalService,
            confidence: EvidenceConfidence::Observed,
        },
        path,
    )?;
    let result = &evidence.normalized_result;
    let result_path = format!("{path}.normalized_result");
    let raw_target = &result["target"];
    let target_path = format!("{result_path}.target");
    let runtime_kind = required_str(raw_target, "runtime_kind", &target_path)?;

    let parameters = &evidence.parameters;
    let parameters_path = format!("{path}.parameters");
    if !parameters
        .get("inspector_endpoint")
        .and_then(Value::as_str)
        .is_some_and(|endpoint| parse_cdp_endpoint(endpoint).is_some())
    {
        return Err(invalid(&format!("{parameters_path}.inspector_endpoint"), "Invalid Inspector endpoint"));
    }
    let parameter_target = match parameters.get("target_id") {
        Some(Value::String(id)) if !id.trim().is_empty() => id.trim().to_string(),
        _ => return Err(invalid(&format!("{parameters_path}.target_id"), "Expected a non-empty string")),
    };
    let declared_kind = match parameters.get("runtime_kind") {
        None => None,
        Some(Value::String(kind)) if RUNTIME_KINDS.contains(&kind.as_str()) => Some(kind.clone()),
        Some(_) => return Err(invalid(&format!("{parameters_path}.runtime_kind"), "Invalid runtime kind")),
    };
    let target_id = required_str(raw_target, "target_id", &target_path)?;
    if parameter_target != target_id || declared_kind.is_some_and(|kind| kind != runtime_kind) {
        return Err(invalid(
            &format!("{parameters_path}.target_id"),
            "Runtime Evidence target or declared role disagrees with its result",
        ));
    }
    let target = TargetView {
        target_id,
        target_type: required_str(raw_target, "protocol_type", &target_path)?,
        title: runtime_kind,
        attached: required_bool(raw_target, "attached", &target_path)?,
        location: v8_location(&raw_target["location"], &format!("{target_path}.location"))?,
    };
    let mut scripts = Vec::new();
    for (index, script) in items(&result["scripts"]["items"], &format!("{result_path}.scripts.items"))?
        .iter()
        .enumerate()
    {
        let script_path = format!("{result_path}.scripts.items.{index}");
        scripts.push(ScriptView {
            script_key: required_str(script, "script_key", &script_path)?,
            frame_id: optional_string(script, "execution_context_key"),
            location: v8_location(&script["location"], &format!("{script_path}.location"))?,
            cdp_hash: script.get("cdp_hash").cloned().unwrap_or(Value::Null),
            length: script.get("length").cloned().unwrap_or(Value::Null),
            is_module: script.get("is_module").cloned().unwrap_or(Value::Null),
            language: Value::Null,
            source_sha256: None,
            source_map_url: None,
        });
    }
    let excluded: i64 = result["scripts"]["excluded"]
        .as_object()
        .map(|counts| counts.values().filter_map(Value::as_i64).sum())
        .unwrap_or(0);
    let truncated = result["capture"]["truncated"] == true;
    let dropped = result["capture"]["events_dropped"].as_i64().unwrap_or(0);
    let completeness = classify_browser_completeness(CompletenessInput {
        policy_filtered: if excluded > 0 { vec!["scripts"] } else { vec![] },
        attach_limited: vec!["frames", "scripts", "script_sources", "workers"],
        truncated: if truncated { vec!["scripts"] } else { vec![] },
        unavailable: vec!["frames", "script_sources", "workers"],
        excluded: if excluded > 0 {
            vec![json!({ "section": "scripts", "reason": "out_of_target_scope", "count": excluded })]
        } else {
            vec![]
        },
        dropped_scripts: dropped,
    });
    let capture_sha256 = digest_canonical_value(result)?;
    Ok(RuntimeCapture {
        kind: "v8-inspector",
        inspection: Inspection {
            target,
            frames: vec![],
            scripts,
            workers: vec![],
            completeness,
        },
        capture_sha256,
        scripts_complete_within_scope: false,
        evidence,
    })
}

fn parse_active_electron_capture(evidence: Evidence, path: &str) -> Result<RuntimeCapture, JsError> {
    if evidence.operation != "capture_electron_scenario"
        || evidence.predicate_type != "rea.electron-active-scenario"
        || evidence.provider.id != "rea-playwright-electron-active"
        || evidence.provider.name != "REA Playwright active Electron observation provider"
        || evidence.provider.version.as_deref() != Some("1")
        || evidence.authority != EvidenceAuthority::ControlledReplay
        || evidence.confidence != EvidenceConfidence::Observed
    {
        return Err(invalid(
            path,
            "Evidence does not match the supported capture_electron_scenario contract",
        ));
    }
    let application_path = required_str(
        &evidence.normalized_result["application"],
        "application_path",
        &format!("{path}.normalized_result.application"),
    )?;
    let absolute = |key: &str| {
        evidence
            .parameters
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && Path::new(value).is_absolute())
            .map(str::to_string)
            .ok_or_else(|| invalid(&format!("{path}.parameters.{key}"), "Expected an absolute path"))
    };
    let parameter_path = absolute("application_path")?;
    let application_root = absolute("application_root")?;
    if application_path != parameter_path || !Path::new(&application_path).starts_with(Path::new(&application_root)) {
        return Err(invalid(
            &format!("{path}.normalized_result.application.application_path"),
            "Active Electron Evidence application path disagrees with its configured root",
        ));
    }
    let digest = digest_canonical_value(&json!(application_path))?;
    let completeness = classify_browser_completeness(CompletenessInput {
        policy_filtered: vec![],
        attach_limited: vec![],
        truncated: vec![],
        unavailable: vec!["frames", "scripts", "script_sources", "workers"],
        excluded: vec![],
        dropped_scripts: 0,
    });
    let capture_sha256 = digest_canonical_value(&evidence.normalized_result)?;
    Ok(RuntimeCapture {
        kind: "electron-active",
        inspection: Inspection {
            target: TargetView {
                target_id: format!("electron-active:{}", &digest[..32]),
                target_type: "electron-application".to_string(),
                title: application_path.clone(),
                attached: true,
                location: RuntimeLoc::File(application_path),
            },
            frames: vec![],
            scripts: vec![],
            workers: vec![],
            completeness,
        },
        capture_sha256,
        scripts_complete_within_scope: false,
        evidence,
    })
}

struct CompletenessInput {
    policy_filtered: Vec<&'static str>,
    attach_limited: Vec<&'static str>,
    truncated: Vec<&'static str>,
    unavailable: Vec<&'static str>,
    excluded: Vec<Value>,
    dropped_scripts: i64,
}

/// Port of REA `classifyBrowserCompleteness`.
fn classify_browser_completeness(input: CompletenessInput) -> Value {
    let policy = !input.policy_filtered.is_empty();
    let truncated = !input.truncated.is_empty() || input.dropped_scripts > 0;
    let attach = !input.attach_limited.is_empty() || !input.unavailable.is_empty();
    let status = if truncated {
        "truncated"
    } else if policy {
        "policy_filtered"
    } else if attach {
        "attach_limited"
    } else {
        "complete_within_window"
    };
    let mut conditions = Vec::new();
    if attach {
        conditions.push("attach_limited");
    }
    if policy {
        conditions.push("policy_filtered");
    }
    if truncated {
        conditions.push("truncated");
    }
    if conditions.is_empty() {
        conditions.push("complete_within_window");
    }
    let sorted = |mut sections: Vec<&'static str>| {
        sections.sort_unstable();
        sections.dedup();
        sections
    };
    json!({
        "status": status,
        "conditions": conditions,
        "policy_filtered_sections": sorted(input.policy_filtered),
        "attach_limited_sections": sorted(input.attach_limited),
        "truncated_sections": sorted(input.truncated),
        "unavailable_sections": sorted(input.unavailable),
        "excluded": input.excluded,
        "dropped_events": {
            "scripts": input.dropped_scripts,
            "network_requests": 0,
            "console_events": 0,
            "websocket_connections": 0,
            "websocket_frames": 0,
            "webmcp_tools": 0,
            "timeline_events": 0,
            "total": input.dropped_scripts,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_prefixes_gain_a_trailing_slash_and_reject_queries() {
        assert_eq!(
            normalize_runtime_url_prefix("https://example.com/app").as_deref(),
            Some("https://example.com/app/")
        );
        assert_eq!(normalize_runtime_url_prefix("https://example.com/?x=1"), None);
        assert_eq!(normalize_runtime_url_prefix("ftp://example.com/"), None);
    }

    #[test]
    fn artifact_prefixes_must_be_safe_relative_paths() {
        assert!(is_safe_prefix(""));
        assert!(is_safe_prefix("a/b"));
        assert!(!is_safe_prefix("/a"));
        assert!(!is_safe_prefix("a/../b"));
        assert!(!is_safe_prefix("a//b"));
    }

    #[test]
    fn mappings_are_deduplicated_and_sorted() {
        let mappings = normalize_runtime_mappings(vec![
            RuntimeMapping::UrlPrefix { prefix: "https://a/".into(), artifact_prefix: String::new() },
            RuntimeMapping::FileRoot { root: "/b".into(), artifact_prefix: String::new() },
            RuntimeMapping::FileRoot { root: "/b".into(), artifact_prefix: String::new() },
        ]);
        assert_eq!(mappings.len(), 2);
        assert!(matches!(mappings[0], RuntimeMapping::FileRoot { .. }));
    }
}
