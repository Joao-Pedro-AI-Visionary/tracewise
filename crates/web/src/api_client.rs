//! Generate typed API clients from an OpenAPI document.
//!
//! Templates are embedded and replay fixtures come from redacted captures, so
//! credential material stripped by `inspect_web_network_capture` cannot be
//! copied into the SDK.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence,
    EvidenceLocation, EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::api_client_emit::render_sdk;
use crate::api_client_model::build_sdk;
use crate::api_client_replay::samples_from_evidence;
use crate::error::WebError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Language {
    Python,
    TypeScript,
}

impl Language {
    fn as_str(self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::TypeScript => "typescript",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateApiClientInput {
    pub spec_path: Option<String>,
    pub spec: Option<Value>,
    pub languages: Vec<String>,
    pub output_directory: String,
    pub package_name: Option<String>,
    pub replay_capture_path: Option<String>,
}

pub struct GeneratedApiClient {
    pub evidence: Evidence,
    pub replay_source: Option<Evidence>,
}

pub fn generate_api_client(input: &GenerateApiClientInput) -> Result<GeneratedApiClient, WebError> {
    if input.spec_path.is_some() && input.spec.is_some() {
        return Err(input_error(
            "spec",
            "generate_api_client accepts spec or spec_path, not both.",
        ));
    }
    if input.spec_path.is_none() && input.spec.is_none() {
        return Err(input_error(
            "spec",
            "generate_api_client requires spec or spec_path.",
        ));
    }
    require_absolute("output_directory", &input.output_directory)?;
    if let Some(path) = &input.spec_path {
        require_absolute("spec_path", path)?;
    }
    if let Some(path) = &input.replay_capture_path {
        require_absolute("replay_capture_path", path)?;
    }
    let languages = parse_languages(&input.languages)?;

    let spec = load_spec(input)?;
    let spec_sha = canonical_sha256(&spec)?;
    let package = package_name(input.package_name.as_deref(), &spec);

    let replay_source = if let Some(path) = &input.replay_capture_path {
        Some(crate::api_spec::inspect_capture_for_spec(path)?)
    } else {
        None
    };
    let sdk = build_sdk(&spec, &package)?;
    let samples = if let Some(source) = &replay_source {
        samples_from_evidence(&sdk.metas, source)?
    } else {
        Vec::new()
    };
    let mut files = render_sdk(
        &sdk.model,
        languages.contains(&Language::Python),
        languages.contains(&Language::TypeScript),
    )?;
    let replay_json = pretty_json(&Value::Array(samples))?;
    if languages.contains(&Language::TypeScript) {
        files.push(("typescript/fixtures/replay.json".to_string(), replay_json.clone()));
    }
    if languages.contains(&Language::Python) {
        files.push(("python/fixtures/replay.json".to_string(), replay_json));
    }
    for (_, contents) in &files {
        reject_secrets(contents)?;
    }

    let root = Path::new(&input.output_directory);
    std::fs::create_dir_all(root)?;
    let mut listed = Vec::new();
    for (relative, contents) in &files {
        if relative.split('/').any(|part| part == ".." || part.is_empty()) {
            return Err(WebError::Format(format!(
                "Refusing to write client file '{relative}'."
            )));
        }
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, contents)?;
        listed.push(json!({
            "path": relative,
            "sha256": sha256_hex(contents.as_bytes()),
            "bytes": contents.len(),
        }));
    }
    listed.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or("")
            .cmp(right["path"].as_str().unwrap_or(""))
    });

    let mut links = evidence_ids(&spec);
    if let Some(source) = &replay_source {
        links.insert(source.evidence_id.clone());
    }
    let evidence = build_evidence(input, &package, &spec_sha, &languages, &listed, &links)?;
    let encoded = serde_json::to_string(&evidence)?;
    reject_secrets(&encoded)?;
    Ok(GeneratedApiClient {
        evidence,
        replay_source,
    })
}

fn load_spec(input: &GenerateApiClientInput) -> Result<Value, WebError> {
    let value = if let Some(path) = &input.spec_path {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|err| {
            input_error("spec_path", &format!("OpenAPI document is not JSON: {err}"))
        })?
    } else {
        input
            .spec
            .clone()
            .ok_or_else(|| input_error("spec", "generate_api_client requires spec or spec_path."))?
    };
    as_openapi(value)
}

fn as_openapi(value: Value) -> Result<Value, WebError> {
    if value.get("openapi").and_then(|item| item.as_str()).is_some()
        && value.get("paths").is_some()
    {
        return Ok(value);
    }
    if let Some(inner) = value.get("normalized_result") {
        if inner.get("openapi").and_then(|item| item.as_str()).is_some()
            && inner.get("paths").is_some()
        {
            return Ok(inner.clone());
        }
    }
    Err(input_error(
        "spec",
        "Expected an OpenAPI document with openapi and paths.",
    ))
}

fn parse_languages(values: &[String]) -> Result<BTreeSet<Language>, WebError> {
    if values.is_empty() {
        return Err(input_error(
            "languages",
            "At least one of typescript or python is required.",
        ));
    }
    let mut languages = BTreeSet::new();
    for value in values {
        match value.as_str() {
            "typescript" | "ts" => {
                languages.insert(Language::TypeScript);
            }
            "python" | "py" => {
                languages.insert(Language::Python);
            }
            other => {
                return Err(input_error(
                    "languages",
                    &format!("Unsupported language '{other}'. Use typescript or python."),
                ));
            }
        }
    }
    Ok(languages)
}

fn package_name(requested: Option<&str>, spec: &Value) -> String {
    let raw = requested.unwrap_or_else(|| {
        spec.get("info")
            .and_then(|info| info.get("title"))
            .and_then(|title| title.as_str())
            .unwrap_or("inferred_api")
    });
    slug(raw)
}

fn slug(raw: &str) -> String {
    let mut out = String::new();
    let mut underscore = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            underscore = false;
        } else if !out.is_empty() && !underscore {
            out.push('_');
            underscore = true;
        }
    }
    let mut name = out.trim_matches('_').to_string();
    if name.is_empty() {
        name = "inferred_api".to_string();
    }
    if name.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        name = format!("api_{name}");
    }
    name
}

fn build_evidence(
    input: &GenerateApiClientInput,
    package: &str,
    spec_sha: &str,
    languages: &BTreeSet<Language>,
    files: &[Value],
    links: &BTreeSet<String>,
) -> Result<Evidence, WebError> {
    let lang_names: Vec<&str> = languages.iter().copied().map(Language::as_str).collect();
    let mut parameters = Map::new();
    parameters.insert("languages".to_string(), json!(lang_names));
    parameters.insert(
        "output_directory".to_string(),
        Value::String(input.output_directory.clone()),
    );
    parameters.insert("package_name".to_string(), Value::String(package.to_string()));
    parameters.insert("spec_sha256".to_string(), Value::String(spec_sha.to_string()));
    if let Some(path) = &input.spec_path {
        parameters.insert("spec_path".to_string(), Value::String(path.clone()));
    }
    if let Some(path) = &input.replay_capture_path {
        parameters.insert(
            "replay_capture_path".to_string(),
            Value::String(path.clone()),
        );
    }

    let mut locations = vec![EvidenceLocation::ArtifactPath {
        path: input.output_directory.clone(),
    }];
    if let Some(path) = &input.spec_path {
        locations.push(EvidenceLocation::ArtifactPath { path: path.clone() });
    }
    if let Some(path) = &input.replay_capture_path {
        locations.push(EvidenceLocation::ArtifactPath { path: path.clone() });
    }

    let normalized = json!({
        "languages": lang_names,
        "package_name": package,
        "output_directory": input.output_directory,
        "files": files,
    });
    let subject = input
        .spec_path
        .as_deref()
        .map(file_subject)
        .transpose()?;
    let observation = EvidenceObservation {
        predicate_type: Some("tracewise.api-client".to_string()),
        operation: "generate_api_client".to_string(),
        parameters: Value::Object(parameters),
        normalized_result: normalized,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Inferred),
        authority: Some(EvidenceAuthority::AnalystInference),
        environment: None,
        limitations: Some(vec![
            "Generated types cover only schemas present in the OpenAPI document. Unobserved fields and status codes are not represented.".to_string(),
            "Credential values are not copied into the SDK. Callers supply authentication headers at runtime.".to_string(),
            "Replay tests use redacted captures and mock the transport. They do not contact the network.".to_string(),
        ]),
        locations: Some(locations),
        evidence_links: Some(links.iter().cloned().collect()),
    };
    create_evidence(
        subject,
        EvidenceProvider {
            id: "tracewise.generate-api-client".to_string(),
            name: "Tracewise API client generator".to_string(),
            version: Some("0.1.0".to_string()),
        },
        observation,
    )
    .map_err(WebError::from)
}

fn file_subject(path: &str) -> Result<EvidenceSubject, WebError> {
    let bytes = std::fs::read(path)?;
    let name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("openapi.json");
    Ok(EvidenceSubject {
        name: name.to_string(),
        digest: DigestSha256 {
            sha256: sha256_hex(&bytes),
        },
        format: "file".to_string(),
        architecture: None,
        local_path: path.to_string(),
    })
}

fn evidence_ids(value: &Value) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    collect_evidence_ids(value, &mut ids);
    ids
}

fn collect_evidence_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "evidence_id" {
                    if let Some(id) = child.as_str() {
                        if id.starts_with("ev_") && id.len() == 67 {
                            ids.insert(id.to_string());
                        }
                    }
                }
                collect_evidence_ids(child, ids);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_evidence_ids(child, ids);
            }
        }
        _ => {}
    }
}

fn pretty_json(value: &Value) -> Result<String, WebError> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn reject_secrets(text: &str) -> Result<(), WebError> {
    if text.contains("SECRET-") {
        return Err(WebError::Format(
            "Generated API client contained a credential marker and was discarded.".to_string(),
        ));
    }
    Ok(())
}

fn require_absolute(field: &str, path: &str) -> Result<(), WebError> {
    if Path::new(path).is_absolute() {
        Ok(())
    } else {
        Err(input_error(
            field,
            "Expected an absolute filesystem path on this host.",
        ))
    }
}

fn input_error(field: &str, message: &str) -> WebError {
    WebError::Input {
        operation: "generate_api_client".to_string(),
        path: vec![field.to_string()],
        reason: "invalid_format".to_string(),
        message: message.to_string(),
    }
}
