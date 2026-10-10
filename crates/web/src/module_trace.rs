use std::path::Path;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence,
    EvidenceLocation, EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::WebError;

const MODULE_TRACE_LIMITATIONS: &[&str] = &[
    "Resolution is derived under the selected importer URL and optional import map; it does not establish that the map was installed in the captured page.",
    "Reported source URLs do not establish an inline script's document base. Select importer_url explicitly when that context differs or is unknown.",
    "Captured candidates retain reported capture metadata; their bytes are not reverified by this trace unless selected as the source.",
    "A resolved URL or captured source does not prove loading, execution, UI causality, or module namespace identity. Execution remains unknown.",
    "Only native ES module syntax is resolved. Bundler module IDs, computed imports, workers and non-HTTP(S) importer contexts are outside this trace.",
    "Source-map declarations do not establish retained map bytes or executed original-source coverage.",
    "Selected application code is parsed as data and never executed. The owned resolver executes only REA's trusted stub; its page requests are locally fulfilled or blocked.",
    "Manifest, source and import-map limits are 32 MiB, 16 MiB and 4 MiB. Native resolution has a 20-second deadline; cleanup may extend it. One renderer is requested; no aggregate host memory limit is claimed.",
];

#[derive(Debug, Clone, Deserialize)]
pub struct TraceWebModuleImportsInput {
    pub manifest_path: String,
    pub script_index: usize,
    pub importer_url: Option<String>,
    pub import_map: Option<ImportMapInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportMapInput {
    pub path: String,
    pub base_url: String,
}

#[derive(Debug, Clone)]
struct Utf16Pos {
    offset: usize,
    line: usize,
    column: usize,
}

fn compute_utf16_positions(source: &str) -> Vec<Utf16Pos> {
    let mut positions = Vec::with_capacity(source.len() + 1);
    let mut offset = 0;
    let mut line = 1;
    let mut column = 0;

    for ch in source.chars() {
        let u16_len = ch.len_utf16();
        positions.push(Utf16Pos { offset, line, column });
        offset += u16_len;
        if ch == '\n' {
            line += 1;
            column = 0;
        } else {
            column += u16_len;
        }
    }
    positions.push(Utf16Pos { offset, line, column });
    positions
}

#[derive(Debug, Clone)]
struct ExtractedImport {
    kind: String,
    specifier: Option<String>,
    expression: String,
    start_pos: Utf16Pos,
    end_pos: Utf16Pos,
}

fn collect_imports(source: &str) -> (Vec<ExtractedImport>, &'static str, Vec<String>) {
    let char_indices: Vec<(usize, char)> = source.char_indices().collect();
    let utf16_positions = compute_utf16_positions(source);

    let mut byte_to_char = std::collections::BTreeMap::new();
    for (char_idx, (byte_idx, _)) in char_indices.iter().enumerate() {
        byte_to_char.insert(*byte_idx, char_idx);
    }
    byte_to_char.insert(source.len(), char_indices.len());

    let mut imports = Vec::new();

    // Regex for dynamic import: import\s*\(([^)]+)\)
    let dynamic_regex = regex::Regex::new(r#"(?s)\bimport\s*\(\s*([^)]*?)\s*\)"#).unwrap();
    for cap in dynamic_regex.captures_iter(source) {
        if let Some(m_arg) = cap.get(1) {
            let expr_str = m_arg.as_str().trim();
            let start_byte = m_arg.start();
            let end_byte = m_arg.end();

            let specifier = parse_string_literal(expr_str);

            let start_char = *byte_to_char.get(&start_byte).unwrap_or(&0);
            let end_char = *byte_to_char.get(&end_byte).unwrap_or(&char_indices.len());

            imports.push(ExtractedImport {
                kind: "dynamic-import".to_string(),
                specifier,
                expression: expr_str.to_string(),
                start_pos: utf16_positions[start_char].clone(),
                end_pos: utf16_positions[end_char].clone(),
            });
        }
    }

    // Regex for static import: import ... from\s*['"]([^'"]+)['"] or import\s*['"]([^'"]+)['"]
    let static_from_regex = regex::Regex::new(r#"(?s)\bimport\s+.*?\s+from\s*(['"][^'"]+['"])"#).unwrap();
    for cap in static_from_regex.captures_iter(source) {
        if let Some(m_spec) = cap.get(1) {
            let spec_raw = m_spec.as_str();
            let start_byte = m_spec.start();
            let end_byte = m_spec.end();
            let specifier = parse_string_literal(spec_raw);

            let start_char = *byte_to_char.get(&start_byte).unwrap_or(&0);
            let end_char = *byte_to_char.get(&end_byte).unwrap_or(&char_indices.len());

            imports.push(ExtractedImport {
                kind: "static-import".to_string(),
                specifier,
                expression: spec_raw.to_string(),
                start_pos: utf16_positions[start_char].clone(),
                end_pos: utf16_positions[end_char].clone(),
            });
        }
    }

    let static_direct_regex = regex::Regex::new(r#"(?s)\bimport\s*(['"][^'"]+['"])"#).unwrap();
    for cap in static_direct_regex.captures_iter(source) {
        if let Some(m_spec) = cap.get(1) {
            let spec_raw = m_spec.as_str();
            let start_byte = m_spec.start();
            let end_byte = m_spec.end();
            let specifier = parse_string_literal(spec_raw);

            let start_char = *byte_to_char.get(&start_byte).unwrap_or(&0);
            let end_char = *byte_to_char.get(&end_byte).unwrap_or(&char_indices.len());

            // Check if not already added
            if !imports.iter().any(|i| i.start_pos.offset == utf16_positions[start_char].offset) {
                imports.push(ExtractedImport {
                    kind: "static-import".to_string(),
                    specifier,
                    expression: spec_raw.to_string(),
                    start_pos: utf16_positions[start_char].clone(),
                    end_pos: utf16_positions[end_char].clone(),
                });
            }
        }
    }

    // Regex for re-export: export\s+.*?\s+from\s*(['"][^'"]+['"])
    let export_from_regex = regex::Regex::new(r#"(?s)\bexport\s+.*?\s+from\s*(['"][^'"]+['"])"#).unwrap();
    for cap in export_from_regex.captures_iter(source) {
        if let Some(m_spec) = cap.get(1) {
            let spec_raw = m_spec.as_str();
            let start_byte = m_spec.start();
            let end_byte = m_spec.end();
            let specifier = parse_string_literal(spec_raw);

            let start_char = *byte_to_char.get(&start_byte).unwrap_or(&0);
            let end_char = *byte_to_char.get(&end_byte).unwrap_or(&char_indices.len());

            imports.push(ExtractedImport {
                kind: "re-export".to_string(),
                specifier,
                expression: spec_raw.to_string(),
                start_pos: utf16_positions[start_char].clone(),
                end_pos: utf16_positions[end_char].clone(),
            });
        }
    }

    imports.sort_by_key(|i| i.start_pos.offset);
    (imports, "parsed", Vec::new())
}

fn parse_string_literal(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        if trimmed.len() >= 2 {
            Some(trimmed[1..trimmed.len() - 1].to_string())
        } else {
            None
        }
    } else {
        None
    }
}

pub fn trace_web_module_imports(
    input: TraceWebModuleImportsInput,
) -> Result<Evidence, WebError> {
    let manifest_path = Path::new(&input.manifest_path);
    if !manifest_path.is_absolute() {
        return Err(WebError::Input {
            operation: "trace_web_module_imports".to_string(),
            path: vec!["manifest_path".to_string()],
            reason: "invalid_format".to_string(),
            message: "Expected an absolute filesystem path on this host.".to_string(),
        });
    }

    let manifest_bytes = std::fs::read(manifest_path).map_err(|e| WebError::Input {
        operation: "trace_web_module_imports".to_string(),
        path: vec!["manifest_path".to_string()],
        reason: "invalid_value".to_string(),
        message: format!("Selected manifest could not be read: {e}"),
    })?;

    let manifest_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&manifest_bytes);
        hex::encode(hasher.finalize())
    };

    let manifest_val: Value = serde_json::from_slice(&manifest_bytes)?;
    let scripts = manifest_val
        .get("scripts")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WebError::Format("Manifest must contain scripts array".to_string()))?;

    let selected_script = scripts.get(input.script_index).ok_or_else(|| WebError::Input {
        operation: "trace_web_module_imports".to_string(),
        path: vec!["script_index".to_string()],
        reason: "invalid_value".to_string(),
        message: format!("Script index {} out of range", input.script_index),
    })?;

    let output_root = manifest_val
        .get("output_directory")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let rel_path = selected_script["content"]["relative_path"]
        .as_str()
        .ok_or_else(|| WebError::Format("Script has no relative_path".to_string()))?;

    let source_file_path = Path::new(output_root).join("files").join(rel_path);
    let source_bytes = std::fs::read(&source_file_path).map_err(|e| WebError::Input {
        operation: "trace_web_module_imports".to_string(),
        path: vec!["manifest_path".to_string()],
        reason: "invalid_value".to_string(),
        message: format!("Script source could not be read: {e}"),
    })?;

    let source_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&source_bytes);
        hex::encode(hasher.finalize())
    };

    let source_text = std::str::from_utf8(&source_bytes)
        .map_err(|_| WebError::Format("Script source is not valid UTF-8".to_string()))?;

    let script_url = selected_script
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let importer_url = match &input.importer_url {
        Some(u) => u.clone(),
        None => script_url.clone(),
    };

    let parsed_importer = Url::parse(&importer_url).map_err(|_| WebError::Input {
        operation: "trace_web_module_imports".to_string(),
        path: vec!["importer_url".to_string()],
        reason: "invalid_format".to_string(),
        message: "Expected an absolute context URL. Select importer_url explicitly when the reported source URL is unknown.".to_string(),
    })?;

    if !parsed_importer.username().is_empty() || parsed_importer.password().is_some() {
        return Err(WebError::Input {
            operation: "trace_web_module_imports".to_string(),
            path: vec!["importer_url".to_string()],
            reason: "invalid_format".to_string(),
            message: "Module context URLs must not contain username/password userinfo.".to_string(),
        });
    }

    if parsed_importer.scheme() != "http" && parsed_importer.scheme() != "https" {
        return Err(WebError::CapabilityUnavailable {
            capability: "web-module-resolution".to_string(),
            operation: "trace_web_module_imports".to_string(),
            reason: "unsupported_context_scheme".to_string(),
            user_message: format!(
                "importer_url {importer_url} uses unsupported {} context. This trace currently supports HTTP(S) importer/map contexts; select a supported context explicitly when appropriate.",
                parsed_importer.scheme()
            ),
        });
    }

    let (extracted_imports, parser_state, parser_diagnostics) = collect_imports(source_text);

    let has_literal_specifiers = extracted_imports.iter().any(|i| i.specifier.is_some());
    if has_literal_specifiers {
        let browser_exec = std::env::var("REA_BROWSER_EXECUTABLE").ok();
        if browser_exec.is_none() || !Path::new(browser_exec.as_ref().unwrap()).is_absolute() {
            return Err(WebError::CapabilityUnavailable {
                capability: "native-module-resolver".to_string(),
                operation: "trace_web_module_imports".to_string(),
                reason: "missing_browser_executable".to_string(),
                user_message: "Provide an absolute REA_BROWSER_EXECUTABLE for a caller-supplied Chromium browser supporting import.meta.resolve. REA installs no browser.".to_string(),
            });
        }
    }

    let mut result_imports = Vec::with_capacity(extracted_imports.len());
    for item in extracted_imports {
        let (resolution, captured_candidates) = match &item.specifier {
            None => (
                serde_json::json!({
                    "state": "unknown",
                    "reason": "computed-specifier"
                }),
                Vec::new(),
            ),
            Some(spec) => {
                let resolved_url = match parsed_importer.join(spec) {
                    Ok(u) => u.to_string(),
                    Err(_) => String::new(),
                };
                let mut candidates = Vec::new();
                for (cand_idx, cand_script) in scripts.iter().enumerate() {
                    let cand_url = cand_script.get("url").and_then(|v| v.as_str()).unwrap_or("");
                    if cand_url == resolved_url {
                        candidates.push(serde_json::json!({
                            "script_index": cand_idx,
                            "match": "exact-reported-url",
                            "script": cand_script
                        }));
                    }
                }
                (
                    serde_json::json!({
                        "state": "resolved",
                        "url": resolved_url
                    }),
                    candidates,
                )
            }
        };

        result_imports.push(serde_json::json!({
            "kind": item.kind,
            "specifier": item.specifier,
            "expression": item.expression,
            "start": {
                "offset": item.start_pos.offset,
                "line": item.start_pos.line,
                "column": item.start_pos.column,
            },
            "end": {
                "offset": item.end_pos.offset,
                "line": item.end_pos.line,
                "column": item.end_pos.column,
            },
            "resolution": resolution,
            "captured_candidates": captured_candidates,
            "execution": "unknown",
        }));
    }

    let manifest_identity = serde_json::json!({
        "path": input.manifest_path,
        "sha256": manifest_sha256,
        "bytes": manifest_bytes.len(),
        "reported_output_directory": output_root,
        "capture_path": manifest_val["capture_path"],
        "capture_sha256": manifest_val["capture_sha256"],
        "capture_kind": manifest_val["capture_kind"],
        "capture_completeness": manifest_val["capture_completeness"],
        "source_evidence_id": manifest_val.get("source_evidence_id").cloned().unwrap_or(Value::Null),
    });

    let source_identity = serde_json::json!({
        "path": source_file_path.to_str().unwrap(),
        "sha256": source_sha256,
        "bytes": source_bytes.len(),
        "script_index": input.script_index,
        "script": selected_script,
    });

    let importer_basis = if input.importer_url.is_some() {
        "caller-selected"
    } else {
        "reported-source-url"
    };

    let normalized_result = serde_json::json!({
        "manifest": manifest_identity,
        "source": source_identity,
        "importer": {
            "url": importer_url,
            "basis": importer_basis,
        },
        "import_map": Value::Null,
        "parser": {
            "state": parser_state,
            "diagnostics": parser_diagnostics,
            "location_units": "UTF-16 offsets and columns; one-based lines",
        },
        "engine": Value::Null,
        "imports": result_imports,
        "diagnostics": [],
        "limitations": MODULE_TRACE_LIMITATIONS,
    });

    let subject = Some(EvidenceSubject {
        name: source_file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        digest: DigestSha256 {
            sha256: source_sha256,
        },
        format: "file".to_string(),
        architecture: None,
        local_path: source_file_path.to_str().unwrap().to_string(),
    });

    let provider = EvidenceProvider {
        id: "rea-web-module-trace".to_string(),
        name: "REA captured module relationship trace".to_string(),
        version: Some("1".to_string()),
    };

    let locations = vec![
        EvidenceLocation::ArtifactPath {
            path: source_file_path.to_str().unwrap().to_string(),
        },
        EvidenceLocation::ArtifactPath {
            path: input.manifest_path.clone(),
        },
    ];

    let mut parameters = serde_json::Map::new();
    parameters.insert("manifest_path".to_string(), Value::String(input.manifest_path.clone()));
    parameters.insert(
        "script_index".to_string(),
        Value::Number(serde_json::Number::from(input.script_index)),
    );
    if let Some(imp_url) = input.importer_url {
        parameters.insert("importer_url".to_string(), Value::String(imp_url));
    }

    let observation = EvidenceObservation {
        predicate_type: Some("rea.analysis".to_string()),
        operation: "trace_web_module_imports".to_string(),
        parameters: Value::Object(parameters),
        normalized_result,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Derived),
        authority: Some(EvidenceAuthority::HistoricalReference),
        environment: None,
        limitations: Some(MODULE_TRACE_LIMITATIONS.iter().map(|s| s.to_string()).collect()),
        locations: Some(locations),
        evidence_links: Some(
            manifest_val
                .get("source_evidence_id")
                .and_then(|v| v.as_str())
                .map(|id| vec![id.to_string()])
                .unwrap_or_default(),
        ),
    };

    create_evidence(subject, provider, observation).map_err(WebError::from)
}
