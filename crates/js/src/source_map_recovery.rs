//! Recover original module text from a version-3 source map.
//!
//! REA's `recover_javascript_sources` shells out to a caller-supplied Wakaru
//! binary (`REA_WAKARU_COMMAND`), which is not part of the repository. This
//! port reads `sourcesContent` with the `sourcemap` crate so the same tool
//! name returns schema-valid Evidence without executing the bundle.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceLocation,
    EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::JsError;
use crate::hash::hash_bytes;
use crate::source_map_load::{load_source_map, token_ranges};

const INPUT_LIMIT: u64 = 64 * 1024 * 1024;
const ENGINE_VERSION: &str = "9.3.2";

pub fn recover_javascript_sources(
    path: &str,
    output_directory: &str,
    extraction_mode: &str,
    rewrite_level: &str,
) -> Result<Evidence, JsError> {
    validate_mode(extraction_mode, rewrite_level)?;
    let input = require_absolute(path, "path")?;
    let output = require_absolute(output_directory, "output_directory")?;
    if output.exists() {
        return Err(JsError::InvalidInput(format!(
            "output_directory must be absent: {output_directory}"
        )));
    }
    let parent = output.parent().ok_or_else(|| {
        JsError::InvalidInput("output_directory parent must exist".into())
    })?;
    if !parent.is_dir() {
        return Err(JsError::InvalidInput(
            "output_directory parent must exist".into(),
        ));
    }
    let bundle_bytes = fs::read(&input)?;
    if bundle_bytes.len() as u64 > INPUT_LIMIT {
        return Err(JsError::InvalidInput("JavaScript input exceeds 64 MiB".into()));
    }
    let bundle_text = std::str::from_utf8(&bundle_bytes)
        .map_err(|_| JsError::InvalidInput("JavaScript input is not valid UTF-8".into()))?;
    let (map_bytes, map_path) = load_source_map(bundle_text, &input)?;
    let map = sourcemap::SourceMap::from_slice(&map_bytes).map_err(|error| {
        JsError::InvalidInput(format!("source map could not be parsed: {error}"))
    })?;
    if map.get_source_count() == 0 {
        return Err(JsError::InvalidInput("source map does not name any sources".into()));
    }

    let published = recover_tree(&input, &output, &bundle_bytes, &map_bytes, &map_path, &map, extraction_mode, rewrite_level);
    if published.is_err() {
        let _ = fs::remove_dir_all(&output);
    }
    let result = published?;
    let limitations = string_list(result.get("limitations"))?;
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    let sha = result["source"]["sha256"].as_str().unwrap_or("").to_string();
    let mut locations = vec![EvidenceLocation::ArtifactPath { path: path.to_string() }];
    if let Some(modules) = result.get("modules").and_then(|v| v.as_array()) {
        for module in modules {
            if let Some(artifact_path) = module.pointer("/artifact/path").and_then(|v| v.as_str()) {
                locations.push(EvidenceLocation::ArtifactPath {
                    path: artifact_path.to_string(),
                });
            }
        }
    }
    create_evidence(
        Some(EvidenceSubject {
            name,
            digest: tracewise_domain::evidence::DigestSha256 { sha256: sha },
            format: "javascript".to_string(),
            architecture: None,
            local_path: path.to_string(),
        }),
        EvidenceProvider {
            id: "sourcemap".to_string(),
            name: "sourcemap".to_string(),
            version: Some(ENGINE_VERSION.to_string()),
        },
        EvidenceObservation {
            predicate_type: None,
            operation: "recover_javascript_sources".to_string(),
            parameters: json!({
                "path": path,
                "output_directory": output_directory,
                "extraction_mode": extraction_mode,
                "rewrite_level": rewrite_level,
            }),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(limitations),
            locations: Some(locations),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(JsError::from)
}

#[allow(clippy::too_many_arguments)]
fn recover_tree(
    input: &Path,
    output: &Path,
    bundle_bytes: &[u8],
    map_bytes: &[u8],
    map_path: &Path,
    map: &sourcemap::SourceMap,
    extraction_mode: &str,
    rewrite_level: &str,
) -> Result<Value, JsError> {
    fs::create_dir(output)?;
    fs::create_dir(output.join("inputs"))?;
    fs::create_dir(output.join("modules"))?;
    fs::create_dir(output.join("reports"))?;
    let bundle_copy = output.join("inputs/bundle.js");
    fs::write(&bundle_copy, bundle_bytes)?;
    let bundle_file = file_record(&bundle_copy, bundle_bytes)?;
    let bundle_sha = bundle_file["sha256"].as_str().unwrap_or("").to_string();
    let bundle_len = bundle_file["bytes"].clone();
    let map_file = file_record(map_path, map_bytes)?;
    let ranges = token_ranges(std::str::from_utf8(bundle_bytes).unwrap_or(""), map);
    let mut modules = Vec::new();
    let mut warnings = Vec::new();
    let mut failed = 0i64;
    let mut used_names = BTreeMap::<String, usize>::new();
    let total = map.get_source_count() as i64;
    for index in 0..map.get_source_count() {
        let source_name = map.get_source(index).unwrap_or("").to_string();
        let Some(contents) = map.get_source_contents(index) else {
            failed += 1;
            warnings.push(json!({
                "filename": source_name,
                "kind": "missing-sources-content",
                "is_error": true,
                "message": "Source map entry has no sourcesContent; the original text was not recovered.",
            }));
            continue;
        };
        let relative = unique_module_path(&source_name, index, &mut used_names);
        let artifact_path = output.join("modules").join(&relative);
        if let Some(parent) = artifact_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = contents.as_bytes();
        fs::write(&artifact_path, bytes)?;
        let artifact = file_record(&artifact_path, bytes)?;
        let byte_ranges = ranges.get(&index).cloned().unwrap_or_default();
        modules.push(json!({
            "reported_filename": relative,
            "reported_status": "recovered",
            "artifact": artifact,
            "source_map": Value::Null,
            "provenance": {
                "reported_input": bundle_copy.display().to_string(),
                "original_path": input.display().to_string(),
                "original_sha256": bundle_sha.as_str(),
                "extraction": "sources-content",
                "byte_ranges": byte_ranges,
                "context_byte_ranges": [],
                "range_semantics": "half-open-utf8-bytes",
            },
        }));
    }
    let report_body = json!({
        "detected_formats": ["source-map"],
        "safety": "no-execution",
        "modules": modules.iter().map(|module| json!({
            "filename": module["reported_filename"],
            "kind": "javascript",
            "status": module["reported_status"],
        })).collect::<Vec<_>>(),
        "warnings": warnings,
        "total": total,
        "failed": failed,
        "elapsed_ms": 0,
    });
    let report_bytes = serde_json::to_vec_pretty(&report_body)?;
    let report_path = output.join("reports/stdout.json");
    fs::write(&report_path, &report_bytes)?;
    let provenance_body = json!({
        "format": "source-map",
        "strategy": "sources-content",
        "modules": modules.iter().map(|module| {
            (module["reported_filename"].as_str().unwrap_or("").to_string(), json!({
                "input": bundle_copy.display().to_string(),
                "ranges": module["provenance"]["byte_ranges"],
                "extraction": "sources-content",
            }))
        }).collect::<serde_json::Map<String, Value>>(),
    });
    let provenance_bytes = serde_json::to_vec_pretty(&provenance_body)?;
    let provenance_path = output.join("reports/provenance.json");
    fs::write(&provenance_path, &provenance_bytes)?;
    let limitations = vec![
        "Recovered sources are copied from source map sourcesContent; original names beyond the map and runtime equivalence are not established.".to_string(),
        "Extraction ranges are half-open UTF-8 byte offsets of generated tokens that name each original source, not rewritten line positions.".to_string(),
        "No Wakaru process was executed. rewrite_level is recorded and not applied because sourcesContent is copied verbatim.".to_string(),
        "No input or recovered application code is executed.".to_string(),
    ];
    let analysis_input = if modules.is_empty() {
        Value::Null
    } else {
        json!({
            "input_path": output.join("modules").display().to_string(),
            "format": "directory",
        })
    };
    let details = json!({
        "source": {
            "path": input.display().to_string(),
            "sha256": bundle_sha,
            "bytes": bundle_len,
            "snapshot_path": bundle_copy.display().to_string(),
            "published_copy": bundle_file,
        },
        "engine": {
            "id": "sourcemap",
            "version": ENGINE_VERSION,
            "executable": map_file,
            "audited_source_revision": ENGINE_VERSION,
            "executed_source_revision": Value::Null,
        },
        "options": {
            "extraction_mode": extraction_mode,
            "rewrite_level": rewrite_level,
        },
        "status": if failed == 0 { "complete" } else { "partial" },
        "detected_formats": ["source-map"],
        "reported_safety": "no-execution",
        "reported_strategy": "sources-content",
        "reported_format": "source-map",
        "total": total,
        "failed": failed,
        "modules": modules,
        "warnings": warnings,
        "report": file_record(&report_path, &report_bytes)?,
        "provenance": file_record(&provenance_path, &provenance_bytes)?,
        "analysis_input": analysis_input,
        "runtime_equivalence": "unknown",
        "limitations": limitations,
    });
    let manifest_bytes = format!("{}\n", serde_json::to_string_pretty(&details)?).into_bytes();
    let manifest_path = output.join("manifest.json");
    fs::write(&manifest_path, &manifest_bytes)?;
    let mut result = details;
    result["manifest"] = file_record(&manifest_path, &manifest_bytes)?;
    Ok(result)
}

fn unique_module_path(source_name: &str, index: u32, used: &mut BTreeMap<String, usize>) -> String {
    let mut relative = sanitize_source_name(source_name);
    if relative.is_empty() {
        relative = format!("recovered-{index}.js");
    }
    let count = used.entry(relative.clone()).or_insert(0);
    if *count == 0 {
        *count = 1;
        return relative;
    }
    *count += 1;
    let suffix = *count;
    match relative.rfind('.') {
        Some(dot) if !relative[dot..].contains('/') => {
            format!("{}-{suffix}{}", &relative[..dot], &relative[dot..])
        }
        _ => format!("{relative}-{suffix}"),
    }
}

fn sanitize_source_name(source_name: &str) -> String {
    let mut text = source_name.replace('\\', "/");
    if let Some(index) = text.find(['?', '#']) {
        text.truncate(index);
    }
    if let Some(index) = text.find("://") {
        text = text[index + 3..].trim_start_matches('/').to_string();
    }
    let mut parts = Vec::new();
    for part in text.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\0') {
            continue;
        }
        parts.push(part);
    }
    parts.join("/")
}

fn file_record(path: &Path, bytes: &[u8]) -> Result<Value, JsError> {
    let hashed = hash_bytes(bytes);
    Ok(json!({
        "path": path.display().to_string(),
        "sha256": hashed.sha256,
        "bytes": hashed.bytes,
    }))
}

fn validate_mode(extraction_mode: &str, rewrite_level: &str) -> Result<(), JsError> {
    if !matches!(extraction_mode, "structural" | "heuristic" | "inspection") {
        return Err(JsError::InvalidInput(
            "extraction_mode must be structural, heuristic, or inspection".into(),
        ));
    }
    if !matches!(rewrite_level, "minimal" | "standard" | "aggressive") {
        return Err(JsError::InvalidInput(
            "rewrite_level must be minimal, standard, or aggressive".into(),
        ));
    }
    Ok(())
}

fn require_absolute(path: &str, field: &str) -> Result<PathBuf, JsError> {
    if path.is_empty() || path.contains('\0') || !path.starts_with('/') {
        return Err(JsError::InvalidInput(format!(
            "{field} must be an absolute filesystem path"
        )));
    }
    Ok(PathBuf::from(path))
}

fn string_list(value: Option<&Value>) -> Result<Vec<String>, JsError> {
    let Some(items) = value.and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect())
}
