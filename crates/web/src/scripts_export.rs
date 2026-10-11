use std::collections::{HashMap, HashSet};
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence,
    EvidenceLocation, EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::WebError;

const EXPORT_LIMITATIONS: &[&str] = &[
    "Only script bytes retained in this capture are exported. Sources are not refetched or executed, and a response or Debugger source does not prove execution.",
    "Ordinary unambiguous URL paths preserve relative module layouts by origin, including case-distinct spellings. Query variants, exact path collisions, file/directory prefixes, inline sources, and unrepresentable paths are isolated. A case-distinct pair is isolated only when the destination filesystem cannot store both spellings; the record names that pair. Browser module relationships of isolated paths remain unknown.",
    "Local JavaScript analysis does not implement browser import maps, root-relative URL resolution, remote URL loading, or browser runtime behavior. It may strip import queries and fragments; isolated variants are not canonical targets.",
    "Source-map declarations are retained as metadata. No source maps or missing dependencies are fetched or reconstructed.",
    "Captured response bytes are browser-decoded bytes; Debugger sources are the exposed text encoded as UTF-8. Redacted bytes are exported exactly as retained, and may no longer parse as JavaScript.",
];

#[derive(Debug, Clone, Deserialize)]
pub struct ExportWebScriptsInput {
    pub capture_path: String,
    pub output_directory: String,
}

#[derive(Debug, Clone)]
struct CapturedScript {
    source: Value,
    url: String,
    content: ScriptContent,
}

#[derive(Debug, Clone)]
enum ScriptContent {
    Captured {
        bytes: Vec<u8>,
        sha256: String,
        media_type: String,
        redacted: Value,
        representation: String,
    },
    Unavailable {
        reason: String,
        message: String,
    },
}

pub fn export_web_scripts(input: ExportWebScriptsInput) -> Result<Evidence, WebError> {
    let capture_path = Path::new(&input.capture_path);
    let output_directory = Path::new(&input.output_directory);

    if !capture_path.is_absolute() || !output_directory.is_absolute() {
        return Err(WebError::Input {
            operation: "export_web_scripts".to_string(),
            path: vec![],
            reason: "invalid_format".to_string(),
            message: "capture_path and output_directory must be absolute filesystem paths on this host.".to_string(),
        });
    }

    if output_directory.exists() {
        return Err(WebError::Input {
            operation: "export_web_scripts".to_string(),
            path: vec!["output_directory".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("Destination directory already exists: {}", output_directory.display()),
        });
    }

    let capture_bytes = std::fs::read(capture_path).map_err(|e| WebError::Input {
        operation: "export_web_scripts".to_string(),
        path: vec!["capture_path".to_string()],
        reason: "invalid_value".to_string(),
        message: format!("Selected capture could not be read: {e}"),
    })?;

    let capture_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&capture_bytes);
        hex::encode(hasher.finalize())
    };

    let text = std::str::from_utf8(&capture_bytes).map_err(|_| WebError::Input {
        operation: "export_web_scripts".to_string(),
        path: vec!["capture_path".to_string()],
        reason: "invalid_format".to_string(),
        message: "Capture is not valid UTF-8 JSON evidence.".to_string(),
    })?;

    let root_val: Value = serde_json::from_str(text).map_err(|e| WebError::Input {
        operation: "export_web_scripts".to_string(),
        path: vec!["capture_path".to_string()],
        reason: "invalid_format".to_string(),
        message: format!("Capture is not valid UTF-8 JSON evidence: {e}"),
    })?;

    let extracted = extract_scripts_from_capture(&root_val)?;

    let planned = plan_web_script_export(&extracted.captured_scripts);

    std::fs::create_dir_all(output_directory)?;
    let files_dir = output_directory.join("files");

    let mut exported_records = Vec::with_capacity(planned.len());
    let mut any_exported = false;

    for item in planned {
        let rel_path_opt = item.record["content"]["relative_path"].as_str().map(|s| s.to_string());
        if let (Some(rel_path), ScriptContent::Captured { bytes, .. }) = (&rel_path_opt, &item.script.content) {
            let target_file = files_dir.join(rel_path);
            if let Some(parent) = target_file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target_file, bytes)?;
            any_exported = true;
        }
        exported_records.push(item.record);
    }

    let mut limitations = extracted.limitations;
    limitations.extend(EXPORT_LIMITATIONS.iter().map(|s| s.to_string()));
    if !any_exported {
        limitations.push(
            "No script bytes were exportable. Include script sources in inspect_web_page or select response_body in capture_browser_scenario, then capture again.".to_string(),
        );
    }

    let analysis_input = if any_exported {
        Some(serde_json::json!({
            "input_path": files_dir.to_str().unwrap(),
            "format": "directory"
        }))
    } else {
        None
    };

    let manifest_val = serde_json::json!({
        "capture_path": input.capture_path,
        "capture_sha256": capture_sha256,
        "capture_kind": extracted.capture_kind,
        "source_evidence_id": extracted.source_evidence_id,
        "capture_completeness": extracted.capture_completeness,
        "output_directory": input.output_directory,
        "analysis_input": analysis_input,
        "scripts": exported_records,
        "limitations": limitations,
    });

    let manifest_str = format!("{}\n", serde_json::to_string_pretty(&manifest_val)?);
    let manifest_bytes = manifest_str.as_bytes();
    let manifest_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(manifest_bytes);
        hex::encode(hasher.finalize())
    };

    let manifest_file_path = output_directory.join("manifest.json");
    std::fs::write(&manifest_file_path, manifest_bytes)?;

    let mut normalized_result = manifest_val;
    normalized_result.as_object_mut().unwrap().insert(
        "manifest".to_string(),
        serde_json::json!({
            "path": manifest_file_path.to_str().unwrap(),
            "sha256": manifest_sha256,
            "bytes": manifest_bytes.len(),
        }),
    );

    let subject = Some(EvidenceSubject {
        name: capture_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        digest: DigestSha256 {
            sha256: capture_sha256,
        },
        format: "file".to_string(),
        architecture: None,
        local_path: input.capture_path.clone(),
    });

    let provider = EvidenceProvider {
        id: "rea-web-script-export".to_string(),
        name: "REA captured script export".to_string(),
        version: Some("1".to_string()),
    };

    let observation = EvidenceObservation {
        predicate_type: Some("rea.web-script-export".to_string()),
        operation: "export_web_scripts".to_string(),
        parameters: serde_json::json!({
            "capture_path": input.capture_path,
            "output_directory": input.output_directory,
        }),
        normalized_result,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Derived),
        authority: Some(EvidenceAuthority::HistoricalReference),
        environment: None,
        limitations: Some(limitations),
        locations: Some(vec![EvidenceLocation::ArtifactPath {
            path: manifest_file_path.to_str().unwrap().to_string(),
        }]),
        evidence_links: Some(
            extracted
                .source_evidence_id
                .map(|id| vec![id])
                .unwrap_or_default(),
        ),
    };

    create_evidence(subject, provider, observation).map_err(WebError::from)
}

struct ExtractedCapture {
    capture_kind: String,
    capture_completeness: Value,
    source_evidence_id: Option<String>,
    captured_scripts: Vec<CapturedScript>,
    limitations: Vec<String>,
}

fn extract_scripts_from_capture(
    raw: &Value,
) -> Result<ExtractedCapture, WebError> {
    let (target, source_evidence_id) = if let Some(op) = raw.get("operation").and_then(|v| v.as_str()) {
        let ev_id = raw.get("evidence_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let norm = raw.get("normalized_result").unwrap_or(raw);
        ((op, norm), ev_id)
    } else {
        let op = if raw.get("scripts").is_some() {
            "inspect_web_page"
        } else if raw.get("events").is_some() {
            "capture_browser_scenario"
        } else {
            ""
        };
        ((op, raw), None)
    };

    let ((op, val), ev_id) = (target, source_evidence_id);

    if op == "inspect_web_page" || val.get("scripts").is_some() {
        let scripts_val = val
            .get("scripts")
            .ok_or_else(|| WebError::Format("Missing scripts in inspect_web_page".to_string()))?;
        let items = scripts_val
            .get("items")
            .and_then(|v| v.as_array())
            .ok_or_else(|| WebError::Format("scripts.items must be an array".to_string()))?;

        let completeness = val.get("completeness").cloned().unwrap_or(Value::Null);
        let limitations = val
            .get("limitations")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let mut captured = Vec::with_capacity(items.len());
        for script in items {
            let script_key = script.get("script_key").and_then(|v| v.as_str()).unwrap_or("");
            let frame_id = script.get("frame_id").cloned().unwrap_or(Value::Null);
            let is_module = script.get("is_module").cloned().unwrap_or(Value::Null);
            let language = script.get("language").cloned().unwrap_or(Value::Null);
            let source_map_url = script.get("source_map_url").cloned().unwrap_or(Value::Null);
            let url = script.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();

            let source_val = serde_json::json!({
                "kind": "page-script",
                "script_key": script_key,
                "frame_id": frame_id,
                "is_module": is_module,
                "language": language,
                "source_map_url": source_map_url,
            });

            let src_obj = script.get("source").and_then(|v| v.as_object());
            let included = src_obj
                .and_then(|s| s.get("included"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let lang_str = language.as_str();
            let content = if !included {
                let reason = src_obj
                    .and_then(|s| s.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("source-not-included");
                ScriptContent::Unavailable {
                    reason: reason.to_string(),
                    message: "Debugger source was not included.".to_string(),
                }
            } else if lang_str.is_some() && lang_str != Some("JavaScript") {
                let l = lang_str.unwrap();
                ScriptContent::Unavailable {
                    reason: "unsupported-language".to_string(),
                    message: format!("Debugger reported language {l}; JavaScript export was not inferred."),
                }
            } else {
                let art = src_obj.and_then(|s| s.get("artifact"));
                let text = art.and_then(|a| a.get("text")).and_then(|v| v.as_str()).unwrap_or("");
                let sha = art.and_then(|a| a.get("sha256")).and_then(|v| v.as_str()).unwrap_or("");
                let media = art.and_then(|a| a.get("media_type")).and_then(|v| v.as_str()).unwrap_or("application/javascript");
                ScriptContent::Captured {
                    bytes: text.as_bytes().to_vec(),
                    sha256: sha.to_string(),
                    media_type: media.to_string(),
                    redacted: Value::Null,
                    representation: "debugger-source-utf8".to_string(),
                }
            };

            captured.push(CapturedScript {
                source: source_val,
                url,
                content,
            });
        }

        Ok(ExtractedCapture {
            capture_kind: "page-inspection".to_string(),
            capture_completeness: completeness,
            source_evidence_id: ev_id,
            captured_scripts: captured,
            limitations,
        })
    } else {
        Err(WebError::Input {
            operation: "export_web_scripts".to_string(),
            path: vec!["capture_path".to_string()],
            reason: "invalid_format".to_string(),
            message: "Expected a valid inspect_web_page or capture_browser_scenario capture, with retained script sources or response bytes. Evidence envelopes must have a matching operation and semantic identifier.".to_string(),
        })
    }
}

struct PlannedItem {
    script: CapturedScript,
    record: Value,
}

struct Candidate {
    path: Option<String>,
    reason: Option<String>,
}

fn candidate_path(script: &CapturedScript) -> Candidate {
    let url = match Url::parse(&script.url) {
        Ok(u) => u,
        Err(_) => {
            return Candidate {
                path: None,
                reason: Some("Source has no absolute HTTP URL (for example an inline script).".to_string()),
            };
        }
    };

    if url.scheme() != "http" && url.scheme() != "https" {
        return Candidate {
            path: None,
            reason: Some("Source URL scheme has no local module layout mapping.".to_string()),
        };
    }

    let path_str = url.path().trim_start_matches('/');
    let parts: Vec<&str> = path_str.split('/').collect();

    let portable_regex = Regex::new(r"^[A-Za-z0-9_~.-]+$").unwrap();
    let reserved_regex = Regex::new(r"(?i)^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)").unwrap();

    let ends_with_js = path_str.ends_with(".js") || path_str.ends_with(".mjs") || path_str.ends_with(".cjs");
    let valid_parts = parts.iter().all(|part| {
        portable_regex.is_match(part)
            && *part != "."
            && *part != ".."
            && !part.ends_with('.')
            && !reserved_regex.is_match(part)
    });

    if !ends_with_js || !valid_parts {
        return Candidate {
            path: None,
            reason: Some("URL path is not an ordinary portable JavaScript module path.".to_string()),
        };
    }

    let origin = url.origin().ascii_serialization();
    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    let origin_hash = hex::encode(hasher.finalize());

    let path = format!("origins/{origin_hash}/{}", parts.join("/"));

    let reason = if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        Some("URL query, fragment, or credentials cannot select a canonical local module.".to_string())
    } else {
        None
    };

    Candidate {
        path: Some(path),
        reason,
    }
}

fn plan_web_script_export(scripts: &[CapturedScript]) -> Vec<PlannedItem> {
    let candidates: Vec<Candidate> = scripts.iter().map(candidate_path).collect();

    // Conflict detection
    let mut prefixes: HashMap<String, (Vec<usize>, Vec<usize>)> = HashMap::new();
    for (index, cand) in candidates.iter().enumerate() {
        if let Some(ref path) = cand.path {
            let parts: Vec<&str> = path.split('/').collect();
            for position in 0..parts.len() {
                let spelling = parts[0..=position].join("/");
                let entry = prefixes.entry(spelling).or_insert_with(|| (Vec::new(), Vec::new()));
                entry.0.push(index);
                if position == parts.len() - 1 {
                    entry.1.push(index);
                }
            }
        }
    }

    let mut conflicts = HashSet::new();
    for entry in prefixes.values() {
        if entry.1.len() > 1 || (!entry.1.is_empty() && entry.0.len() > entry.1.len()) {
            for &idx in &entry.0 {
                conflicts.insert(idx);
            }
        }
    }

    let mut out = Vec::with_capacity(scripts.len());
    for (index, script) in scripts.iter().enumerate() {
        match &script.content {
            ScriptContent::Unavailable { reason, message } => {
                out.push(PlannedItem {
                    script: script.clone(),
                    record: serde_json::json!({
                        "source": script.source,
                        "url": script.url,
                        "content": {
                            "state": "unavailable",
                            "reason": reason,
                            "message": message,
                        }
                    }),
                });
            }
            ScriptContent::Captured {
                bytes,
                sha256,
                media_type,
                redacted,
                representation,
            } => {
                let cand = &candidates[index];
                let reason = if conflicts.contains(&index) {
                    Some("Captured paths collide by content version or file/directory prefix.".to_string())
                } else {
                    cand.reason.clone()
                };

                let (rel_path, layout, layout_reason) = if reason.is_some() || cand.path.is_none() {
                    let source_hash = canonical_sha256(&script.source).unwrap_or_else(|_| {
                        let mut h = Sha256::new();
                        h.update(serde_json::to_string(&script.source).unwrap().as_bytes());
                        hex::encode(h.finalize())
                    });
                    (
                        format!("isolated/source-{}-{source_hash}.js", index + 1),
                        "isolated",
                        reason,
                    )
                } else {
                    (cand.path.clone().unwrap(), "url-path", None)
                };

                out.push(PlannedItem {
                    script: script.clone(),
                    record: serde_json::json!({
                        "source": script.source,
                        "url": script.url,
                        "content": {
                            "state": "exported",
                            "relative_path": rel_path,
                            "layout": layout,
                            "layout_reason": layout_reason,
                            "sha256": sha256,
                            "bytes": bytes.len(),
                            "media_type": media_type,
                            "redacted": redacted,
                            "representation": representation,
                        }
                    }),
                });
            }
        }
    }

    out
}
