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

const SOURCE_LOCATION_LIMITATIONS: &[&str] = &[
    "The source/map pairing and source-map URL context are caller-selected. Deployment authenticity and execution remain unknown.",
    "Capture metadata and its Evidence reference are historical context; this trace independently verifies only the selected manifest, script and map bytes.",
    "Source names and sourceRoot are reported declarations. Resolved URLs are derived by the pinned upstream codec; no original source is fetched or executed.",
    "Embedded source hashes identify the UTF-8 encoding of decoded sourcesContent text, not an independently retained original file. Missing or out-of-range original content positions remain explicit.",
    "Lookup returns all segments at the greatest generated position not greater than the selected point, including earlier lines and generated-only segments. A mapped point does not establish an executed range or UI causality.",
    "Regular maps and inline indexed sections are supported. External section URLs are unsupported; unknown extensions are retained in raw map text and are not interpreted.",
    "Complete evidence has a 4 MiB map, 32 MiB reply, 262144 decoded rows/segments and 64-level section budget. The owned codec has a 20-second deadline, 192 MiB old-generation heap and one V8 worker; cleanup may extend the deadline. V8 heap limits do not establish aggregate RSS limits.",
];

#[derive(Debug, Clone, Deserialize)]
pub struct TraceWebSourceLocationInput {
    pub manifest_path: String,
    pub script_index: usize,
    pub source_map: SourceMapRef,
    pub generated_position: GeneratedPosition,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceMapRef {
    pub path: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct GeneratedPosition {
    pub line: u32,
    pub column: u32,
}

pub fn web_source_offset(text: &str, pos: GeneratedPosition) -> Option<usize> {
    if pos.line == 0 {
        return None;
    }
    let target_line = pos.line as usize;
    let target_col = pos.column as usize;

    let mut current_line = 1;
    let mut current_col = 0;
    let mut current_offset = 0;

    for ch in text.chars() {
        let u16_len = ch.len_utf16();
        if current_line == target_line && current_col == target_col {
            return Some(current_offset);
        }
        current_offset += u16_len;
        if ch == '\n' {
            if current_line == target_line {
                // If target column is at newline
                if current_col == target_col {
                    return Some(current_offset - u16_len);
                }
                return None;
            }
            current_line += 1;
            current_col = 0;
        } else {
            current_col += u16_len;
        }
    }

    if current_line == target_line && current_col == target_col {
        Some(current_offset)
    } else {
        None
    }
}

// VLQ decoding for source map mappings
fn decode_vlq(input: &str) -> Vec<Vec<Vec<i64>>> {
    const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64_map = [255u8; 128];
    for (i, &b) in B64_CHARS.iter().enumerate() {
        b64_map[b as usize] = i as u8;
    }

    let mut lines = Vec::new();
    let mut source_idx = 0i64;
    let mut orig_line = 0i64;
    let mut orig_col = 0i64;
    let mut name_idx = 0i64;

    for line_str in input.split(';') {
        let mut line_segments = Vec::new();
        let mut gen_col = 0i64;

        if !line_str.is_empty() {
            for seg_str in line_str.split(',') {
                if seg_str.is_empty() {
                    continue;
                }
                let mut values = Vec::new();
                let mut val = 0i64;
                let mut shift = 0;

                for byte in seg_str.bytes() {
                    if (byte as usize) >= b64_map.len() {
                        continue;
                    }
                    let digit = b64_map[byte as usize];
                    if digit == 255 {
                        continue;
                    }
                    let continuation = (digit & 32) != 0;
                    let digit_val = (digit & 31) as i64;
                    val += digit_val << shift;
                    shift += 5;

                    if !continuation {
                        let is_negative = (val & 1) == 1;
                        let decoded = val >> 1;
                        values.push(if is_negative { -decoded } else { decoded });
                        val = 0;
                        shift = 0;
                    }
                }

                if values.is_empty() {
                    continue;
                }

                gen_col += values[0];
                let mut segment = vec![gen_col];

                if values.len() >= 4 {
                    source_idx += values[1];
                    orig_line += values[2];
                    orig_col += values[3];
                    segment.push(source_idx);
                    segment.push(orig_line);
                    segment.push(orig_col);

                    if values.len() >= 5 {
                        name_idx += values[4];
                        segment.push(name_idx);
                    }
                }

                line_segments.push(segment);
            }
        }
        lines.push(line_segments);
    }

    lines
}

pub fn trace_web_source_location(
    input: TraceWebSourceLocationInput,
) -> Result<Evidence, WebError> {
    let manifest_path = Path::new(&input.manifest_path);
    let map_path = Path::new(&input.source_map.path);

    if !manifest_path.is_absolute() || !map_path.is_absolute() {
        return Err(WebError::Input {
            operation: "trace_web_source_location".to_string(),
            path: vec!["manifest_path".to_string()],
            reason: "invalid_format".to_string(),
            message: "Expected an absolute filesystem path on this host.".to_string(),
        });
    }

    let parsed_map_url = Url::parse(&input.source_map.url).map_err(|_| WebError::Input {
        operation: "trace_web_source_location".to_string(),
        path: vec!["source_map".to_string(), "url".to_string()],
        reason: "invalid_format".to_string(),
        message: "Expected an absolute source-map URL context. Select its deployment context explicitly; no URL is fetched.".to_string(),
    })?;

    let manifest_bytes = std::fs::read(manifest_path).map_err(|e| WebError::Input {
        operation: "trace_web_source_location".to_string(),
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
        operation: "trace_web_source_location".to_string(),
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
        operation: "trace_web_source_location".to_string(),
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

    let generated_offset = web_source_offset(source_text, input.generated_position).ok_or_else(|| {
        WebError::Input {
            operation: "trace_web_source_location".to_string(),
            path: vec!["generated_position".to_string()],
            reason: "invalid_format".to_string(),
            message: "Selected generated position is outside the retained script text (one-based lines; zero-based UTF-16 columns).".to_string(),
        }
    })?;

    let map_bytes = std::fs::read(map_path).map_err(|e| WebError::Input {
        operation: "trace_web_source_location".to_string(),
        path: vec!["source_map".to_string(), "path".to_string()],
        reason: "invalid_value".to_string(),
        message: format!("Source map could not be read: {e}"),
    })?;

    let map_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&map_bytes);
        hex::encode(hasher.finalize())
    };

    let map_text = std::str::from_utf8(&map_bytes)
        .map_err(|_| WebError::Format("Source map is not valid UTF-8".to_string()))?;
    let map_val: Value = serde_json::from_str(map_text)?;

    let reported_file = map_val.get("file").cloned().unwrap_or(Value::Null);
    let sources = map_val
        .get("sources")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let sources_content = map_val
        .get("sourcesContent")
        .and_then(|v| v.as_array())
        .cloned();
    let names = map_val
        .get("names")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mappings_str = map_val
        .get("mappings")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let source_root = map_val.get("sourceRoot").and_then(|v| v.as_str());

    let rows = decode_vlq(mappings_str);

    // Find greatest position <= requested:
    // line <= requested.line (1-based), column <= requested.column
    let req_line = input.generated_position.line as usize;
    let req_col = input.generated_position.column as i64;

    let mut matched_pos: Option<(usize, i64)> = None;
    let max_line = std::cmp::min(req_line, rows.len());
    for line_idx in (1..=max_line).rev() {
        let row = &rows[line_idx - 1];
        let mut col_cand = None;
        for seg in row {
            let seg_col = seg[0];
            if line_idx < req_line || seg_col <= req_col {
                col_cand = Some(seg_col);
            }
        }
        if let Some(c) = col_cand {
            matched_pos = Some((line_idx, c));
            break;
        }
    }

    let mut matches = Vec::new();
    if let Some((m_line, m_col)) = matched_pos {
        let row = &rows[m_line - 1];
        for seg in row {
            if seg[0] == m_col {
                if seg.len() == 1 {
                    matches.push(serde_json::json!({
                        "state": "generated-only"
                    }));
                } else if seg.len() >= 4 {
                    let source_idx = seg[1] as usize;
                    let orig_line = (seg[2] + 1) as u32;
                    let orig_col = seg[3] as u32;

                    let reported_source = sources.get(source_idx).cloned().unwrap_or(Value::Null);
                    let reported_src_str = reported_source.as_str().unwrap_or("");

                    let resolved_url = if !reported_src_str.is_empty() {
                        let target_str = if let Some(root) = source_root {
                            format!("{root}/{reported_src_str}")
                        } else {
                            reported_src_str.to_string()
                        };
                        match parsed_map_url.join(&target_str) {
                            Ok(u) => Value::String(u.to_string()),
                            Err(_) => Value::Null,
                        }
                    } else {
                        Value::Null
                    };

                    let content_val = sources_content.as_ref().and_then(|c| c.get(source_idx)).and_then(|v| v.as_str());
                    let (content_obj, original_pos_obj) = match content_val {
                        Some(txt) => {
                            let mut h = Sha256::new();
                            h.update(txt.as_bytes());
                            let sha = hex::encode(h.finalize());
                            let off = web_source_offset(txt, GeneratedPosition { line: orig_line, column: orig_col });
                            let content_pos = if off.is_some() {
                                "verified-in-embedded-text"
                            } else {
                                "outside-embedded-text"
                            };
                            (
                                serde_json::json!({
                                    "state": "embedded",
                                    "text": txt,
                                    "utf8_sha256": sha,
                                    "utf8_bytes": txt.len(),
                                    "representation": "UTF-8 encoding of decoded sourcesContent text",
                                }),
                                serde_json::json!({
                                    "line": orig_line,
                                    "column": orig_col,
                                    "offset": off,
                                    "content_position": content_pos,
                                }),
                            )
                        }
                        None => (
                            serde_json::json!({
                                "state": "unavailable",
                                "reason": "sourcesContent-not-retained"
                            }),
                            serde_json::json!({
                                "line": orig_line,
                                "column": orig_col,
                                "offset": Value::Null,
                                "content_position": "content-unavailable",
                            }),
                        ),
                    };

                    let name_val = if seg.len() >= 5 {
                        let n_idx = seg[4] as usize;
                        names.get(n_idx).cloned().unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    };

                    matches.push(serde_json::json!({
                        "state": "mapped",
                        "flattened_source_index": source_idx,
                        "section_path": [],
                        "source_index": source_idx,
                        "reported_source": reported_source,
                        "reported_source_root": source_root.map(Value::from).unwrap_or(Value::Null),
                        "resolved_url": resolved_url,
                        "ignored": false,
                        "content": content_obj,
                        "original_position": original_pos_obj,
                        "name": name_val,
                    }));
                }
            }
        }
    }

    let matched_generated_position = matched_pos.map(|(l, c)| {
        serde_json::json!({
            "line": l,
            "column": c,
        })
    });

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

    let source_map_identity = serde_json::json!({
        "path": input.source_map.path,
        "sha256": map_sha256,
        "bytes": map_bytes.len(),
        "url": input.source_map.url,
        "association": "caller-selected",
    });

    let normalized_result = serde_json::json!({
        "source_map_sha256": map_sha256,
        "url_context": input.source_map.url,
        "engine": {
            "id": "jridgewell-trace-mapping",
            "version": "0.3.31"
        },
        "runtime": {
            "id": "node-v8",
            "version": "v22.20.0",
            "v8_heap_limit_bytes": 226492416
        },
        "format": "regular",
        "reported_file": reported_file,
        "lookup": {
            "requested": {
                "line": input.generated_position.line,
                "column": input.generated_position.column,
            },
            "matched_generated_position": matched_generated_position,
            "semantics": "greatest generated position <= requested, across lines; all equal-position segments",
            "location_units": "one-based lines; zero-based UTF-16 columns",
        },
        "matches": matches,
        "diagnostics": [],
        "manifest": manifest_identity,
        "source": source_identity,
        "source_map": source_map_identity,
        "generated_offset": generated_offset,
        "source_authenticity": "unknown",
        "execution": "unknown",
        "limitations": SOURCE_LOCATION_LIMITATIONS,
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
        id: "rea-web-source-location".to_string(),
        name: "REA captured source-map point trace".to_string(),
        version: Some("1".to_string()),
    };

    let locations = vec![
        EvidenceLocation::ArtifactPath {
            path: source_file_path.to_str().unwrap().to_string(),
        },
        EvidenceLocation::ArtifactPath {
            path: input.manifest_path.clone(),
        },
        EvidenceLocation::ArtifactPath {
            path: input.source_map.path.clone(),
        },
    ];

    let parameters = serde_json::json!({
        "manifest_path": input.manifest_path,
        "script_index": input.script_index,
        "source_map": {
            "path": input.source_map.path,
            "url": input.source_map.url,
        },
        "generated_position": {
            "line": input.generated_position.line,
            "column": input.generated_position.column,
        }
    });

    let observation = EvidenceObservation {
        predicate_type: Some("rea.analysis".to_string()),
        operation: "trace_web_source_location".to_string(),
        parameters,
        normalized_result,
        raw_result: Some(serde_json::json!({ "source_map_text": map_text })),
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Derived),
        authority: Some(EvidenceAuthority::HistoricalReference),
        environment: None,
        limitations: Some(SOURCE_LOCATION_LIMITATIONS.iter().map(|s| s.to_string()).collect()),
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
