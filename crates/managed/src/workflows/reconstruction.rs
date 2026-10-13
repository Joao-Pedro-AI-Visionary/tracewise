//! `import_managed_reconstruction` (REA `managedReconstruction.ts`).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{input_error, parse_evidence, sha256_canonical, WR};

fn sha256_text(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `text.split(/\r\n|\r|\n/u).length`, with the empty string counting zero lines.
fn count_lines(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let bytes = text.as_bytes();
    let mut lines = 1;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                lines += 1;
                if bytes.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
            }
            b'\n' => lines += 1,
            _ => {}
        }
        index += 1;
    }
    lines
}

/// JavaScript `String#length` (UTF-16 code units).
fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

const LIMITATIONS: [&str; 4] = [
    "Decompiler output is imported as reconstruction evidence and analyst inference; metadata and IL observations remain canonical.",
    "This operation did not execute, load, reflect over, debug, instrument, patch, or decompile the target artifact.",
    "The imported reconstruction is valid only for the exact artifact SHA-256, MVID, method signature, and normalized IL shape recorded here.",
    "Obfuscated names, decompiler variables, and control-flow restructuring are not treated as proof without separate validation.",
];

/// Apply the schema defaults REA's input parser fills in.
pub fn normalize_input(input: &Value) -> Value {
    let mut normalized = input.clone();
    if let Some(decompiler) = normalized.get_mut("decompiler").and_then(Value::as_object_mut) {
        decompiler.entry("version").or_insert(Value::Null);
        decompiler.entry("executable_sha256").or_insert(Value::Null);
        decompiler.entry("options").or_insert(json!([]));
    }
    if let Some(object) = normalized.as_object_mut() {
        object.entry("notes").or_insert(json!([]));
    }
    normalized
}

/// Authenticate decompiler reconstruction against static IL Evidence.
pub fn import_managed_reconstruction(input: &Value) -> WR<Value> {
    let input = normalize_input(input);
    let static_evidence = parse_evidence(&input["static_members"])?;
    if static_evidence.operation != "inspect_managed_members" {
        return Err(input_error("Evidence operation is not inspect_managed_members"));
    }
    let members = &static_evidence.normalized_result;
    let empty = Vec::new();
    let observed_methods = members["methods"].as_array().unwrap_or(&empty);
    let candidates = input["methods"].as_array().unwrap_or(&empty);
    let mut imported = Vec::new();
    for candidate in candidates {
        let token = candidate["token"].as_str().unwrap_or_default();
        let observed = observed_methods.iter().find(|item| {
            item["token"] == candidate["token"]
                && item["signature"]["raw_sha256"] == candidate["signature_sha256"]
                && item["body"]["status"] == "present"
                && !item["body"]["normalized_il_sha256"].is_null()
                && !candidate["normalized_il_sha256"].is_null()
                && item["body"]["normalized_il_sha256"] == candidate["normalized_il_sha256"]
        });
        let Some(observed) = observed else {
            return Err(input_error(format!(
                "Reconstruction method lock {token} does not match a static managed member observation"
            )));
        };
        let reconstruction = &candidate["reconstruction"];
        let text = reconstruction["text"].as_str().unwrap_or_default();
        let text_sha256 = sha256_text(text);
        if let Some(declared) = reconstruction.get("text_sha256").filter(|v| !v.is_null()) {
            if declared.as_str() != Some(text_sha256.as_str()) {
                return Err(input_error(format!("Reconstruction text hash mismatch for {token}")));
            }
        }
        imported.push(json!({
            "token": observed["token"],
            "declaring_type": observed["declaring_type"],
            "name": observed["name"],
            "signature_sha256": observed["signature"]["raw_sha256"],
            "normalized_il_sha256": observed["body"]["normalized_il_sha256"],
            "body_sha256": observed["body"]["il_sha256"],
            "il_size": observed["body"]["il_size"],
            "reconstruction": {
                "kind": reconstruction["kind"],
                "language": reconstruction["language"],
                "text": text,
                "text_sha256": text_sha256,
                "text_length": js_length(text),
                "line_count": count_lines(text),
                "source_path": reconstruction.get("source_path").cloned().filter(|v| !v.is_null()),
                "start_line": reconstruction.get("start_line").cloned().filter(|v| !v.is_null()),
                "end_line": reconstruction.get("end_line").cloned().filter(|v| !v.is_null()),
            },
            "validation": {
                "matched_static_member": true,
                "exact_build_required": true,
                "canonical_observation": false,
                "confidence_floor": "inference",
            },
        }));
    }
    let count_kind = |kind: &str| imported.iter().filter(|m| m["reconstruction"]["kind"] == kind).count();
    let total_text_bytes: usize = imported.iter().map(|m| m["reconstruction"]["text_length"].as_u64().unwrap_or(0) as usize).sum();
    let decompiler = &input["decompiler"];
    let mut decompiler_record = decompiler.clone();
    decompiler_record["options_sha256"] = json!(sha256_canonical(&decompiler["options"])?);
    let without_id = json!({
        "phase": "reconstruction-import",
        "executed": false,
        "static_observation": {
            "evidence_id": static_evidence.evidence_id,
            "artifact_sha256": members["artifact"]["sha256"],
            "artifact_path": members["artifact"]["path"],
            "byte_length": members["artifact"]["byte_length"],
            "module_name": members["module"]["name"],
            "mvid": members["module"]["mvid"],
            "metadata_status": members["metadata"]["status"],
        },
        "decompiler": decompiler_record,
        "summary": {
            "imported_methods": imported.len(),
            "decompiled_csharp_methods": count_kind("decompiled-csharp"),
            "decompiled_il_methods": count_kind("decompiled-il"),
            "pseudocode_methods": count_kind("semantic-pseudocode"),
            "total_text_bytes": total_text_bytes,
        },
        "methods": imported,
        "notes": input["notes"],
        "evidence_links": [static_evidence.evidence_id],
        "limitations": LIMITATIONS,
    });
    let reconstruction_id = sha256_canonical(&without_id)?;
    let mut result = without_id;
    result["reconstruction_id"] = json!(format!("mre_{reconstruction_id}"));
    Ok(result)
}
