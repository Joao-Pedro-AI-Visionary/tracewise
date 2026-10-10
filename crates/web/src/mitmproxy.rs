use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence,
    EvidenceLocation, EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::WebError;
use crate::har::InspectWebNetworkCaptureInput;

const MITMDUMP_REQUIREMENT: &str =
    "Native capture decoding requires Linux and an absolute REA_MITMDUMP_COMMAND path to caller-supplied mitmdump 12.2.3; HAR needs no external engine.";

pub fn inspect_mitmproxy_capture(
    input: InspectWebNetworkCaptureInput,
) -> Result<Evidence, WebError> {
    let capture_path = Path::new(&input.capture_path);
    if !capture_path.is_absolute() {
        return Err(WebError::Input {
            operation: "inspect_web_network_capture".to_string(),
            path: vec!["capture_path".to_string()],
            reason: "invalid_format".to_string(),
            message: "Expected an absolute filesystem path on this host.".to_string(),
        });
    }

    if cfg!(not(target_os = "linux")) {
        return Err(WebError::CapabilityUnavailable {
            capability: "mitmproxy".to_string(),
            operation: "inspect_web_network_capture".to_string(),
            reason: MITMDUMP_REQUIREMENT.to_string(),
            user_message: MITMDUMP_REQUIREMENT.to_string(),
        });
    }

    let command_path = match std::env::var("REA_MITMDUMP_COMMAND") {
        Ok(cmd) if Path::new(&cmd).is_absolute() && Path::new(&cmd).exists() => PathBuf::from(cmd),
        _ => {
            return Err(WebError::CapabilityUnavailable {
                capability: "mitmproxy".to_string(),
                operation: "inspect_web_network_capture".to_string(),
                reason: MITMDUMP_REQUIREMENT.to_string(),
                user_message: MITMDUMP_REQUIREMENT.to_string(),
            });
        }
    };

    let temp_dir = std::env::temp_dir();
    let id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let req_path = temp_dir.join(format!("rea_mitm_req_{id}_{nonce}.json"));
    let reply_path = temp_dir.join(format!("rea_mitm_reply_{id}_{nonce}.json"));
    let conf_dir = temp_dir.join(format!("rea_mitm_conf_{id}_{nonce}"));
    std::fs::create_dir_all(&conf_dir)?;

    let bridge_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("bridge/mitmproxy/capture.py");

    let req_body = serde_json::json!({
        "snapshot_path": input.capture_path,
        "reply_path": reply_path.to_str().unwrap(),
        "sensitive_values": input.sensitive_values,
    });
    std::fs::write(&req_path, serde_json::to_string(&req_body)?)?;

    let output = Command::new(&command_path)
        .arg("--no-server")
        .arg("-q")
        .arg("--set")
        .arg(format!("confdir={}", conf_dir.display()))
        .arg("--set")
        .arg(format!("rea_request_path={}", req_path.display()))
        .arg("-s")
        .arg(&bridge_path)
        .output();

    let _ = std::fs::remove_file(&req_path);
    let _ = std::fs::remove_dir_all(&conf_dir);

    let output = output.map_err(|e| WebError::CapabilityUnavailable {
        capability: "mitmproxy".to_string(),
        operation: "inspect_web_network_capture".to_string(),
        reason: format!("Failed to spawn mitmdump: {e}"),
        user_message: format!("Configured mitmdump executable is unavailable: {e}"),
    })?;

    if !output.status.success() || !reply_path.exists() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = std::fs::remove_file(&reply_path);
        return Err(WebError::Format(format!(
            "mitmdump exited with status {}: {stderr}",
            output.status
        )));
    }

    let reply_bytes = std::fs::read(&reply_path)?;
    let _ = std::fs::remove_file(&reply_path);

    let reply_val: Value = serde_json::from_slice(&reply_bytes)?;
    if reply_val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let msg = reply_val
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Mitmproxy bridge failed");
        return Err(WebError::Format(msg.to_string()));
    }

    let decoded = reply_val["value"].clone();

    let bytes = std::fs::read(capture_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let artifact_sha256 = hex::encode(hasher.finalize());
    let artifact_bytes = bytes.len();

    let safe_path = if input.sensitive_values.iter().any(|lit| input.capture_path.contains(lit)) {
        String::new()
    } else {
        input.capture_path.clone()
    };

    let safe_sha256 = if input.sensitive_values.iter().any(|lit| artifact_sha256.contains(lit)) {
        None
    } else {
        Some(artifact_sha256.clone())
    };

    let total_records = decoded["total_records"].as_u64().unwrap_or(0) as usize;
    let selected_ordinals: Vec<usize> = match &input.record_ordinals {
        Some(ords) => ords.clone(),
        None => (0..total_records).collect(),
    };

    let all_records = decoded["records"].as_array().cloned().unwrap_or_default();
    let selected_records: Vec<Value> = selected_ordinals
        .iter()
        .filter_map(|&ord| all_records.get(ord).cloned())
        .collect();

    let limitations: Vec<String> = vec![
        "This is retained producer evidence, without live browser transaction IDs, scenario provenance, execution attribution or deployment authenticity. Recorded URLs are never fetched.".to_string(),
        "Every record is decoded before selection; no partial success is returned on malformed input or a resource limit.".to_string(),
        "Known authentication headers/cookies and explicitly marked literal values are excluded. Unknown extension names do not establish sensitivity.".to_string(),
        "A 32 MiB input, 96 MiB reply and 64-level nesting budget bound complete evidence. HAR uses a 192 MiB Node old-generation heap; native decoding uses a 768 MiB Linux address-space limit. Each owned command has a 30-second deadline with independent cleanup.".to_string(),
    ];

    let normalized_result = serde_json::json!({
        "artifact": {
            "path": safe_path,
            "sha256": safe_sha256,
            "bytes": artifact_bytes,
        },
        "format": "mitmproxy",
        "decoder": decoded["decoder"],
        "container": decoded["container"],
        "total_records": total_records,
        "records": selected_records,
        "runtime_attribution": "unknown",
        "limitations": limitations,
    });

    let mut parameters = serde_json::Map::new();
    parameters.insert("capture_path".to_string(), Value::String(safe_path.clone()));
    if !input.sensitive_values.iter().any(|lit| input.format.contains(lit)) {
        parameters.insert("format".to_string(), Value::String(input.format.clone()));
    }
    parameters.insert(
        "record_ordinals".to_string(),
        serde_json::to_value(&selected_ordinals).unwrap(),
    );
    parameters.insert(
        "sensitive_value_count".to_string(),
        Value::Number(serde_json::Number::from(input.sensitive_values.len())),
    );

    let subject = safe_sha256.as_ref().map(|sha| EvidenceSubject {
        name: capture_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string(),
        digest: DigestSha256 {
            sha256: sha.clone(),
        },
        format: "file".to_string(),
        architecture: None,
        local_path: safe_path.clone(),
    });

    let provider = EvidenceProvider {
        id: "mitmproxy-native-tnetstring".to_string(),
        name: "REA offline native mitmproxy adapter".to_string(),
        version: Some("12.2.3".to_string()),
    };

    let locations = if safe_path.is_empty() {
        Vec::new()
    } else {
        vec![EvidenceLocation::ArtifactPath {
            path: safe_path.clone(),
        }]
    };

    let observation = EvidenceObservation {
        predicate_type: Some("rea.analysis".to_string()),
        operation: "inspect_web_network_capture".to_string(),
        parameters: Value::Object(parameters),
        normalized_result,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Observed),
        authority: Some(EvidenceAuthority::HistoricalReference),
        environment: None,
        limitations: Some(limitations),
        locations: Some(locations),
        evidence_links: Some(Vec::new()),
    };

    create_evidence(subject, provider, observation).map_err(WebError::from)
}
