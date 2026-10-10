use std::path::Path;

use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence,
    EvidenceLocation, EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::WebError;

const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

const HAR_LIMITATIONS: &[&str] = &[
    "This is retained producer evidence, without live browser transaction IDs, scenario provenance, execution attribution or deployment authenticity. Recorded URLs are never fetched.",
    "Every record is decoded before selection; no partial success is returned on malformed input or a resource limit.",
    "Known authentication headers/cookies and explicitly marked literal values are excluded. Unknown extension names do not establish sensitivity.",
    "A 32 MiB input, 96 MiB reply and 64-level nesting budget bound complete evidence. HAR uses a 192 MiB Node old-generation heap; native decoding uses a 768 MiB Linux address-space limit. Each owned command has a 30-second deadline with independent cleanup.",
];

const RECORD_LIMITATION: &str = "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless content explicitly uses valid base64; declared sizes are preserved independently of retained bytes. mitmproxy 12.2.3 SaveHar may report null optional postData.text; that null is retained and omitted only from the upstream validation copy.";

#[derive(Debug, Clone, Deserialize)]
pub struct InspectWebNetworkCaptureInput {
    pub capture_path: String,
    pub format: String,
    pub record_ordinals: Option<Vec<usize>>,
    #[serde(default)]
    pub sensitive_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    pub pointer: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumericLiteral {
    pub pointer: String,
    pub producer_type: String,
    pub literal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryField {
    pub pointer: String,
    pub representation: String,
    pub state: String,
    pub content_base64: Option<String>,
    pub bytes: Option<usize>,
    pub sha256: Option<String>,
}

struct Redactor<'a> {
    sensitive_values: &'a [String],
    sensitive_bytes: Vec<Vec<u8>>,
    redactions: Vec<Redaction>,
    transport_url_regex: Regex,
}

impl<'a> Redactor<'a> {
    fn new(sensitive_values: &'a [String]) -> Self {
        let sensitive_bytes: Vec<Vec<u8>> = sensitive_values
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let transport_url_regex =
            Regex::new(r"(?i)^([\x00-\x20]*(?:[a-z][a-z0-9+.-]*:)?//)([^/?#]*@)").unwrap();
        Self {
            sensitive_values,
            sensitive_bytes,
            redactions: Vec::new(),
            transport_url_regex,
        }
    }

    fn redact_text(&mut self, text: &str, pointer: &str, transport_url: bool) -> Option<String> {
        let mut result = text.to_string();
        if transport_url {
            if let Some(captures) = self.transport_url_regex.captures(text) {
                if let (Some(m_all), Some(m_scheme)) = (captures.get(0), captures.get(1)) {
                    result = format!("{}{}", m_scheme.as_str(), &text[m_all.end()..]);
                    self.redactions.push(Redaction {
                        pointer: pointer.to_string(),
                        reason: "transport-credential".to_string(),
                        scope: None,
                    });
                }
            }
        }

        if self.sensitive_values.iter().any(|lit| text.contains(lit) || result.contains(lit)) {
            self.redactions.push(Redaction {
                pointer: pointer.to_string(),
                reason: "explicit-sensitive-value".to_string(),
                scope: None,
            });
            return None;
        }

        Some(result)
    }

    fn credential(&mut self, pointer: &str) -> Value {
        self.redactions.push(Redaction {
            pointer: pointer.to_string(),
            reason: "transport-credential".to_string(),
            scope: None,
        });
        Value::Null
    }

    fn sensitive_bytes_check(&self, bytes: &[u8]) -> bool {
        self.sensitive_bytes.iter().any(|pat| {
            if pat.is_empty() {
                false
            } else {
                bytes.windows(pat.len()).any(|window| window == pat.as_slice())
            }
        })
    }
}

fn is_har_credential(pointer: &str, parent: &Map<String, Value>) -> bool {
    let is_header = (pointer.starts_with("/request/headers/") || pointer.starts_with("/response/headers/"))
        && pointer.ends_with("/value");
    if is_header {
        if let Some(name_val) = parent.get("name").and_then(|n| n.as_str()) {
            let lower = name_val.to_ascii_lowercase();
            if CREDENTIAL_HEADERS.contains(&lower.as_str()) {
                return true;
            }
        }
    }

    let is_cookie = (pointer.starts_with("/request/cookies/") || pointer.starts_with("/response/cookies/"))
        && pointer.ends_with("/value");
    is_cookie
}

fn is_har_transport_url(pointer: &str, parent: Option<&Map<String, Value>>) -> bool {
    if pointer == "/request/url" || pointer == "/response/redirectURL" {
        return true;
    }
    let is_header = (pointer.starts_with("/request/headers/") || pointer.starts_with("/response/headers/"))
        && pointer.ends_with("/value");
    if is_header {
        if let Some(parent_map) = parent {
            if let Some(name_val) = parent_map.get("name").and_then(|n| n.as_str()) {
                let lower = name_val.to_ascii_lowercase();
                if lower == "location" || lower == "referer" || lower == "origin" {
                    return true;
                }
            }
        }
    }
    false
}

struct ProjectResult {
    reported: Value,
    numeric_literals: Vec<NumericLiteral>,
    binary_fields: Vec<BinaryField>,
    redactions: Vec<Redaction>,
}

fn project_har_value(
    value: &Value,
    sensitive_values: &[String],
    redact: bool,
) -> Result<ProjectResult, WebError> {
    let mut redactor = Redactor::new(sensitive_values);
    let mut numeric_literals = Vec::new();
    let mut binary_fields = Vec::new();

    let reported = visit_har(
        value,
        "",
        0,
        None,
        redact,
        sensitive_values,
        &mut redactor,
        &mut numeric_literals,
        &mut binary_fields,
    )?;

    Ok(ProjectResult {
        reported,
        numeric_literals,
        binary_fields,
        redactions: redactor.redactions,
    })
}

#[allow(clippy::too_many_arguments)]
fn visit_har(
    item: &Value,
    pointer: &str,
    depth: usize,
    parent: Option<&Map<String, Value>>,
    redact: bool,
    sensitive_values: &[String],
    redactor: &mut Redactor,
    numeric_literals: &mut Vec<NumericLiteral>,
    binary_fields: &mut Vec<BinaryField>,
) -> Result<Value, WebError> {
    if depth > 64 {
        return Err(WebError::Format(
            "HAR exceeds the 64-level complete-evidence nesting budget.".to_string(),
        ));
    }

    if redact {
        if let Some(p) = parent {
            if is_har_credential(pointer, p) {
                return Ok(redactor.credential(pointer));
            }
        }
    }

    match item {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(num) => {
            let lit = num.to_string();
            if redact && sensitive_values.iter().any(|s| lit.contains(s)) {
                redactor.redactions.push(Redaction {
                    pointer: pointer.to_string(),
                    reason: "explicit-sensitive-value".to_string(),
                    scope: None,
                });
                return Ok(Value::Null);
            }
            numeric_literals.push(NumericLiteral {
                pointer: pointer.to_string(),
                producer_type: "json-number".to_string(),
                literal: lit,
            });
            Ok(Value::Number(num.clone()))
        }
        Value::String(s) => {
            if redact && pointer == "/response/content/text" {
                if let Some(p) = parent {
                    if p.get("encoding").and_then(|v| v.as_str()) == Some("base64") {
                        let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(&compact)
                            .map_err(|_| {
                                WebError::Format(
                                    "HAR content declares base64 but its text is not valid canonical base64."
                                        .to_string(),
                                )
                            })?;

                        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&decoded);
                        let mut hasher = Sha256::new();
                        hasher.update(&decoded);
                        let sha = hex::encode(hasher.finalize());

                        let hidden = redactor.sensitive_bytes_check(&decoded)
                            || sensitive_values.iter().any(|lit| {
                                s.contains(lit)
                                    || content_b64.contains(lit)
                                    || sha.contains(lit)
                            });

                        if hidden {
                            binary_fields.push(BinaryField {
                                pointer: pointer.to_string(),
                                representation: "har-base64-content".to_string(),
                                state: "redacted".to_string(),
                                content_base64: None,
                                bytes: None,
                                sha256: None,
                            });
                            redactor.redactions.push(Redaction {
                                pointer: pointer.to_string(),
                                reason: "explicit-sensitive-value".to_string(),
                                scope: None,
                            });
                            return Ok(Value::Null);
                        } else {
                            binary_fields.push(BinaryField {
                                pointer: pointer.to_string(),
                                representation: "har-base64-content".to_string(),
                                state: "retained".to_string(),
                                content_base64: Some(content_b64),
                                bytes: Some(decoded.len()),
                                sha256: Some(sha),
                            });
                            return Ok(Value::String(s.clone()));
                        }
                    }
                }
            }

            if redact {
                let transport = is_har_transport_url(pointer, parent);
                match redactor.redact_text(s, pointer, transport) {
                    Some(safe) => Ok(Value::String(safe)),
                    None => Ok(Value::Null),
                }
            } else {
                Ok(Value::String(s.clone()))
            }
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for (index, child) in arr.iter().enumerate() {
                let child_pointer = format!("{pointer}/{index}");
                let child_res = visit_har(
                    child,
                    &child_pointer,
                    depth + 1,
                    parent,
                    redact,
                    sensitive_values,
                    redactor,
                    numeric_literals,
                    binary_fields,
                )?;
                out.push(child_res);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map.iter() {
                if redact && sensitive_values.iter().any(|lit| key.contains(lit)) {
                    // Property name sensitive: remove property and add redaction
                    redactor.redactions.push(Redaction {
                        pointer: pointer.to_string(),
                        reason: "explicit-sensitive-value".to_string(),
                        scope: Some("property-name".to_string()),
                    });
                    continue;
                }
                let child_pointer = format!(
                    "{}/{}",
                    pointer,
                    key.replace('~', "~0").replace('/', "~1")
                );
                let child_res = visit_har(
                    child,
                    &child_pointer,
                    depth + 1,
                    Some(map),
                    redact,
                    sensitive_values,
                    redactor,
                    numeric_literals,
                    binary_fields,
                )?;
                out.insert(key.clone(), child_res);
            }
            Ok(Value::Object(out))
        }
    }
}

pub fn inspect_har_capture(
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

    if let Some(ref ordinals) = input.record_ordinals {
        let mut seen = std::collections::HashSet::new();
        for &ord in ordinals {
            if !seen.insert(ord) {
                return Err(WebError::Input {
                    operation: "inspect_web_network_capture".to_string(),
                    path: vec!["record_ordinals".to_string()],
                    reason: "invalid_format".to_string(),
                    message: "Each requested producer ordinal must occur once.".to_string(),
                });
            }
        }
    }

    let bytes = std::fs::read(capture_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let artifact_sha256 = hex::encode(hasher.finalize());
    let artifact_bytes = bytes.len();

    let text = std::str::from_utf8(&bytes)
        .map_err(|_| WebError::Format("HAR is not valid UTF-8 JSON.".to_string()))?;
    // Skip leading BOM if present
    let clean_text = text.trim_start_matches('\u{feff}');
    let raw: Value = serde_json::from_str(clean_text)?;

    let raw_log = raw
        .get("log")
        .and_then(|v| v.as_object())
        .ok_or_else(|| WebError::Format("HAR must contain log.entries.".to_string()))?;

    let version = raw_log.get("version").and_then(|v| v.as_str()).unwrap_or("");
    if version != "1.2" {
        return Err(WebError::Format(
            "Only the pinned HAR 1.2 schema profile is supported.".to_string(),
        ));
    }

    let entries = raw_log
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WebError::Format("HAR must contain log.entries.".to_string()))?;

    let total_records = entries.len();

    let selected_ordinals: Vec<usize> = match &input.record_ordinals {
        Some(ords) => {
            for &ord in ords {
                if ord >= total_records {
                    return Err(WebError::Input {
                        operation: "inspect_web_network_capture".to_string(),
                        path: vec!["record_ordinals".to_string()],
                        reason: "invalid_format".to_string(),
                        message: format!(
                            "Producer ordinal {ord} is outside the retained capture ({total_records} records)."
                        ),
                    });
                }
            }
            ords.clone()
        }
        None => (0..total_records).collect(),
    };

    let records_excluded = ["log", "entries"].iter().any(|key| {
        input.sensitive_values.iter().any(|lit| key.contains(lit))
    });

    let mut container_raw = raw.clone();
    if let Some(log_obj) = container_raw.get_mut("log").and_then(|v| v.as_mut_object()) {
        log_obj.insert("entries".to_string(), Value::Null);
    }
    let container_projected = project_har_value(&container_raw, &input.sensitive_values, true)?;

    let mut records = Vec::with_capacity(selected_ordinals.len());
    for &ordinal in &selected_ordinals {
        let entry = &entries[ordinal];
        let projected = project_har_value(entry, &input.sensitive_values, true)?;

        let (reported, numeric_literals, binary_fields, redactions, location) = if records_excluded {
            (
                Value::Null,
                Vec::new(),
                Vec::new(),
                vec![Redaction {
                    pointer: String::new(),
                    reason: "explicit-sensitive-value".to_string(),
                    scope: None,
                }],
                serde_json::json!({
                    "kind": "unknown",
                    "reason": "explicit-sensitive-value"
                }),
            )
        } else {
            (
                projected.reported,
                projected.numeric_literals,
                projected.binary_fields,
                projected.redactions,
                serde_json::json!({
                    "kind": "json-pointer",
                    "pointer": format!("/log/entries/{ordinal}")
                }),
            )
        };

        let mut limitations = vec![RECORD_LIMITATION.to_string()];
        if records_excluded {
            limitations.push(
                "This record's payload and sidecars are excluded because its structural ancestor property was explicitly marked sensitive."
                    .to_string(),
            );
        }

        records.push(serde_json::json!({
            "ordinal": ordinal,
            "location": location,
            "reported": reported,
            "binary_fields": binary_fields,
            "numeric_literals": numeric_literals,
            "redactions": redactions,
            "limitations": limitations,
        }));
    }

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

    let mut limitations: Vec<String> = HAR_LIMITATIONS.iter().map(|s| s.to_string()).collect();
    if safe_path.is_empty() {
        limitations.push(
            "The explicitly sensitive artifact path is excluded; its size remains available."
                .to_string(),
        );
    }
    if safe_sha256.is_none() {
        limitations.push(
            "The explicitly sensitive artifact digest is excluded; its cryptographic identity is unknown in this Evidence."
                .to_string(),
        );
    }

    let records_pointer = if records_excluded {
        Value::Null
    } else {
        Value::String("/log/entries".to_string())
    };

    let decoder = serde_json::json!({
        "id": "har-schema/lossless-json",
        "name": "REA HAR capture adapter",
        "version": "har-schema@2.0.0;jsonc-parser@3.3.1;lossless-json@4.3.1"
    });

    let artifact = serde_json::json!({
        "path": safe_path,
        "sha256": safe_sha256,
        "bytes": artifact_bytes,
    });

    let container = serde_json::json!({
        "reported": container_projected.reported,
        "numeric_literals": container_projected.numeric_literals,
        "redactions": container_projected.redactions,
        "records_pointer": records_pointer,
    });

    let normalized_result = serde_json::json!({
        "artifact": artifact,
        "format": "har",
        "decoder": decoder,
        "container": container,
        "total_records": total_records,
        "records": records,
        "runtime_attribution": "unknown",
        "limitations": limitations,
    });

    let mut parameters = Map::new();
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
        id: "har-schema/lossless-json".to_string(),
        name: "REA HAR capture adapter".to_string(),
        version: Some("har-schema@2.0.0;jsonc-parser@3.3.1;lossless-json@4.3.1".to_string()),
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
