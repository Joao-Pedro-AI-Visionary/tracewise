//! In-memory scenario secrets (port of REA browser/BrowserScenarioSecrets.ts).
//!
//! Values are read from the process environment for one capture and are never
//! written into evidence, logs, or the returned capture.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::browser_observation::{sanitize_browser_url, SanitizedBrowserUrl};
use crate::browser_scenario::{ScenarioUrl, ScenarioValue};
use crate::error::WebError;
use crate::runtime_cdp::input_error;

const REDACTION_PREFIX: &str = "[REDACTED:";
const OPERATION: &str = "capture_browser_scenario";

/// Resolved secret values kept only for the capture that requested them.
pub struct ScenarioSecrets {
    values: BTreeMap<String, String>,
}

impl std::fmt::Debug for ScenarioSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ScenarioSecrets([redacted])")
    }
}

impl ScenarioSecrets {
    pub fn resolve(declarations: &[(String, String)]) -> Result<Self, WebError> {
        let mut values = BTreeMap::new();
        for (secret_id, variable) in declarations {
            let value = std::env::var(variable).map_err(|_| {
                input_error(
                    OPERATION,
                    "secrets",
                    format!("Secret environment variable {variable} is not set"),
                )
            })?;
            values.insert(secret_id.clone(), value);
        }
        Ok(Self { values })
    }

    pub fn resolve_value(&self, source: &ScenarioValue) -> String {
        match source {
            ScenarioValue::Literal(value) => value.clone(),
            ScenarioValue::Secret(secret_id) => self
                .values
                .get(secret_id)
                .cloned()
                .unwrap_or_default(),
        }
    }

    pub fn url(&self, destination: &ScenarioUrl) -> String {
        if destination.query.is_empty() {
            return destination.url.clone();
        }
        let Ok(mut url) = url::Url::parse(&destination.url) else {
            return destination.url.clone();
        };
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in &destination.query {
                query.append_pair(name, &self.resolve_value(value));
            }
        }
        url.to_string()
    }

    pub fn redact(&self, value: &str) -> String {
        let mut output = value.to_string();
        for (secret_id, secret) in self.replacements() {
            if secret.is_empty() {
                continue;
            }
            output = output.replace(secret, &marker(secret_id));
        }
        output
    }

    pub fn redact_bytes(&self, value: &[u8]) -> Vec<u8> {
        let mut output = value.to_vec();
        for (secret_id, secret) in self.replacements() {
            if secret.is_empty() {
                continue;
            }
            for candidate in encoded_forms(secret) {
                output = replace_bytes(&output, candidate.as_bytes(), marker(secret_id).as_bytes());
            }
        }
        output
    }

    pub fn sanitize_url(&self, value: &str) -> SanitizedBrowserUrl {
        let mut output = value.to_string();
        for (secret_id, secret) in self.replacements() {
            if secret.is_empty() {
                continue;
            }
            let marker = marker(secret_id);
            for candidate in encoded_forms(secret) {
                output = output.replace(&candidate, &marker);
            }
        }
        let mut sanitized = sanitize_browser_url(&output);
        if output != value {
            sanitized.redacted = true;
        }
        sanitized
    }

    pub fn fingerprint(&self, value: &str) -> serde_json::Value {
        for secret in self.values.values() {
            if !secret.is_empty() && value.contains(secret) {
                return serde_json::json!({ "value_state": "redacted-secret", "value_sha256": null });
            }
        }
        serde_json::json!({
            "value_state": "hashed",
            "value_sha256": hex::encode(Sha256::digest(self.redact(value).as_bytes())),
        })
    }

    fn replacements(&self) -> Vec<(&str, &str)> {
        let mut pairs: Vec<(&str, &str)> = self.values.iter().map(|(id, value)| (id.as_str(), value.as_str())).collect();
        pairs.sort_by(|left, right| right.1.len().cmp(&left.1.len()).then_with(|| left.0.cmp(right.0)));
        pairs
    }
}

fn marker(secret_id: &str) -> String {
    format!("{REDACTION_PREFIX}{secret_id}]")
}

fn encoded_forms(secret: &str) -> Vec<String> {
    let mut forms = vec![
        secret.to_string(),
        encode_uri_component(secret),
        form_urlencoded::byte_serialize(secret.as_bytes()).collect(),
    ];
    if let Ok(encoded) = serde_json::to_string(secret) {
        if encoded.len() >= 2 {
            forms.push(encoded[1..encoded.len() - 1].to_string());
        }
    }
    forms.sort();
    forms.dedup();
    forms
}

fn encode_uri_component(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                output.push(byte as char);
            }
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut output = Vec::new();
    let mut offset = 0;
    while let Some(index) = find_bytes(&haystack[offset..], needle) {
        output.extend_from_slice(&haystack[offset..offset + index]);
        output.extend_from_slice(replacement);
        offset += index + needle.len();
    }
    output.extend_from_slice(&haystack[offset..]);
    output
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_scenario::ScenarioValue;

    #[test]
    fn redact_removes_raw_and_encoded_secret_text() {
        let secrets = ScenarioSecrets {
            values: BTreeMap::from([("token".to_string(), "p@ss word".to_string())]),
        };
        let raw = secrets.redact("p@ss word");
        assert_eq!(raw, "[REDACTED:token]");
        assert!(!raw.contains("p@ss"));
        let url = format!("http://127.0.0.1/x?q={}", encode_uri_component("p@ss word"));
        let sanitized = secrets.sanitize_url(&url);
        assert!(sanitized.redacted);
        assert!(!sanitized.url.contains("p%40ss") && !sanitized.url.contains("p@ss"));
        let literal = secrets.resolve_value(&ScenarioValue::Literal("visible".to_string()));
        assert_eq!(literal, "visible");
    }
}
