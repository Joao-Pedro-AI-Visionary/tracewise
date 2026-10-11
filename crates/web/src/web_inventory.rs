//! Stable resource and script identities (port of REA domain/webInventory.ts).

use serde_json::{json, Value};
use tracewise_domain::canonical::canonical_sha256;

use crate::error::WebError;

/// `res_<sha256>` of the public resource projection.
pub fn stable_resource_key(resource: &Value) -> Result<String, WebError> {
    let payload = json!({
        "content_size": resource["content_size"],
        "mime_type": resource["mime_type"],
        "origin": resource["origin"],
        "type": resource["type"],
        "url": resource["url"],
    });
    Ok(format!("res_{}", canonical_sha256(&payload)?))
}

/// `scr_<sha256>` excludes target ids, CDP script ids, and timestamps.
pub fn stable_script_key(script: &Value) -> Result<String, WebError> {
    let payload = json!({
        "cdp_hash": script["cdp_hash"],
        "is_module": script["is_module"],
        "language": script["language"],
        "length": script["length"],
        "source_map_url": script["source_map_url"],
        "url": script["url"],
    });
    Ok(format!("scr_{}", canonical_sha256(&payload)?))
}

/// Exact raw-URL match, then sanitized-URL ambiguity, else unmatched.
pub fn reconcile_captured_script(
    raw_url: &str,
    sanitized_url: &str,
    raw_resources: &[(String, Value)],
    resources: &[Value],
) -> Result<Value, WebError> {
    let exact: Vec<&Value> = raw_resources
        .iter()
        .filter(|(raw, _)| raw == raw_url)
        .map(|(_, resource)| resource)
        .collect();
    if exact.len() == 1 {
        let key = stable_resource_key(exact[0])?;
        return Ok(json!({ "status": "exact", "resource_key": key }));
    }
    let mut candidates: Vec<String> = resources
        .iter()
        .filter(|resource| resource["url"].as_str() == Some(sanitized_url))
        .map(stable_resource_key)
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort();
    candidates.dedup();
    if !candidates.is_empty() {
        return Ok(json!({
            "status": "ambiguous",
            "candidate_resource_keys": candidates,
        }));
    }
    Ok(json!({
        "status": "unmatched",
        "reason": "no_exact_sanitized_url",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_key_is_stable_for_the_same_projection() {
        let resource = json!({
            "url": "http://127.0.0.1:9/app.js",
            "origin": "http://127.0.0.1:9",
            "type": "Script",
            "mime_type": "text/javascript",
            "content_size": 12,
        });
        let key = stable_resource_key(&resource).unwrap();
        assert!(key.starts_with("res_"));
        assert_eq!(key.len(), 4 + 64);
        assert_eq!(key, stable_resource_key(&resource).unwrap());
    }
}
