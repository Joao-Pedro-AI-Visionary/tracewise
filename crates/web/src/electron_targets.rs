//! `list_electron_targets` and the shared Electron Evidence envelope
//! (port of REA browser/CdpElectronProvider.ts `listTargets`,
//! domain/javascript/electronObservation.ts input schemas and
//! application/javascript/ElectronEvidence.ts).
//!
//! The protocol surface is plain CDP HTTP discovery (`/json/version`,
//! `/json/list`), so the shared `cdp_endpoint` client is reused unchanged.

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, ExecutionEnvironment, IsolationLevel,
};

use crate::browser_observation::parse_browser_scope;
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery};
use crate::electron_file_scope::authorized_electron_file;
use crate::error::WebError;

pub const CDP_ELECTRON_PROVIDER_ID: &str = "rea-cdp-electron";
pub const CDP_ELECTRON_PROVIDER_NAME: &str = "REA Electron file-page CDP observation provider";
pub const CDP_ELECTRON_PROVIDER_VERSION: &str = "1";

const OPERATION: &str = "list_electron_targets";

/// Strict `{cdp_endpoint}` input; returns the normalized loopback endpoint.
pub fn parse_list_electron_targets_input(args: &Value) -> Result<String, WebError> {
    // `allowed_origins` is a browser-tool key, not an Electron one.
    if let Some(object) = args.as_object() {
        if object.contains_key("allowed_origins") {
            return Err(WebError::Input {
                operation: OPERATION.to_string(),
                path: vec!["allowed_origins".to_string()],
                reason: "invalid_value".to_string(),
                message: "Unrecognized key: \"allowed_origins\"".to_string(),
            });
        }
    }
    parse_browser_scope(OPERATION, args, &[]).map(|(scope, _)| scope.cdp_endpoint)
}

/// List local file page targets exposed by the selected endpoint.
pub async fn list_electron_targets(cdp_endpoint: &str) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(cdp_endpoint, OPERATION).await?;
    let result = electron_target_list(&discovery);
    create_electron_evidence(OPERATION, json!({ "cdp_endpoint": cdp_endpoint }), result)
}

/// Project discovery into the public Electron target list.
pub fn electron_target_list(discovery: &CdpEndpointDiscovery) -> Value {
    let mut allowed = Vec::new();
    let (mut unsupported_url, mut non_page, mut unconnectable) = (0u64, 0u64, 0u64);
    for target in &discovery.targets {
        if target.target_type != "page" {
            non_page += 1;
            continue;
        }
        let Some(file_path) = authorized_electron_file(&target.url) else {
            unsupported_url += 1;
            continue;
        };
        if discovery.target_web_socket(target).is_none() {
            unconnectable += 1;
            continue;
        }
        allowed.push(json!({
            "target_id": target.id,
            "type": target.target_type,
            "title": target.title,
            "file_path": file_path,
            "attached": target.attached,
        }));
    }
    allowed.sort_by(|left, right| {
        left["target_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["target_id"].as_str().unwrap_or_default())
    });
    let mut limitations = vec![Value::from(
        "Every local file page exposed by the selected loopback CDP endpoint is eligible for listing.",
    )];
    if unconnectable > 0 {
        limitations.push(Value::from(format!(
            "{unconnectable} otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded."
        )));
    }
    json!({
        "browser": discovery.version.to_json(),
        "targets": allowed,
        "excluded": {
            "unsupported_url": unsupported_url,
            "non_page": non_page,
        },
        "limitations": limitations,
    })
}

/// Create Evidence for one passive Electron observation (REA `createElectronEvidence`).
///
/// Only page inspections carry `target`, and only they report an environment
/// (`<product>@<revision>`) plus the host-platform limitation.
pub fn create_electron_evidence(
    operation: &str,
    parameters: Value,
    result: Value,
) -> Result<Evidence, WebError> {
    let inspection = result.get("target").is_some();
    let predicate_type = if operation == OPERATION {
        "rea.electron-target-list"
    } else {
        "rea.electron-page-inspection"
    };
    let environment = inspection.then(|| ExecutionEnvironment {
        id: format!(
            "{}@{}",
            result["browser"]["product"].as_str().unwrap_or_default(),
            result["browser"]["revision"].as_str().unwrap_or_default()
        ),
        platform: "unknown".to_string(),
        architecture: "unknown".to_string(),
        isolation: IsolationLevel::None,
    });
    // REA createEvidence prepends the subject-unavailable reason.
    let mut limitations = vec!["Artifact identity is unavailable for this observation.".to_string()];
    if let Some(items) = result["limitations"].as_array() {
        limitations.extend(items.iter().filter_map(|item| item.as_str().map(str::to_string)));
    }
    if inspection {
        limitations.push("Browser host platform and architecture were not observed.".to_string());
    }
    create_evidence(
        None,
        EvidenceProvider {
            id: CDP_ELECTRON_PROVIDER_ID.to_string(),
            name: CDP_ELECTRON_PROVIDER_NAME.to_string(),
            version: Some(CDP_ELECTRON_PROVIDER_VERSION.to_string()),
        },
        EvidenceObservation {
            predicate_type: Some(predicate_type.to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ExternalService),
            environment,
            limitations: Some(limitations),
            locations: Some(vec![]),
            evidence_links: Some(vec![]),
        },
    )
    .map_err(WebError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp_endpoint::{CdpBrowserVersion, CdpEndpointTarget, CdpWebSocketEndpoint};

    fn target(id: &str, kind: &str, url: &str) -> CdpEndpointTarget {
        CdpEndpointTarget {
            id: id.to_string(),
            target_type: kind.to_string(),
            title: format!("title {id}"),
            url: url.to_string(),
            attached: false,
            web_socket: None,
        }
    }

    #[test]
    fn classifies_targets_by_type_and_file_scope() {
        let fixture = std::fs::canonicalize(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/web/electron_app/index.html"
        ))
        .unwrap();
        let url = url::Url::from_file_path(&fixture).unwrap().to_string();
        let discovery = CdpEndpointDiscovery {
            web_socket: CdpWebSocketEndpoint::Browser {
                url: "ws://127.0.0.1:9/devtools/browser/x".to_string(),
            },
            version: CdpBrowserVersion {
                product: "Electron/1".to_string(),
                protocol_version: "1.3".to_string(),
                revision: "r".to_string(),
                user_agent: "ua".to_string(),
                js_version: "v8".to_string(),
            },
            targets: vec![
                target("B", "page", &url),
                target("A", "page", &url),
                target("C", "page", "https://example.com/"),
                target("D", "service_worker", &url),
                target("E", "page", "file:///definitely/missing.html"),
            ],
        };
        let list = electron_target_list(&discovery);
        assert_eq!(list["targets"][0]["target_id"], "A");
        assert_eq!(list["targets"][1]["target_id"], "B");
        assert_eq!(list["targets"][0]["file_path"], fixture.to_str().unwrap());
        assert_eq!(list["excluded"], json!({ "unsupported_url": 2, "non_page": 1 }));
        assert_eq!(list["limitations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn input_is_strict_loopback() {
        assert_eq!(
            parse_list_electron_targets_input(&json!({ "cdp_endpoint": "http://127.0.0.1:9222/" })).unwrap(),
            "http://127.0.0.1:9222"
        );
        for bad in [
            json!({}),
            json!({ "cdp_endpoint": "http://example.com:9222" }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "allowed_origins": [] }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "extra": 1 }),
        ] {
            assert!(parse_list_electron_targets_input(&bad).is_err(), "{bad}");
        }
    }
}
