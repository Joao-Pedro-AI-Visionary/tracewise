//! `list_browser_targets` (port of REA CdpBrowserProvider.listTargets).

use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{
    create_browser_evidence, parse_browser_scope, sanitize_browser_url, BrowserScope,
};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery};
use crate::error::WebError;

const OPERATION: &str = "list_browser_targets";

/// Parse and normalize `list_browser_targets` arguments.
pub fn parse_list_browser_targets_input(args: &Value) -> Result<BrowserScope, WebError> {
    parse_browser_scope(OPERATION, args, &[]).map(|(scope, _)| scope)
}

/// List page targets within the endpoint and origin scope in the request.
pub async fn list_browser_targets(input: &BrowserScope) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(&input.cdp_endpoint, OPERATION).await?;
    let result = browser_target_list(&discovery, &input.allowed_origins);
    create_browser_evidence(
        OPERATION,
        "rea.browser-target-list",
        json!({
            "cdp_endpoint": input.cdp_endpoint,
            "allowed_origins": input.allowed_origins,
        }),
        result,
    )
}

/// Project discovery into the public target list; `allowed_origins` empty
/// means every page target with a tuple origin is in scope.
pub fn browser_target_list(discovery: &CdpEndpointDiscovery, allowed_origins: &[String]) -> Value {
    let mut allowed = Vec::new();
    let (mut disallowed_origin, mut unsupported_url, mut non_page, mut unconnectable) =
        (0u64, 0u64, 0u64, 0u64);
    for target in &discovery.targets {
        if target.target_type != "page" {
            non_page += 1;
            continue;
        }
        let url = sanitize_browser_url(&target.url);
        let Some(origin) = url.origin else {
            unsupported_url += 1;
            continue;
        };
        if !allowed_origins.is_empty() && !allowed_origins.contains(&origin) {
            disallowed_origin += 1;
            continue;
        }
        if discovery.target_web_socket(target).is_none() {
            unconnectable += 1;
            continue;
        }
        allowed.push((
            target.id.clone(),
            json!({
                "target_id": target.id,
                "type": target.target_type,
                "title": target.title,
                "url": url.url,
                "origin": origin,
                "attached": target.attached,
            }),
        ));
    }
    allowed.sort_by(|(a, _), (b, _)| {
        a.to_lowercase()
            .cmp(&b.to_lowercase())
            .then_with(|| a.cmp(b))
    });

    let mut limitations = vec![if allowed_origins.is_empty() {
        "All page targets with supported HTTP(S) URLs are listed.".to_string()
    } else {
        "Only page targets whose current URL matches an explicitly requested exact origin are listed."
            .to_string()
    }];
    if unconnectable > 0 {
        limitations.push(format!(
            "{unconnectable} otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded."
        ));
    }
    json!({
        "browser": discovery.version.to_json(),
        "targets": allowed.into_iter().map(|(_, t)| t).collect::<Vec<_>>(),
        "excluded": {
            "disallowed_origin": disallowed_origin,
            "unsupported_url": unsupported_url,
            "non_page": non_page,
        },
        "limitations": limitations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp_endpoint::{CdpBrowserVersion, CdpEndpointTarget, CdpWebSocketEndpoint};

    fn target(id: &str, kind: &str, url: &str, ws: bool) -> CdpEndpointTarget {
        CdpEndpointTarget {
            id: id.to_string(),
            target_type: kind.to_string(),
            title: format!("t{id}"),
            url: url.to_string(),
            attached: false,
            web_socket: ws.then(|| CdpWebSocketEndpoint::Page {
                target_id: id.to_string(),
                url: format!("ws://127.0.0.1:9222/devtools/page/{id}"),
            }),
        }
    }

    fn discovery(web_socket: CdpWebSocketEndpoint) -> CdpEndpointDiscovery {
        CdpEndpointDiscovery {
            web_socket,
            version: CdpBrowserVersion {
                product: "Chrome/1".into(),
                protocol_version: "1.3".into(),
                revision: "r".into(),
                user_agent: "ua".into(),
                js_version: "v8".into(),
            },
            targets: vec![
                target("C", "page", "https://b.test/x", true),
                target("A", "page", "https://a.test/", true),
                target("B", "page", "about:blank", true),
                target("D", "service_worker", "https://a.test/sw.js", true),
                target("E", "page", "https://a.test/nows", false),
            ],
        }
    }

    #[test]
    fn filters_by_kind_origin_and_transport() {
        let browser = discovery(CdpWebSocketEndpoint::Browser {
            url: "ws://127.0.0.1:9222/devtools/browser/x".into(),
        });
        let all = browser_target_list(&browser, &[]);
        let ids: Vec<_> = all["targets"].as_array().unwrap().iter().map(|t| t["target_id"].clone()).collect();
        assert_eq!(ids, vec![json!("A"), json!("C"), json!("E")]);
        assert_eq!(all["excluded"], json!({"disallowed_origin": 0, "unsupported_url": 1, "non_page": 1}));

        let scoped = browser_target_list(&browser, &["https://a.test".to_string()]);
        assert_eq!(scoped["targets"].as_array().unwrap().len(), 2);
        assert_eq!(scoped["excluded"]["disallowed_origin"], 1);

        // A page-scoped discovery socket only reaches targets with their own socket.
        let page = discovery(CdpWebSocketEndpoint::Page {
            target_id: "Z".into(),
            url: "ws://127.0.0.1:9222/devtools/page/Z".into(),
        });
        let listed = browser_target_list(&page, &[]);
        assert_eq!(listed["targets"].as_array().unwrap().len(), 2);
        assert_eq!(listed["limitations"].as_array().unwrap().len(), 2);
    }
}
