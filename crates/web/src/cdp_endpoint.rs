//! CDP HTTP discovery (`/json/version`, `/json/list`) and WebSocket endpoint
//! validation (port of REA browser/CdpEndpoint.ts).

use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};
use url::Url;

use crate::browser_observation::{browser_error, sanitize_browser_url, BrowserFailureReason};
use crate::error::WebError;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Validated CDP discovery socket and its command-routing scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpWebSocketEndpoint {
    Browser { url: String },
    Page { target_id: String, url: String },
}

impl CdpWebSocketEndpoint {
    pub fn url(&self) -> &str {
        match self {
            Self::Browser { url } | Self::Page { url, .. } => url,
        }
    }
}

/// Browser identity reported by `/json/version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpBrowserVersion {
    pub product: String,
    pub protocol_version: String,
    pub revision: String,
    pub user_agent: String,
    pub js_version: String,
}

impl CdpBrowserVersion {
    pub fn to_json(&self) -> Value {
        json!({
            "product": self.product,
            "protocol_version": self.protocol_version,
            "revision": self.revision,
            "user_agent": self.user_agent,
            "js_version": self.js_version,
        })
    }
}

/// Bounded discovery target with an optional validated direct transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEndpointTarget {
    pub id: String,
    pub target_type: String,
    pub title: String,
    pub url: String,
    pub attached: bool,
    /// Always `CdpWebSocketEndpoint::Page` for this target's id when present.
    pub web_socket: Option<CdpWebSocketEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEndpointDiscovery {
    pub web_socket: CdpWebSocketEndpoint,
    pub version: CdpBrowserVersion,
    pub targets: Vec<CdpEndpointTarget>,
}

impl CdpEndpointDiscovery {
    /// Select a browser attachment socket or a direct socket for one target.
    pub fn target_web_socket<'a>(&'a self, target: &'a CdpEndpointTarget) -> Option<&'a CdpWebSocketEndpoint> {
        match &self.web_socket {
            CdpWebSocketEndpoint::Browser { .. } => Some(&self.web_socket),
            CdpWebSocketEndpoint::Page { target_id, .. } => target
                .web_socket
                .as_ref()
                .or_else(|| (*target_id == target.id).then_some(&self.web_socket)),
        }
    }
}

/// Read CDP discovery endpoints without following redirects.
pub async fn discover_cdp_endpoint(
    endpoint: &str,
    operation: &str,
) -> Result<CdpEndpointDiscovery, WebError> {
    let base = Url::parse(endpoint)
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(DISCOVERY_TIMEOUT)
        .build()
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let version_input = read_cdp_json(&client, &base, "/json/version", operation).await?;
    let targets_input = read_cdp_json(&client, &base, "/json/list", operation).await?;
    let invalid = || browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None);

    let version = parse_version(&version_input).ok_or_else(invalid)?;
    let raw_targets = targets_input.as_array().ok_or_else(invalid)?;
    let mut targets = Vec::with_capacity(raw_targets.len());
    for raw in raw_targets {
        targets.push(parse_target(endpoint, raw).ok_or_else(invalid)?);
    }
    Ok(CdpEndpointDiscovery {
        web_socket: safe_cdp_web_socket_endpoint(endpoint, &version.1).ok_or_else(invalid)?,
        version: version.0,
        targets,
    })
}

async fn read_cdp_json(
    client: &reqwest::Client,
    base: &Url,
    path: &str,
    operation: &str,
) -> Result<Value, WebError> {
    let url = base
        .join(path)
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            let reason = if e.is_timeout() {
                BrowserFailureReason::Timeout
            } else {
                BrowserFailureReason::EndpointUnreachable
            };
            browser_error(operation, reason, None)
        })?;
    if response.status().as_u16() != 200 {
        return Err(browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None));
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    serde_json::from_slice(&body)
        .map_err(|_| browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None))
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str, min_len: usize) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| s.len() >= min_len)
}

fn parse_version(input: &Value) -> Option<(CdpBrowserVersion, String)> {
    let object = input.as_object()?;
    Some((
        CdpBrowserVersion {
            product: string_field(object, "Browser", 1)?.to_string(),
            protocol_version: string_field(object, "Protocol-Version", 1)?.to_string(),
            revision: string_field(object, "WebKit-Version", 0)?.to_string(),
            user_agent: string_field(object, "User-Agent", 0)?.to_string(),
            js_version: string_field(object, "V8-Version", 0)?.to_string(),
        },
        string_field(object, "webSocketDebuggerUrl", 1)?.to_string(),
    ))
}

fn parse_target(endpoint: &str, input: &Value) -> Option<CdpEndpointTarget> {
    let object = input.as_object()?;
    let id = string_field(object, "id", 1)?.to_string();
    let target_type = string_field(object, "type", 1)?.to_string();
    let url = string_field(object, "url", 0)?.to_string();
    let title = match object.get("title") {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return None,
    };
    let attached = match object.get("attached") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let web_socket = match object.get("webSocketDebuggerUrl") {
        None => None,
        Some(Value::String(s)) if !s.is_empty() => match safe_cdp_web_socket_endpoint(endpoint, s)
        {
            Some(ws @ CdpWebSocketEndpoint::Page { .. })
                if matches!(&ws, CdpWebSocketEndpoint::Page { target_id, .. } if *target_id == id) =>
            {
                Some(ws)
            }
            _ => None,
        },
        Some(_) => return None,
    };
    Some(CdpEndpointTarget {
        title: sanitize_target_title(&title, &url),
        id,
        target_type,
        url,
        attached,
        web_socket,
    })
}

/// Accept only same-port, credential-free `ws:` devtools sockets and pin
/// their host to the trusted endpoint host.
fn safe_cdp_web_socket_endpoint(endpoint: &str, reported: &str) -> Option<CdpWebSocketEndpoint> {
    let mut parsed = Url::parse(reported).ok()?;
    let trusted = Url::parse(endpoint).ok()?;
    if parsed.scheme() != "ws"
        || parsed.port() != trusted.port()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !parsed.query().unwrap_or("").is_empty()
        || !parsed.fragment().unwrap_or("").is_empty()
    {
        return None;
    }
    let scope = cdp_web_socket_path(parsed.path())?;
    parsed.set_host(trusted.host_str()).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let url = parsed.to_string();
    Some(match scope {
        None => CdpWebSocketEndpoint::Browser { url },
        Some(target_id) => CdpWebSocketEndpoint::Page { target_id, url },
    })
}

/// `Some(None)` for a browser socket, `Some(Some(id))` for a page socket.
fn cdp_web_socket_path(path: &str) -> Option<Option<String>> {
    if path_identifier(path, "/devtools/browser/").is_some() {
        return Some(None);
    }
    path_identifier(path, "/devtools/page/").map(Some)
}

fn path_identifier(path: &str, prefix: &str) -> Option<String> {
    let identifier = path.strip_prefix(prefix)?;
    (!identifier.is_empty() && !identifier.contains('/')).then(|| identifier.to_string())
}

fn sanitize_target_title(value: &str, target_url: &str) -> String {
    match Url::parse(value) {
        Ok(url) if url.scheme() == "http" || url.scheme() == "https" => {
            sanitize_browser_url(value).url
        }
        _ => sanitize_target_url_alias(value, target_url),
    }
}

/// Redact credentials from same-origin URL aliases embedded in a title.
fn sanitize_target_url_alias(value: &str, target_url: &str) -> String {
    let Ok(parsed) = Url::parse(target_url) else {
        return value.to_string();
    };
    // Only hierarchical targets have a host to search for; opaque targets
    // (about:, data:, chrome:) cannot carry userinfo aliases.
    let Some(host) = url_host(&parsed) else {
        return value.to_string();
    };
    let origin = parsed.origin().ascii_serialization();
    let mut markers = vec![origin, format!("//{host}"), host.clone()];
    if parsed.path() != "/" {
        markers.push(parsed.path().to_string());
    }
    let pattern = format!(
        "(?:{})[^\\s<>\"']*",
        markers.iter().map(|m| regex::escape(m)).collect::<Vec<_>>().join("|")
    );
    let Ok(regex) = Regex::new(&pattern) else {
        return value.to_string();
    };
    regex
        .replace_all(value, |caps: &regex::Captures<'_>| {
            sanitize_same_origin_title_url(&caps[0], &parsed, &host)
        })
        .into_owned()
}

fn url_host(url: &Url) -> Option<String> {
    let host = url.host_str().filter(|h| !h.is_empty())?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn sanitize_same_origin_title_url(candidate: &str, target: &Url, host: &str) -> String {
    let scheme = target.scheme();
    let parsed = if candidate.starts_with("//") {
        Url::parse(&format!("{scheme}:{candidate}"))
    } else if candidate.starts_with(host) {
        Url::parse(&format!("{scheme}://{candidate}"))
    } else {
        Url::parse(&target.origin().ascii_serialization()).and_then(|o| o.join(candidate))
    };
    match parsed {
        Ok(url)
            if url.origin() == target.origin()
                && (!url.username().is_empty() || url.password().is_some()) =>
        {
            sanitize_browser_url(candidate).url
        }
        _ => candidate.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_socket_endpoint_is_pinned_to_trusted_host() {
        let ws = safe_cdp_web_socket_endpoint(
            "http://127.0.0.1:9222",
            "ws://localhost:9222/devtools/browser/abc",
        )
        .unwrap();
        assert_eq!(
            ws,
            CdpWebSocketEndpoint::Browser {
                url: "ws://127.0.0.1:9222/devtools/browser/abc".to_string()
            }
        );
        let page =
            safe_cdp_web_socket_endpoint("http://127.0.0.1:9222", "ws://127.0.0.1:9222/devtools/page/T1")
                .unwrap();
        assert!(matches!(page, CdpWebSocketEndpoint::Page { ref target_id, .. } if target_id == "T1"));
        for bad in [
            "ws://127.0.0.1:9333/devtools/browser/abc",
            "wss://127.0.0.1:9222/devtools/browser/abc",
            "ws://u:p@127.0.0.1:9222/devtools/browser/abc",
            "ws://127.0.0.1:9222/devtools/browser/abc?x=1",
            "ws://127.0.0.1:9222/devtools/other/abc",
            "ws://127.0.0.1:9222/devtools/page/a/b",
        ] {
            assert_eq!(safe_cdp_web_socket_endpoint("http://127.0.0.1:9222", bad), None, "{bad}");
        }
    }

    #[test]
    fn titles_lose_url_credentials() {
        assert_eq!(
            sanitize_target_title("https://u:p@example.com/x", "https://example.com/x"),
            "https://example.com/x"
        );
        assert_eq!(
            sanitize_target_title("Plain title", "https://example.com/"),
            "Plain title"
        );
    }

    #[test]
    fn target_schema_defaults_and_rejections() {
        let t = parse_target(
            "http://127.0.0.1:9222",
            &json!({"id": "A", "type": "page", "url": "https://example.com/"}),
        )
        .unwrap();
        assert_eq!(t.title, "");
        assert!(!t.attached);
        assert_eq!(t.web_socket, None);
        assert!(parse_target(
            "http://127.0.0.1:9222",
            &json!({"id": "", "type": "page", "url": "x"})
        )
        .is_none());
        let mismatched = parse_target(
            "http://127.0.0.1:9222",
            &json!({"id": "A", "type": "page", "url": "x",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/B"}),
        )
        .unwrap();
        assert_eq!(mismatched.web_socket, None);
    }
}
