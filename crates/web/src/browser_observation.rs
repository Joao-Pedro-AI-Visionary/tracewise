//! Shared browser observation scope: input validation, URL sanitization,
//! failure reasons and Evidence envelopes (port of REA domain/browserObservation.ts,
//! domain/browserObservationError.ts and application/BrowserEvidence.ts).

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, ExecutionEnvironment, IsolationLevel,
};
use url::Url;

use crate::error::WebError;

pub const CDP_BROWSER_PROVIDER_ID: &str = "rea-cdp-browser";
pub const CDP_BROWSER_PROVIDER_NAME: &str = "REA Chrome DevTools Protocol observation provider";
pub const CDP_BROWSER_PROVIDER_VERSION: &str = "2";

/// Chrome switches required for the experimental WebMCP CDP domain and page tools.
pub const CHROME_WEBMCP_LAUNCH_ARGS: &[&str] = &[
    "--enable-experimental-web-platform-features",
    "--enable-features=WebMCP,DevToolsWebMCPSupport",
];

/// Stable failure reasons shared by the CDP adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserFailureReason {
    EndpointUnreachable,
    InvalidEndpointResponse,
    TargetNotFound,
    TargetNotAllowed,
    TargetChanged,
    ProtocolError,
    Disconnected,
    PayloadLimit,
    Timeout,
}

impl BrowserFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndpointUnreachable => "endpoint_unreachable",
            Self::InvalidEndpointResponse => "invalid_endpoint_response",
            Self::TargetNotFound => "target_not_found",
            Self::TargetNotAllowed => "target_not_allowed",
            Self::TargetChanged => "target_changed",
            Self::ProtocolError => "protocol_error",
            Self::Disconnected => "disconnected",
            Self::PayloadLimit => "payload_limit",
            Self::Timeout => "timeout",
        }
    }

    /// Public error code from REA's analysis error projection.
    pub fn error_code(self) -> &'static str {
        match self {
            Self::Timeout => "provider_timeout",
            Self::PayloadLimit => "truncated",
            Self::TargetNotFound | Self::TargetNotAllowed | Self::TargetChanged => {
                "target_unavailable"
            }
            Self::EndpointUnreachable | Self::Disconnected => "provider_unavailable",
            Self::InvalidEndpointResponse | Self::ProtocolError => "unreadable_output",
        }
    }
}

/// Build a browser observation failure for one public operation.
pub fn browser_error(
    operation: &str,
    reason: BrowserFailureReason,
    detail: Option<String>,
) -> WebError {
    WebError::BrowserObservation {
        operation: operation.to_string(),
        reason: reason.as_str().to_string(),
        code: reason.error_code().to_string(),
        user_message: detail.unwrap_or_else(|| failure_message(operation, reason)),
    }
}

fn failure_message(operation: &str, reason: BrowserFailureReason) -> String {
    match reason {
        BrowserFailureReason::Timeout => format!("{operation} exceeded its execution deadline. Review the target's responsiveness and retained observations before retrying."),
        BrowserFailureReason::EndpointUnreachable => format!("{operation} could not reach the selected loopback debugging endpoint. Verify that the target process is running with debugging enabled and that the endpoint's port matches it, then retry."),
        BrowserFailureReason::TargetNotFound => format!("{operation} could not find the selected target at the debugging endpoint. Refresh target discovery for that endpoint and retry with a returned target ID."),
        BrowserFailureReason::Disconnected => format!("{operation} lost its debugging connection. Verify that the target process is still running, refresh target discovery, and retry the observation."),
        _ => format!("Browser observation {operation} failed: {}", reason.as_str()),
    }
}

fn input_error(operation: &str, path: &[&str], message: impl Into<String>) -> WebError {
    let message = message.into();
    WebError::Input {
        operation: operation.to_string(),
        path: path.iter().map(|p| p.to_string()).collect(),
        reason: "invalid_value".to_string(),
        message,
    }
}

/// Validated request scope shared by endpoint-backed browser tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserScope {
    /// Normalized loopback endpoint origin, e.g. `http://127.0.0.1:9222`.
    pub cdp_endpoint: String,
    /// Deduplicated, sorted exact HTTP(S) origins (empty = unrestricted).
    pub allowed_origins: Vec<String>,
}

/// Parse the strict `{cdp_endpoint, allowed_origins}` object plus `extra` keys.
pub fn parse_browser_scope(
    operation: &str,
    args: &Value,
    extra: &[&str],
) -> Result<(BrowserScope, Map<String, Value>), WebError> {
    let object = args
        .as_object()
        .ok_or_else(|| input_error(operation, &[], "Expected an object"))?;
    for key in object.keys() {
        if key != "cdp_endpoint" && key != "allowed_origins" && !extra.contains(&key.as_str()) {
            return Err(input_error(
                operation,
                &[key.as_str()],
                format!("Unrecognized key: \"{key}\""),
            ));
        }
    }
    let endpoint = match object.get("cdp_endpoint") {
        Some(Value::String(s)) if !s.is_empty() => s,
        _ => {
            return Err(input_error(
                operation,
                &["cdp_endpoint"],
                "cdp_endpoint must be a non-empty string",
            ))
        }
    };
    let cdp_endpoint = parse_cdp_endpoint(endpoint).ok_or_else(|| {
        input_error(
            operation,
            &["cdp_endpoint"],
            "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1",
        )
    })?;
    let mut allowed_origins = Vec::new();
    match object.get("allowed_origins") {
        None => {}
        Some(Value::Array(items)) => {
            for item in items {
                let origin = item
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .and_then(parse_exact_origin)
                    .ok_or_else(|| {
                        input_error(
                            operation,
                            &["allowed_origins"],
                            "Expected one exact HTTP(S) origin without a path or wildcard",
                        )
                    })?;
                allowed_origins.push(origin);
            }
        }
        Some(_) => {
            return Err(input_error(
                operation,
                &["allowed_origins"],
                "allowed_origins must be an array of origins",
            ))
        }
    }
    allowed_origins.sort();
    allowed_origins.dedup();
    Ok((
        BrowserScope {
            cdp_endpoint,
            allowed_origins,
        },
        object.clone(),
    ))
}

/// Read a required string field and trim it (`z.string().trim().min(1)`).
pub fn trimmed_string_field(
    operation: &str,
    object: &Map<String, Value>,
    key: &str,
) -> Result<String, WebError> {
    match object.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        _ => Err(input_error(
            operation,
            &[key],
            format!("{key} must be a non-empty string"),
        )),
    }
}

fn is_literal_loopback_hostname(hostname: &str) -> bool {
    hostname == "127.0.0.1" || hostname == "[::1]" || hostname == "::1"
}

/// Loopback-only HTTP endpoint accepted for a user-owned CDP browser.
pub fn parse_cdp_endpoint(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "http"
        || !url.host_str().is_some_and(is_literal_loopback_hostname)
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || !url.query().unwrap_or("").is_empty()
        || !url.fragment().unwrap_or("").is_empty()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// Exact normalized HTTP(S) authority used for browser observation scope.
pub fn parse_exact_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if (url.scheme() != "http" && url.scheme() != "https")
        || url.host_str().is_none_or(|h| h.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || !url.query().unwrap_or("").is_empty()
        || !url.fragment().unwrap_or("").is_empty()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// Sanitized browser URL: userinfo credentials removed, everything else kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedBrowserUrl {
    pub url: String,
    pub origin: Option<String>,
    pub query_parameter_names: Vec<String>,
    pub redacted: bool,
}

impl SanitizedBrowserUrl {
    pub fn to_json(&self) -> Value {
        json!({
            "url": self.url,
            "origin": self.origin,
            "query_parameter_names": self.query_parameter_names,
            "redacted": self.redacted,
        })
    }
}

/// Preserve local URL data while removing only URL userinfo credentials.
pub fn sanitize_browser_url(value: &str) -> SanitizedBrowserUrl {
    let Ok(parsed) = Url::parse(value) else {
        return SanitizedBrowserUrl {
            url: value.to_string(),
            origin: None,
            query_parameter_names: vec![],
            redacted: false,
        };
    };
    let had_credentials = !parsed.username().is_empty() || parsed.password().is_some();
    let names = parsed.query_pairs().map(|(k, _)| k.into_owned()).collect();
    let origin = parsed.origin();
    let url = if had_credentials {
        remove_url_user_info(value, &parsed)
    } else {
        value.to_string()
    };
    SanitizedBrowserUrl {
        url,
        origin: origin
            .is_tuple()
            .then(|| origin.ascii_serialization()),
        query_parameter_names: names,
        redacted: had_credentials,
    }
}

fn remove_url_user_info(value: &str, parsed: &Url) -> String {
    let authority_start = match value.find("://") {
        Some(idx) => idx + 3,
        None if value.starts_with("//") => 2,
        None => return credential_free_href(parsed),
    };
    let remaining = &value[authority_start..];
    let authority_end = remaining
        .find(['/', '?', '#'])
        .map_or(value.len(), |d| authority_start + d);
    let authority = &value[authority_start..authority_end];
    let Some(user_info_end) = authority.rfind('@') else {
        return credential_free_href(parsed);
    };
    let candidate = format!(
        "{}{}{}",
        &value[..authority_start],
        &authority[user_info_end + 1..],
        &value[authority_end..]
    );
    match Url::parse(&candidate) {
        Ok(url) if url.username().is_empty() && url.password().is_none() => candidate,
        _ => credential_free_href(parsed),
    }
}

fn credential_free_href(parsed: &Url) -> String {
    let mut url = parsed.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

/// Sanitized URL whose origin is inside the allowed set.
pub fn allowed_sanitized_url(
    value: Option<&str>,
    allowed_origins: &[String],
) -> Option<SanitizedBrowserUrl> {
    let sanitized = sanitize_browser_url(value?);
    match &sanitized.origin {
        Some(origin) if allowed_origins.contains(origin) => Some(sanitized),
        _ => None,
    }
}

/// Wrap one browser observation result in a `rea.*` Evidence envelope.
pub fn create_browser_evidence(
    operation: &str,
    predicate_type: &str,
    parameters: Value,
    result: Value,
) -> Result<Evidence, WebError> {
    // Bundle analysis has no browser identity; runtime and page tools do.
    // A missing browser object is an absent environment, not a synthetic "@".
    let environment = result.get("browser").and_then(Value::as_object).map(|browser| ExecutionEnvironment {
        id: format!(
            "{}@{}",
            browser.get("product").and_then(Value::as_str).unwrap_or_default(),
            browser.get("revision").and_then(Value::as_str).unwrap_or_default()
        ),
        platform: "unknown".to_string(),
        architecture: "unknown".to_string(),
        isolation: IsolationLevel::None,
    });
    let mut limitations =
        vec!["Artifact identity is unavailable for this observation.".to_string()];
    if let Some(items) = result["limitations"].as_array() {
        limitations.extend(items.iter().filter_map(|l| l.as_str().map(str::to_string)));
    }
    if environment.is_some() {
        limitations.push("Browser host platform and architecture were not observed.".to_string());
    }

    let provider = EvidenceProvider {
        id: CDP_BROWSER_PROVIDER_ID.to_string(),
        name: CDP_BROWSER_PROVIDER_NAME.to_string(),
        version: Some(CDP_BROWSER_PROVIDER_VERSION.to_string()),
    };
    let observation = EvidenceObservation {
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
    };
    create_evidence(None, provider, observation).map_err(WebError::from)
}

/// Public JSON body for a browser observation tool failure.
pub fn browser_error_body(error: &WebError) -> Option<Value> {
    match error {
        WebError::BrowserObservation {
            operation,
            reason,
            code,
            user_message,
        } => Some(json!({
            "error": {
                "code": code,
                "message": user_message,
                "retryable": false,
                "details": { "operation": operation, "reason": reason },
            }
        })),
        WebError::CdpCommandRejected {
            operation,
            code,
            message,
        } => Some(json!({
            "error": {
                "code": "unreadable_output",
                "message": format!("CDP rejected a command during {operation}: {message}"),
                "retryable": false,
                "details": { "operation": operation, "reason": "command_rejected", "cdp_code": code },
            }
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_must_be_explicit_loopback_http() {
        assert_eq!(
            parse_cdp_endpoint("http://127.0.0.1:9222/").as_deref(),
            Some("http://127.0.0.1:9222")
        );
        assert_eq!(
            parse_cdp_endpoint("http://[::1]:9222").as_deref(),
            Some("http://[::1]:9222")
        );
        for bad in [
            "http://localhost:9222",
            "http://127.0.0.1",
            "https://127.0.0.1:9222",
            "http://10.0.0.1:9222",
            "http://127.0.0.1:9222/json",
            "http://a:b@127.0.0.1:9222",
            "http://127.0.0.1:9222/?x=1",
        ] {
            assert_eq!(parse_cdp_endpoint(bad), None, "{bad}");
        }
    }

    #[test]
    fn origins_are_exact_and_normalized() {
        assert_eq!(
            parse_exact_origin("https://Example.com:443/").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(parse_exact_origin("https://example.com/path"), None);
        assert_eq!(parse_exact_origin("ftp://example.com"), None);
        assert_eq!(parse_exact_origin("https://*.example.com"), None);
        let (scope, _) = parse_browser_scope(
            "list_browser_targets",
            &json!({
                "cdp_endpoint": "http://127.0.0.1:9222",
                "allowed_origins": ["https://b.test", "https://a.test/", "https://b.test"]
            }),
            &[],
        )
        .unwrap();
        assert_eq!(scope.allowed_origins, vec!["https://a.test", "https://b.test"]);
        assert!(parse_browser_scope(
            "list_browser_targets",
            &json!({"cdp_endpoint": "http://127.0.0.1:9222", "x": 1}),
            &[],
        )
        .is_err());
    }

    #[test]
    fn sanitize_removes_only_credentials() {
        let s = sanitize_browser_url("https://user:pw@example.com/a?b=1&c=2#f");
        assert_eq!(s.url, "https://example.com/a?b=1&c=2#f");
        assert_eq!(s.origin.as_deref(), Some("https://example.com"));
        assert_eq!(s.query_parameter_names, vec!["b", "c"]);
        assert!(s.redacted);
        assert_eq!(sanitize_browser_url("about:blank").origin, None);
        assert_eq!(sanitize_browser_url("chrome://newtab/").origin, None);
    }
}
