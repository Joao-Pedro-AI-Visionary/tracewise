//! `capture_web_screenshot` (port of REA browser/CdpScreenshot.ts,
//! domain/webScreenshot.ts and CdpBrowserProvider.captureScreenshot).

use base64::prelude::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{
    allowed_sanitized_url, browser_error, create_browser_evidence, parse_browser_scope,
    sanitize_browser_url, trimmed_string_field, BrowserFailureReason, BrowserScope,
};
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::error::WebError;

const OPERATION: &str = "capture_web_screenshot";
const CLEANUP_DOMAINS: [&str; 4] = ["Network", "Debugger", "Runtime", "Page"];
const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureWebScreenshotInput {
    pub scope: BrowserScope,
    pub target_id: String,
}

/// Parse and normalize `capture_web_screenshot` arguments.
pub fn parse_capture_web_screenshot_input(args: &Value) -> Result<CaptureWebScreenshotInput, WebError> {
    let (scope, object) = parse_browser_scope(OPERATION, args, &["target_id"])?;
    let target_id = trimmed_string_field(OPERATION, &object, "target_id")?;
    Ok(CaptureWebScreenshotInput { scope, target_id })
}

fn fail(reason: BrowserFailureReason) -> WebError {
    browser_error(OPERATION, reason, None)
}

/// Select one page target and derive its origin scope before opening a session.
fn authorize_target<'a>(
    discovery: &'a CdpEndpointDiscovery,
    input: &CaptureWebScreenshotInput,
) -> Result<(&'a CdpEndpointTarget, Vec<String>), WebError> {
    let target = discovery
        .targets
        .iter()
        .find(|t| t.id == input.target_id)
        .ok_or_else(|| {
            browser_error(
                OPERATION,
                BrowserFailureReason::TargetNotFound,
                Some(format!(
                    "Target {} was not found at the selected endpoint.",
                    input.target_id
                )),
            )
        })?;
    let origin = sanitize_browser_url(&target.url).origin;
    let allowed = &input.scope.allowed_origins;
    match origin {
        Some(origin)
            if target.target_type == "page"
                && (allowed.is_empty() || allowed.contains(&origin)) =>
        {
            let scope = if allowed.is_empty() { vec![origin] } else { allowed.clone() };
            Ok((target, scope))
        }
        _ => Err(browser_error(
            OPERATION,
            BrowserFailureReason::TargetNotAllowed,
            Some(format!(
                "Target {} must be an HTTP(S) page in the selected origin scope.",
                input.target_id
            )),
        )),
    }
}

/// Capture the current viewport of one authorized target.
pub async fn capture_web_screenshot(input: &CaptureWebScreenshotInput) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(&input.scope.cdp_endpoint, OPERATION).await?;
    let (target, origins) = authorize_target(&discovery, input)?;
    let mut session = open_cdp_target_session(&discovery, target, OPERATION).await?;
    let captured = capture_viewport(&mut session, &origins).await;
    close_cdp_target_session(session, &CLEANUP_DOMAINS).await;
    let captured = captured?;

    let result = json!({
        "browser": discovery.version.to_json(),
        "target": {
            "target_id": target.id,
            "url": captured.url,
            "origin": captured.origin,
        },
        "captured_at": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "viewport": { "width": captured.width, "height": captured.height },
        "artifact": web_screenshot_artifact(&captured.png),
        "completeness": empty_completeness(),
        "limitations": [
            "The screenshot contains the visible viewport, including on-screen content.",
            "REA does not scroll, evaluate JavaScript, or capture beyond the current viewport.",
        ],
    });
    create_browser_evidence(
        OPERATION,
        "rea.web-screenshot",
        json!({
            "cdp_endpoint": input.scope.cdp_endpoint,
            "allowed_origins": origins,
            "target_id": input.target_id,
        }),
        result,
    )
}

struct CapturedViewport {
    url: String,
    origin: String,
    width: u32,
    height: u32,
    png: Vec<u8>,
}

struct NavigationState {
    changed: bool,
    left_scope: bool,
    url: Option<String>,
    loader_id: Option<String>,
}

fn main_frame(frame_tree: &Map<String, Value>) -> Option<&Map<String, Value>> {
    frame_tree.get("frameTree")?.get("frame")?.as_object()
}

/// Capture without navigation, evaluation or page mutation; reject the
/// screenshot if the main frame navigated or left scope meanwhile.
async fn capture_viewport(
    session: &mut crate::cdp_connection::CdpTargetSession,
    origins: &[String],
) -> Result<CapturedViewport, WebError> {
    let session_id = session.session_id.clone();
    let sid = session_id.as_deref();
    let connection = &mut session.connection;
    connection.send("Page.enable", json!({}), sid).await?;
    let before = connection.send("Page.getFrameTree", json!({}), sid).await?;
    let initial_frame = main_frame(&before);
    let before_url = initial_frame
        .and_then(|f| f.get("url"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let authorized = allowed_sanitized_url(before_url.as_deref(), origins)
        .ok_or_else(|| fail(BrowserFailureReason::TargetNotAllowed))?;
    let main_frame_id = initial_frame
        .and_then(|f| f.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| fail(BrowserFailureReason::TargetNotAllowed))?;
    let mut navigation = NavigationState {
        changed: false,
        left_scope: false,
        url: before_url.clone(),
        loader_id: initial_frame
            .and_then(|f| f.get("loaderId"))
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    // Events delivered before this point predate the authorized frame tree.
    connection.take_events();

    let shot = connection
        .send(
            "Page.captureScreenshot",
            json!({ "format": "png", "fromSurface": true, "captureBeyondViewport": false }),
            sid,
        )
        .await;
    // A failed capture is reported first; the placeholder is never read.
    let after = if shot.is_ok() {
        connection.send("Page.getFrameTree", json!({}), sid).await
    } else {
        Ok(Map::new())
    };
    for event in connection.take_events() {
        if event.session_id.as_deref() == sid {
            observe_navigation(&event, &main_frame_id, origins, &mut navigation);
        }
    }
    let shot = shot?;
    let after = after?;

    let png = shot
        .get("data")
        .and_then(Value::as_str)
        .and_then(decode_canonical_base64)
        .ok_or_else(|| fail(BrowserFailureReason::PayloadLimit))?;
    let (width, height) = png_dimensions(&png)?;
    if navigation.left_scope {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    let after_url = main_frame(&after)
        .and_then(|f| f.get("url"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if navigation.changed
        || after_url != before_url
        || allowed_sanitized_url(after_url.as_deref(), origins).is_none()
    {
        return Err(fail(BrowserFailureReason::TargetChanged));
    }
    Ok(CapturedViewport {
        url: authorized.url,
        origin: authorized.origin.unwrap_or_default(),
        width,
        height,
        png,
    })
}

fn observe_navigation(
    event: &CdpEvent,
    main_frame_id: &str,
    origins: &[String],
    state: &mut NavigationState,
) {
    let params = &event.params;
    let (frame_id, frame) = match event.method.as_str() {
        "Page.frameNavigated" => (params.get("frame").and_then(|f| f.get("id")), params.get("frame")),
        "Page.frameRequestedNavigation" | "Page.navigatedWithinDocument" => {
            (params.get("frameId"), Some(params))
        }
        _ => return,
    };
    if frame_id.and_then(Value::as_str) != Some(main_frame_id) {
        return;
    }
    let frame_url = frame.and_then(|f| f.get("url")).and_then(Value::as_str);
    if event.method == "Page.frameNavigated" {
        let loader_id = frame.and_then(|f| f.get("loaderId")).and_then(Value::as_str);
        if state.loader_id.as_deref().is_some_and(|l| !l.is_empty())
            && loader_id == state.loader_id.as_deref()
            && frame_url == state.url.as_deref()
        {
            return;
        }
    }
    state.changed = true;
    if allowed_sanitized_url(frame_url, origins).is_none() {
        state.left_scope = true;
    }
}

/// Strict canonical base64 decoder used before digest validation.
pub fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    #[allow(clippy::manual_is_multiple_of)]
    if value.is_empty() || value.len() % 4 != 0 {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(value).ok()?;
    (BASE64_STANDARD.encode(&decoded) == value).then_some(decoded)
}

fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), WebError> {
    if bytes.len() < 24 || bytes[..8] != PNG_SIGNATURE || &bytes[12..16] != b"IHDR" {
        return Err(fail(BrowserFailureReason::ProtocolError));
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if width == 0 || height == 0 {
        return Err(fail(BrowserFailureReason::ProtocolError));
    }
    Ok((width, height))
}

/// Content-addressed inline PNG artifact.
pub fn web_screenshot_artifact(bytes: &[u8]) -> Value {
    json!({
        "sha256": hex::encode(Sha256::digest(bytes)),
        "bytes": bytes.len(),
        "media_type": "image/png",
        "data_base64": BASE64_STANDARD.encode(bytes),
    })
}

/// Completeness of a screenshot: no sections are captured, filtered or dropped.
fn empty_completeness() -> Value {
    json!({
        "status": "complete_within_window",
        "conditions": ["complete_within_window"],
        "policy_filtered_sections": [],
        "attach_limited_sections": [],
        "truncated_sections": [],
        "unavailable_sections": [],
        "excluded": [],
        "dropped_events": {
            "scripts": 0,
            "network_requests": 0,
            "console_events": 0,
            "websocket_connections": 0,
            "websocket_frames": 0,
            "webmcp_tools": 0,
            "timeline_events": 0,
            "total": 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_requires_trimmed_target_id() {
        let input = parse_capture_web_screenshot_input(&json!({
            "cdp_endpoint": "http://127.0.0.1:9222/",
            "target_id": "  T1 ",
        }))
        .unwrap();
        assert_eq!(input.target_id, "T1");
        assert_eq!(input.scope.cdp_endpoint, "http://127.0.0.1:9222");
        assert!(parse_capture_web_screenshot_input(&json!({
            "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "  "
        }))
        .is_err());
    }

    #[test]
    fn canonical_base64_and_png_header() {
        assert_eq!(decode_canonical_base64("AAE="), Some(vec![0, 1]));
        assert_eq!(decode_canonical_base64("AAF="), None);
        assert_eq!(decode_canonical_base64(""), None);
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend([0, 0, 0, 13]);
        png.extend(b"IHDR");
        png.extend(3u32.to_be_bytes());
        png.extend(2u32.to_be_bytes());
        assert_eq!(png_dimensions(&png).unwrap(), (3, 2));
        assert!(png_dimensions(&png[..20]).is_err());
    }

    #[test]
    fn navigation_events_mark_changes() {
        let origins = vec!["https://a.test".to_string()];
        let mut state = NavigationState {
            changed: false,
            left_scope: false,
            url: Some("https://a.test/".into()),
            loader_id: Some("L1".into()),
        };
        let same = CdpEvent {
            method: "Page.frameNavigated".into(),
            params: json!({"frame": {"id": "F", "loaderId": "L1", "url": "https://a.test/"}}),
            session_id: None,
        };
        observe_navigation(&same, "F", &origins, &mut state);
        assert!(!state.changed);
        let child = CdpEvent {
            method: "Page.frameRequestedNavigation".into(),
            params: json!({"frameId": "child", "url": "https://evil.test/"}),
            session_id: None,
        };
        observe_navigation(&child, "F", &origins, &mut state);
        assert!(!state.changed);
        let away = CdpEvent {
            method: "Page.frameRequestedNavigation".into(),
            params: json!({"frameId": "F", "url": "https://evil.test/"}),
            session_id: None,
        };
        observe_navigation(&away, "F", &origins, &mut state);
        assert!(state.changed && state.left_scope);
    }
}
