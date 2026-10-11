//! Minimal correlated CDP JSON-RPC transport over one WebSocket
//! (port of REA browser/CdpConnection.ts and browser/CdpTargetSession.ts).
//!
//! Commands are issued sequentially: `send` writes one command and reads
//! frames until its response arrives. Events received meanwhile are queued
//! in arrival order and drained with [`CdpConnection::take_events`], which
//! preserves the wire ordering the original listener model relies on.

use std::collections::VecDeque;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::browser_observation::{browser_error, BrowserFailureReason};
use crate::cdp_endpoint::{CdpEndpointDiscovery, CdpEndpointTarget, CdpWebSocketEndpoint};
use crate::error::WebError;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// One validated CDP event envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct CdpEvent {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

pub struct CdpConnection {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    operation: String,
    next_id: u64,
    events: VecDeque<CdpEvent>,
    closed: bool,
    protocol_failed: bool,
}

impl CdpConnection {
    /// Connect to one already-validated loopback CDP WebSocket.
    pub async fn connect(url: &str, operation: &str) -> Result<Self, WebError> {
        let mut config = WebSocketConfig::default();
        config.max_message_size = None;
        config.max_frame_size = None;
        let (socket, _) = tokio_tungstenite::connect_async_with_config(url, Some(config), true)
            .await
            .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
        Ok(Self {
            socket,
            operation: operation.to_string(),
            next_id: 1,
            events: VecDeque::new(),
            closed: false,
            protocol_failed: false,
        })
    }

    fn fail(&self, reason: BrowserFailureReason) -> WebError {
        browser_error(&self.operation, reason, None)
    }

    /// Execute one command, optionally within a flat target session.
    pub async fn send(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Map<String, Value>, WebError> {
        self.send_with_timeout(method, params, session_id, COMMAND_TIMEOUT)
            .await
    }

    pub async fn send_with_timeout(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        timeout: Duration,
    ) -> Result<Map<String, Value>, WebError> {
        if self.protocol_failed {
            return Err(self.fail(BrowserFailureReason::ProtocolError));
        }
        if self.closed {
            return Err(self.fail(BrowserFailureReason::Disconnected));
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut command = json!({ "id": id, "method": method, "params": params });
        if let Some(session_id) = session_id {
            command["sessionId"] = json!(session_id);
        }
        match tokio::time::timeout(timeout, self.exchange(id, command, session_id)).await {
            Ok(result) => result,
            Err(_) => Err(self.fail(BrowserFailureReason::Timeout)),
        }
    }

    async fn exchange(
        &mut self,
        id: u64,
        command: Value,
        session_id: Option<&str>,
    ) -> Result<Map<String, Value>, WebError> {
        if self
            .socket
            .send(Message::text(command.to_string()))
            .await
            .is_err()
        {
            self.closed = true;
            return Err(self.fail(BrowserFailureReason::Disconnected));
        }
        loop {
            let text = match self.socket.next().await {
                Some(Ok(Message::Text(text))) => text.as_str().to_string(),
                Some(Ok(Message::Binary(bytes))) => match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_) => return Err(self.protocol_failure()),
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                    self.closed = true;
                    return Err(self.fail(BrowserFailureReason::Disconnected));
                }
                Some(Ok(_)) => continue,
            };
            let Ok(Value::Object(message)) = serde_json::from_str::<Value>(&text) else {
                return Err(self.protocol_failure());
            };
            if let Some(raw_id) = message.get("id") {
                let Some(response_id) = raw_id.as_u64().filter(|n| *n >= 1) else {
                    return Err(self.protocol_failure());
                };
                if response_id != id {
                    // Responses for commands no longer pending are ignored.
                    continue;
                }
                return self.receive_response(&message, session_id);
            }
            let event = self.parse_event(message)?;
            self.events.push_back(event);
        }
    }

    fn receive_response(
        &mut self,
        message: &Map<String, Value>,
        session_id: Option<&str>,
    ) -> Result<Map<String, Value>, WebError> {
        if let Some(reported) = message.get("sessionId") {
            if reported.as_str() != session_id || session_id.is_none() {
                return Err(self.protocol_failure());
            }
        }
        match (message.get("result"), message.get("error")) {
            (Some(Value::Object(result)), None) => Ok(result.clone()),
            (None, Some(Value::Object(error))) => {
                match (error.get("code").and_then(Value::as_i64), error.get("message").and_then(Value::as_str)) {
                    (Some(code), Some(text)) => Err(WebError::CdpCommandRejected {
                        operation: self.operation.clone(),
                        code,
                        message: text.to_string(),
                    }),
                    _ => Err(self.protocol_failure()),
                }
            }
            _ => Err(self.protocol_failure()),
        }
    }

    fn parse_event(&mut self, mut message: Map<String, Value>) -> Result<CdpEvent, WebError> {
        let method = match message.get("method").and_then(Value::as_str) {
            Some(m) if !m.is_empty() => m.to_string(),
            _ => return Err(self.protocol_failure()),
        };
        let params = match message.remove("params") {
            None => Value::Object(Map::new()),
            Some(p @ Value::Object(_)) => p,
            Some(_) => return Err(self.protocol_failure()),
        };
        let session_id = match message.get("sessionId") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(self.protocol_failure()),
        };
        Ok(CdpEvent {
            method,
            params,
            session_id,
        })
    }

    fn protocol_failure(&mut self) -> WebError {
        self.protocol_failed = true;
        self.fail(BrowserFailureReason::ProtocolError)
    }

    /// Drain events received so far, in wire order.
    pub fn take_events(&mut self) -> Vec<CdpEvent> {
        self.events.drain(..).collect()
    }

    /// Close only our socket; never close the browser or selected page.
    pub async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, self.socket.close(None)).await;
    }
}

/// One CDP connection scoped either by a flat browser session or page socket.
pub struct CdpTargetSession {
    pub connection: CdpConnection,
    pub session_id: Option<String>,
}

/// Open one authorized target through its supported browser or page transport.
pub async fn open_cdp_target_session(
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    operation: &str,
) -> Result<CdpTargetSession, WebError> {
    let web_socket = discovery
        .target_web_socket(target)
        .ok_or_else(|| browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None))?;
    let mut connection = CdpConnection::connect(web_socket.url(), operation).await?;
    if matches!(web_socket, CdpWebSocketEndpoint::Page { .. }) {
        return Ok(CdpTargetSession {
            connection,
            session_id: None,
        });
    }
    let attached = connection
        .send(
            "Target.attachToTarget",
            json!({ "targetId": target.id, "flatten": true }),
            None,
        )
        .await;
    match attached {
        Ok(result) => match result.get("sessionId").and_then(Value::as_str) {
            Some(session_id) if !session_id.is_empty() => Ok(CdpTargetSession {
                connection,
                session_id: Some(session_id.to_string()),
            }),
            _ => {
                connection.close().await;
                Err(browser_error(operation, BrowserFailureReason::ProtocolError, None))
            }
        },
        Err(error) => {
            connection.close().await;
            Err(error)
        }
    }
}

/// Disable enabled domains, detach browser sessions, and close our socket.
/// Cleanup is best-effort and bounded by one shared one-second budget.
pub async fn close_cdp_target_session(mut session: CdpTargetSession, enabled_domains: &[&str]) {
    let deadline = tokio::time::Instant::now() + CLOSE_TIMEOUT;
    let session_id = session.session_id.clone();
    for domain in enabled_domains {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = session
            .connection
            .send_with_timeout(&format!("{domain}.disable"), json!({}), session_id.as_deref(), remaining)
            .await;
    }
    if let Some(session_id) = &session_id {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            let _ = session
                .connection
                .send_with_timeout(
                    "Target.detachFromTarget",
                    json!({ "sessionId": session_id }),
                    None,
                    remaining,
                )
                .await;
        }
    }
    session.connection.close().await;
}
