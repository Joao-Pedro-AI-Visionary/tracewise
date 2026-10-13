//! The MCP boundary of the IDA provider (port of `IdaMcpConnection.ts`).
//!
//! [`IdaConnection`] is the injectable seam the session client talks through. The shipped
//! implementation, [`McpConnection`], drives a registered upstream server with `rmcp`:
//! over stdio (the proxy runs in its own process group) or, for a `url` registration, over
//! streamable HTTP to a local endpoint. rmcp 0.11 forwards only a bearer `Authorization`
//! value, so the registration's headers ride on the `reqwest` client itself, which also
//! refuses redirects (REA uses `redirect: "error"`). Plain `http` only: this build has no
//! TLS stack, so an `https` registration validates but reports that it cannot connect.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use process_wrap::tokio::{KillOnDrop, ProcessGroup, TokioCommandWrap};
use rmcp::model::{CallToolRequestParam, ClientCapabilities, ClientInfo, Implementation};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::error::AnalysisError;

use super::config::{IdaRegistration, IdaTransport};
use super::http_client::HttpClient;
use super::protocol::{decode_tool_result, DecodeFailure};

/// A failure at the upstream boundary, before it is projected for the caller.
#[derive(Debug, Clone)]
pub enum IdaFault {
    /// `AnalysisProtocolError`: the upstream answered outside the expected protocol.
    Protocol(String),
    /// A zod failure: malformed or unsupported producer data (the rendered issues).
    Malformed(String),
    /// A typed analysis failure raised inside the adapter (input, cancellation).
    Analysis(Box<AnalysisError>),
    /// Anything else (transport, timeouts, process failures): a provider adapter failure.
    Other(String),
}

impl IdaFault {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn analysis(error: AnalysisError) -> Self {
        Self::Analysis(Box::new(error))
    }
}

impl From<DecodeFailure> for IdaFault {
    fn from(failure: DecodeFailure) -> Self {
        match failure {
            DecodeFailure::Protocol(message) => Self::Protocol(message),
            DecodeFailure::Malformed(message) => Self::Malformed(message),
        }
    }
}

/// Injectable MCP boundary used by the provider and by the conformance tests.
#[async_trait]
pub trait IdaConnection: Send + Sync {
    /// Connect and list the upstream tool names.
    async fn connect(&self) -> Result<Vec<String>, IdaFault>;
    /// Call one upstream tool and decode its result.
    async fn call(&self, name: &str, args: &Value) -> Result<Value, IdaFault>;
    /// What the upstream announced about itself (`serverInfo`), or null before connecting.
    fn server_info(&self) -> Value;
    async fn close(&self) -> Result<(), IdaFault>;
}

/// Variables the MCP SDK would otherwise inherit from the ambient process; REA blanks them
/// so only the selected environment snapshot (plus the registration's own) reaches the proxy.
const DEFAULT_INHERITED_ENV_VARS: [&str; 6] = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"];

/// Live stdio session with its process group.
struct Live {
    service: RunningService<RoleClient, ClientInfo>,
    /// Present for stdio registrations only.
    group: Option<ProcessGroupGuard>,
}

/// Kills the proxy's whole process group when the connection is dropped without a clean close.
struct ProcessGroupGuard {
    pgid: Option<u32>,
    armed: bool,
}

impl ProcessGroupGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let (true, Some(pgid)) = (self.armed, self.pgid) {
            // The proxy was spawned as the leader of its own process group (`ProcessGroup::leader`),
            // so the group id equals its pid; the guard is disarmed after a confirmed shutdown,
            // so a recycled pid is never signalled.
            crate::process::kill_group(pgid as i32);
        }
    }
}

pub struct McpConnection {
    registration: IdaRegistration,
    environment: BTreeMap<String, String>,
    live: Mutex<Option<Live>>,
    info: StdMutex<Value>,
}

impl McpConnection {
    /// `environment` is the snapshot selected for this provider (never the ambient one).
    pub fn new(registration: IdaRegistration, environment: BTreeMap<String, String>) -> Self {
        Self {
            registration,
            environment,
            live: Mutex::new(None),
            info: StdMutex::new(Value::Null),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.registration.timeout_ms)
    }

    /// A transport failure with the registration's credentials removed.
    fn transport_failure(&self, message: &str) -> IdaFault {
        IdaFault::Other(redact_transport_failure(message, &self.registration))
    }

    /// Run the MCP handshake over `transport`, bounded by the registration's timeout.
    async fn serve<T, E, A>(
        &self,
        transport: T,
    ) -> Result<RunningService<RoleClient, ClientInfo>, IdaFault>
    where
        T: rmcp::transport::IntoTransport<RoleClient, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        match tokio::time::timeout(self.timeout(), client_info().serve(transport)).await {
            Ok(Ok(service)) => Ok(service),
            Ok(Err(error)) => Err(self.transport_failure(&error.to_string())),
            Err(_) => Err(IdaFault::Other("Request timed out".to_string())),
        }
    }

    fn http_transport(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<StreamableHttpClientTransport<HttpClient>, IdaFault> {
        use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
        if url::Url::parse(url)
            .map(|u| u.scheme() != "http")
            .unwrap_or(true)
        {
            return Err(IdaFault::Other(
                "Only plain http IDA MCP endpoints are supported by this build (it has no TLS stack); use a http://localhost endpoint or the stdio proxy."
                    .to_string(),
            ));
        }
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            let invalid = || {
                IdaFault::Other(
                    "An IDA MCP registration header is not a valid HTTP header.".to_string(),
                )
            };
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
            let mut header_value = HeaderValue::from_str(value).map_err(|_| invalid())?;
            if matches!(
                header_name.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            ) {
                header_value.set_sensitive(true);
            }
            map.insert(header_name, header_value);
        }
        let client = reqwest::Client::builder()
            // The endpoint is the user's own local IDA proxy; never route it through ambient proxies.
            .no_proxy()
            .default_headers(map)
            // REA fails a request that is redirected instead of following it.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                attempt
                    .error("the IDA MCP endpoint answered with a redirect, which is not followed")
            }))
            .build()
            .map_err(|e| IdaFault::Other(format!("Cannot build the IDA MCP HTTP client: {e}")))?;
        Ok(StreamableHttpClientTransport::with_client(
            HttpClient(client),
            StreamableHttpClientTransportConfig::with_uri(url.to_string()),
        ))
    }

    fn command(
        &self,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> TokioCommandWrap {
        let mut wrapped = TokioCommandWrap::with_new(command, |cmd| {
            cmd.args(args);
            crate::process::harden_proxy(cmd);
            cmd.env_clear();
            for key in DEFAULT_INHERITED_ENV_VARS {
                cmd.env(key, "");
            }
            cmd.envs(&self.environment);
            cmd.env("IDA_MCP_MAX_WORKERS", "1");
            cmd.envs(env);
        });
        wrapped.wrap(ProcessGroup::leader());
        wrapped.wrap(KillOnDrop);
        wrapped
    }
}

fn client_info() -> ClientInfo {
    ClientInfo {
        protocol_version: Default::default(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation {
            name: "rea-ida-provider".to_string(),
            title: None,
            version: "1".to_string(),
            icons: None,
            website_url: None,
        },
    }
}

fn implementation_json(info: &Implementation) -> Value {
    serde_json::to_value(info).unwrap_or(Value::Null)
}

#[async_trait]
impl IdaConnection for McpConnection {
    async fn connect(&self) -> Result<Vec<String>, IdaFault> {
        let mut guard = self.live.lock().await;
        if guard.is_some() {
            return Err(IdaFault::protocol(
                "IDA MCP connection was already established.",
            ));
        }
        let (service, group) = match &self.registration.transport {
            IdaTransport::Stdio { command, args, env } => {
                let (transport, stderr) =
                    TokioChildProcess::builder(self.command(command, args, env))
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|e| {
                            IdaFault::Other(format!("Cannot start the IDA MCP proxy: {e}"))
                        })?;
                let group = ProcessGroupGuard {
                    pgid: transport.id(),
                    armed: true,
                };
                if let Some(pid) = transport.id() {
                    crate::process::spawn_watchdog(pid as i32);
                }
                // Drain proxy diagnostics without persisting ambient environment or credentials.
                if let Some(mut stderr) = stderr {
                    tokio::spawn(async move {
                        let mut sink = [0u8; 4096];
                        while matches!(stderr.read(&mut sink).await, Ok(n) if n > 0) {}
                    });
                }
                (self.serve(transport).await?, Some(group))
            }
            IdaTransport::Http { url, headers } => {
                let transport = self.http_transport(url, headers)?;
                (self.serve(transport).await?, None)
            }
        };
        let peer = service.peer().clone();
        *self.info.lock().unwrap() = peer
            .peer_info()
            .map(|info| implementation_json(&info.server_info))
            .unwrap_or(Value::Null);
        let listed = tokio::time::timeout(self.timeout(), peer.list_tools(None)).await;
        *guard = Some(Live { service, group });
        match listed {
            Ok(Ok(catalog)) => Ok(catalog
                .tools
                .iter()
                .map(|tool| tool.name.to_string())
                .collect()),
            Ok(Err(error)) => Err(self.transport_failure(&error.to_string())),
            Err(_) => Err(IdaFault::Other("Request timed out".to_string())),
        }
    }

    async fn call(&self, name: &str, args: &Value) -> Result<Value, IdaFault> {
        let peer = {
            let guard = self.live.lock().await;
            match guard.as_ref() {
                Some(live) => live.service.peer().clone(),
                None => {
                    return Err(IdaFault::Other(
                        "IDA MCP connection is not established.".to_string(),
                    ))
                }
            }
        };
        let arguments = match args {
            Value::Object(map) => Some(map.clone()),
            Value::Null => None,
            _ => {
                return Err(IdaFault::protocol(
                    "IDA MCP tool arguments must be an object.",
                ))
            }
        };
        let request = CallToolRequestParam {
            name: name.to_string().into(),
            arguments,
        };
        let result = match tokio::time::timeout(self.timeout(), peer.call_tool(request)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => return Err(self.transport_failure(&error.to_string())),
            Err(_) => return Err(IdaFault::Other("Request timed out".to_string())),
        };
        let raw = serde_json::to_value(&result).map_err(|e| IdaFault::Other(e.to_string()))?;
        decode_tool_result(&raw).map_err(IdaFault::from)
    }

    fn server_info(&self) -> Value {
        self.info.lock().unwrap().clone()
    }

    async fn close(&self) -> Result<(), IdaFault> {
        let live = self.live.lock().await.take();
        let Some(mut live) = live else {
            return Ok(());
        };
        let result = live.service.cancel().await;
        if let Some(group) = live.group.as_mut() {
            group.disarm();
        }
        // The service owns the transport; cancelling it closes stdin and reaps the proxy
        // (or ends the HTTP session).
        result
            .map(|_| ())
            .map_err(|e| self.transport_failure(&e.to_string()))
    }
}

/// Construct the default connection factory for a registration.
pub fn default_connection(
    registration: &IdaRegistration,
    environment: &BTreeMap<String, String>,
) -> std::sync::Arc<dyn IdaConnection> {
    std::sync::Arc::new(McpConnection::new(
        registration.clone(),
        environment.clone(),
    ))
}

/// Redact configured transport authentication values from diagnostics.
pub fn redact_transport_failure(message: &str, registration: &IdaRegistration) -> String {
    let mut out = message.to_string();
    if let IdaTransport::Http { headers, .. } = &registration.transport {
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if !matches!(
                lower.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            ) {
                continue;
            }
            let credential = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("Basic "))
                .map(str::trim_start);
            for secret in [Some(value.as_str()), credential].into_iter().flatten() {
                if !secret.is_empty() {
                    out = out.replace(secret, "[redacted transport credential]");
                }
            }
        }
    }
    out
}

/// JSON object of arguments, with `database` appended when the session is scoped.
pub fn scoped(args: &Value, database: Option<&str>) -> Value {
    match (args, database) {
        (Value::Object(map), Some(database)) => {
            let mut scoped = map.clone();
            scoped.insert("database".to_string(), json!(database));
            Value::Object(scoped)
        }
        _ => args.clone(),
    }
}
