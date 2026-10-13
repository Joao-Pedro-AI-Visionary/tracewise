pub mod delivery;
pub mod electron_handlers;
pub mod format;
pub mod handlers;
pub mod js_application_handlers;
pub mod process_handlers;
pub mod reconstruction_handlers;
pub mod schema_order;
pub mod session;
pub mod tracks;

use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use session::BinarySession;

#[derive(Clone)]
pub struct TracewiseServer {
    pub session: BinarySession,
}

impl TracewiseServer {
    pub fn new() -> Self {
        Self {
            session: BinarySession::new(),
        }
    }
}

impl Default for TracewiseServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerHandler for TracewiseServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Tracewise MCP server (Phase 0 Foundation)".to_string()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "tracewise".to_string(),
                version: "0.1.0".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: tracewise_contracts::listed_tools(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        handlers::dispatch_tool(&self.session, request, Some(&context)).await
    }
}

pub async fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    let server = TracewiseServer::new();
    let service = server.serve(rmcp::transport::stdio()).await?;
    // SIGTERM / SIGINT / SIGHUP: release every engine (JVM, bridge sockets, runtime directories)
    // before leaving; the OS default would end the process without running any destructor.
    spawn_signal_shutdown();
    let outcome = service.waiting().await;
    // The client closed stdin (or the transport failed): same cleanup as an explicit close.
    tracks::shutdown().await;
    outcome?;
    Ok(())
}

fn spawn_signal_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        return;
    };
    tokio::spawn(async move {
        let code = tokio::select! {
            _ = term.recv() => 143,
            _ = int.recv() => 130,
            _ = hup.recv() => 129,
        };
        tracks::shutdown().await;
        std::process::exit(code);
    });
}
