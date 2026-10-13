pub mod electron_handlers;
pub mod format;
pub mod handlers;
pub mod process_handlers;
pub mod reconstruction_handlers;
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
    service.waiting().await?;
    Ok(())
}
