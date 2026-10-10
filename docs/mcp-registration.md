# Registering the Tracewise MCP Server

This guide describes how to register and configure the Tracewise Model Context Protocol (MCP) server across different AI assistant environments.

Tracewise exposes an MCP stdio server communicating via JSON-RPC 2.0 with full support for:
- Tools execution and schema validation (Draft 2020-12)
- Real-time progress reporting (`notifications/progress`) via `progressToken`
- Cancellation handling (`notifications/cancelled`) to abort running operations

---

## 1. Building the Tracewise Binary

Before registering the server, ensure the binary is compiled:

```bash
cargo build --release
```

The resulting binary will be at:
```bash
/abs/path/to/tracewise/target/release/tracewise
```

Replace `/abs/path/tracewise` below with the actual absolute path to your compiled `tracewise` binary.

---

## 2. Claude Code

### Option A: Using the Claude CLI

Run the following command in your terminal:

```bash
claude mcp add tracewise -- /abs/path/tracewise mcp
```

### Option B: Project-level `.mcp.json`

Create or edit `.mcp.json` in your repository root:

```json
{
  "mcpServers": {
    "tracewise": {
      "command": "/abs/path/tracewise",
      "args": ["mcp"]
    }
  }
}
```

---

## 3. Cursor

Add the Tracewise server configuration to your user-level Cursor MCP configuration file (`~/.cursor/mcp.json`) or workspace configuration:

```json
{
  "mcpServers": {
    "tracewise": {
      "command": "/abs/path/tracewise",
      "args": ["mcp"]
    }
  }
}
```

---

## 4. Claude Desktop

For Claude Desktop, add the configuration to your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tracewise": {
      "command": "/abs/path/tracewise",
      "args": ["mcp"]
    }
  }
}
```

---

## 5. Available Phase 0 Tools

Once registered, the following 12 tools are available to the client:

| Tool Name | Description |
|---|---|
| `inspect_analysis_view` | Inspect normalized analysis view and return evidence record |
| `open_binary` | Open target binary for analysis and compute initial SHA-256 |
| `close_binary` | Close currently active target binary session |
| `binary_session` | Query active target session status, identity, and capabilities |
| `export_evidence_bundle` | Export session ledger evidence and unknowns to bundle file |
| `import_evidence_bundle` | Import external evidence bundle and merge into session ledger |
| `get_evidence_bundle` | Retrieve current evidence bundle in-memory |
| `compare_bundles` | Compare two evidence bundles and record differential evidence |
| `list_unknowns` | List residual unknowns filtered by status, severity, or domain |
| `record_unknown` | Record a new residual unknown in the ledger |
| `update_unknown` | Update an existing residual unknown (status, severity, notes) |
| `verify_unknown_resolution` | Verify whether a resolved unknown's evidence links hold |

---

## 6. Verifying Registration

1. **Verify Binary Operation:**
   ```bash
   tracewise tools
   ```
   This will print all 12 registered tool names and descriptions.

2. **Verify JSON-RPC Stdio:**
   Run `tracewise mcp` and send an `initialize` JSON-RPC handshake:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}
   ```
   The server responds with server info and capabilities.
