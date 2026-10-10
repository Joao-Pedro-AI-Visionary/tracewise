# Tracewise

Tracewise is a fast, robust Rust rewrite of [REA](https://github.com/morluto/rea) (morluto/rea, MIT).

This repository implements **Phase 0 (Foundation)**:
- Canonical JSON hashing (RFC 8785) and deterministic `ev_<sha256>` semantic projection calculation.
- Evidence domain model (confidence levels, authority enum, discriminated locations union, provenance links).
- ResidualUnknown lifecycle with chained revision digests and optimistic concurrency control (`expected_revision`).
- EvidenceBundle import/export with re-authentication and bundle comparison.
- EvidenceLedger for in-memory session tracking.
- MCP (Model Context Protocol) stdio server powered by `rmcp` exposing the 12 Phase 0 tools verbatim.
- CLI binary `tracewise` with `mcp`, `hash`, and `tools` subcommands.

## Usage

```bash
# Build the workspace
cargo build

# Run unit and integration tests
cargo test

# Run MCP stdio server
tracewise mcp

# Hash a JSON file canonically
tracewise hash <file.json>

# List available Phase 0 tools
tracewise tools
```

## Registering the MCP server

### Claude Code

Using the CLI:
```bash
claude mcp add tracewise -- /abs/path/tracewise mcp
```

Or configure via `.mcp.json` in your project root:
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

### Cursor

Add to your Cursor MCP settings (`~/.cursor/mcp.json`):
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

For more detailed setup, verification steps, and client support, see [docs/mcp-registration.md](docs/mcp-registration.md).

## License

Licensed under the MIT License. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
