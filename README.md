# Tracewise

Tracewise is a fast, robust Rust rewrite of [REA](https://github.com/morluto/rea) (morluto/rea, MIT).

This repository implements **Phase 0 (Foundation)**:
- Canonical JSON hashing (RFC 8785) and deterministic `ev_<sha256>` semantic projection calculation.
- Evidence domain model (confidence levels, authority enum, discriminated locations union, provenance links).
- ResidualUnknown lifecycle with chained revision digests and optimistic concurrency control (`expected_revision`).
- EvidenceBundle import/export with re-authentication and bundle comparison.
- EvidenceLedger for in-memory session tracking.
- MCP (Model Context Protocol) stdio server powered by `rmcp`. `tools/list` exposes 28 tools: the 27 REA tools verbatim, plus the tracewise-owned `infer_api_spec` tool.
- CLI binary `tracewise` with `mcp`, `hash`, `tools`, and `infer-api-spec` subcommands.

## Usage

```bash
# Build the workspace
cargo build

# Run unit and integration tests
cargo test

# Run MCP stdio server
tracewise mcp

Live browser tools attach to a loopback Chrome DevTools endpoint (`http://127.0.0.1:<port>` or `http://[::1]:<port>`). `allowed_origins` is an optional list of exact `http`/`https` origins: an empty list lists every HTTP(S) page, and a capture with no filter is limited to that target's current origin. URLs keep query and fragment; only userinfo credentials are removed.

`inspect_web_page` passively records one page (DOM, accessibility, scripts, resources, attach-window network and console metadata, workers, redacted storage). It does not navigate or evaluate JavaScript. `Cookie`, `Set-Cookie`, and `Authorization` are removed from captured network data; response metadata keeps an allowlist and `values_redacted` stays true. `observe_web_session` records a navigation timeline for `observation_ms` (default 10000, minimum 1) and does not retain headers, bodies, or cookies.

`analyze_web_bundle` reuses that passive capture with script source retained and reports static chunk, route, endpoint, WebMCP and vendor findings. It does not execute the captured JavaScript. `fetch_source_maps` defaults to false. `observe_web_execution` arms one precise-coverage window (`observation_ms` default 10000, minimum 1) and records request initiators for that window; counters reset until coverage is stopped, and the page stays externally owned. `inspect_web_event_listeners` reads native listener descriptors for the first main-document CSS match and does not dispatch the event.

`discover_webmcp_tools` inventories page-registered WebMCP tools through `WebMCP.enable` and `toolsAdded` / `toolsRemoved` (`observation_ms` default 100). Metadata is page-declared and untrusted; discovered tools are never registered or invoked. `capture_browser_scenario` runs one explicit action sequence. `browser.mode = "launch"` starts Chrome through the process supervisor with an owned temporary profile and terminates that process when the capture ends; `connect` attaches to an existing loopback target and leaves it running. Secret values are read from environment variables for the duration of the capture and are redacted from retained URLs, DOM, storage fingerprints and errors. They are not written into the evidence parameters.

# Hash a JSON file canonically
tracewise hash <file.json>

# List available Phase 0 tools
tracewise tools

# Infer an OpenAPI 3.1 document from a redacted HAR or mitmproxy capture
tracewise infer-api-spec <capture> -o spec.json
```

`infer_api_spec` groups captured requests into templated endpoints and writes an OpenAPI 3.1 document. Credential values stay out of the spec; redacted authentication headers are recorded as a security scheme whose scheme is unknown, and every unobserved aspect is a residual unknown. The contract is in [docs/new-tools.md](docs/new-tools.md).

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
