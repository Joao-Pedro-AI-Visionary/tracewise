# Tracewise

Tracewise is a fast, robust Rust rewrite of [REA](https://github.com/morluto/rea) (morluto/rea, MIT).

This repository implements **Phase 0 (Foundation)**:
- Canonical JSON hashing (RFC 8785) and deterministic `ev_<sha256>` semantic projection calculation.
- Evidence domain model (confidence levels, authority enum, discriminated locations union, provenance links).
- ResidualUnknown lifecycle with chained revision digests and optimistic concurrency control (`expected_revision`).
- EvidenceBundle import/export with re-authentication and bundle comparison.
- EvidenceLedger for in-memory session tracking.
- MCP (Model Context Protocol) stdio server powered by `rmcp`. `tools/list` exposes 52 tools: the 50 REA tools verbatim (Phase 0, Phase 1, and Phase 2), plus the tracewise-owned `infer_api_spec` and `generate_api_client` tools. Phase 2 currently implements artifact inventory (`inspect_artifact`, `extract_artifact`, `compare_artifacts`), source-map recovery (`recover_javascript_sources`), historical-source comparison (`compare_source_to_bundle`), application analysis (`analyze_javascript_application`), and semantic tracing (`trace_javascript_semantics`). The remaining Phase 2 tools return the MCP error `not yet implemented: <tool>`.
- CLI binary `tracewise` with `mcp`, `hash`, `tools`, `infer-api-spec`, and `generate-api-client` subcommands.

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

# Generate typed TypeScript and Python clients from that document
tracewise generate-api-client spec.json --lang ts,py -o outdir --replay <capture>
```

`infer_api_spec` groups captured requests into templated endpoints and writes an OpenAPI 3.1 document. Credential values stay out of the spec; redacted authentication headers are recorded as a security scheme whose scheme is unknown, and every unobserved aspect is a residual unknown.

`generate_api_client` renders a fetch-based TypeScript SDK and a stdlib Python SDK from that document. `--replay` turns the redacted capture into `node:test` and `unittest` cases. Each generated file is listed with its sha256. The contracts are in [docs/new-tools.md](docs/new-tools.md).

`recover_javascript_sources` reads a local UTF-8 bundle and its version-3 source map (`sourceMappingURL` or a sibling `.map`) and writes `sourcesContent` into an absent output directory. It does not execute the bundle. The original REA tool shells out to a caller-supplied Wakaru binary; this port uses the `sourcemap` crate because that binary is not bundled. `compare_source_to_bundle` scores a `HistoricalSourceGraph` against authenticated `analyze_javascript_application` evidence with the same signal weights as REA.

`analyze_javascript_application` inventories a local JavaScript application directory and returns the REA application graph. Parsing and binding use oxc (parser + semantic) so node spans and symbol resolution match the original Babel walk on the `fixtures/js/app` fixture. The tool does not execute the application. Oracle comparison ignores `evidence_id`, `subject.local_path`, and `normalized_result.input_path`.

## Demo: site -> spec -> SDK

`scripts/demo.sh` walks the local fixture API through a redacted capture into typed clients:

1. Starts `fixtures/web/server.py` on a free loopback port.
2. Records a HAR with `fixtures/web/record_har.py`. The capture includes `Authorization` and `Cookie` values so redaction is exercised.
3. Runs `tracewise infer-api-spec` and `tracewise generate-api-client --lang ts,py` with `--replay` pointed at that HAR.
4. Compiles the TypeScript SDK with `tsc` (`npx -y -p typescript tsc`) using Node at `/tmp/node-v22.20.0-linux-x64/bin` when that tree exists, otherwise `node` and `npx` on `PATH`, then runs `node --test`.
5. Runs `python3 -m unittest` for the Python SDK.
6. Calls the generated Python and TypeScript clients against the server that is still running (`GET /api/me`, `GET /api/todos`, `GET /api/todos/1`, `POST /api/todos`, `GET /api/todos/99`).
7. Fails if the marker `SECRET-` appears in the OpenAPI document, the generated SDK, or the command logs, then stops the server.

```bash
cargo build -p tracewise --bin tracewise
./scripts/demo.sh
```

The script exits non-zero when any step fails. It uses `target/debug/tracewise` unless `TRACEWISE` points at another binary.

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
