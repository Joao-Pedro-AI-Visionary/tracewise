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

## License

Licensed under the MIT License. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
