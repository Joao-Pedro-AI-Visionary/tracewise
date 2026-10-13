# Tracewise

**Understand and integrate any system with your AI agent.**

Tracewise is a local MCP server and CLI, written in Rust, that gives coding agents (Claude Code, Cursor, Codex, Gemini CLI and any other MCP client) eyes on software you don't control: undocumented APIs, third-party web apps, minified JavaScript bundles, Electron apps, Android APKs, .NET assemblies, native binaries and firmware.

Every conclusion comes back as **Evidence**: tagged as observed, derived or inferred, content-addressed (`ev_<sha256>` over an RFC 8785 canonical projection, so tampering is detectable), and paired with the residual unknowns it could not resolve.

Tracewise is a Rust rewrite of [REA](https://github.com/morluto/rea) by morluto (MIT). It keeps REA's tool names and JSON schemas byte-for-byte, so existing REA prompts and clients work unchanged, and adds tools aimed at developers who build integrations. See [Credits](#credits).

## What it is for

- **Integrate without docs.** Capture traffic from a browser, a HAR or mitmproxy, then `infer_api_spec` writes an OpenAPI 3.1 document where every endpoint links to the request that proves it, and `generate_api_client` emits typed TypeScript and Python SDKs with replay tests. Cookies and tokens are redacted before anything is stored.
- **Clone a feature.** Trace a feature through a site, a bundle or an Electron app, build a reconstruction obligation ledger, and verify that your reimplementation covers it.
- **Migrate legacy.** Recover sources from source maps, compare versions, inspect .NET members and P/Invoke boundaries, read APK classes and methods.
- **Audit what you ship.** Check your own bundle, APK or binary for leaked endpoints, keys and source maps before release.
- **Debug the opaque.** Inspect Mach-O/ELF/PE layout, code signatures, recorded crashes, firmware regions, and drive Ghidra, Hopper or IDA when you need a disassembler.

## Status

`tools/list` serves **172 tools**: the 170 tools of REA at commit `0fa0b04`, with identical names and schemas, plus `infer_api_spec` and `generate_api_client`. Every tool dispatches to a Rust implementation.

| Family | Tools | How parity was checked |
| --- | ---: | --- |
| Foundation: sessions, evidence, unknowns, bundles | 12 | REA oracle; evidence hashes match byte-for-byte |
| Web and APIs: HAR, mitmproxy, live Chrome via CDP, WebMCP, scenarios | 15 + 2 new | REA oracle with real Chrome and mitmproxy 12.2.3 |
| JavaScript and Electron: artifacts, source maps, native application graph (oxc), V8 runtime, process capture, reconstruction | 23 | REA oracle; the application-graph tools against the live REA MCP server (see below) |
| .NET and Android: ECMA-335, JADX, Apktool, JEB | 19 | REA oracle on real assemblies, the ApiDemos APK, jadx-headless-mcp 0.7.1 and Apktool 2.9.3; JEB against a test double |
| adb | 24 | REA oracle against a scripted `adb` (no device) |
| Native static, pure Rust: Mach-O, signatures, plist, Swift, NIB, PE resources, ELF layout, crash cores, EVM | 14 | REA oracle where REA runs on Linux; Apple goldens elsewhere |
| Disassemblers: Ghidra, Hopper, IDA | 57 | REA oracle against Ghidra 12.1.4; Hopper and IDA against test doubles |
| Native runtime and firmware: macOS UI/LLDB, Binwalk, Unblob | 6 | REA oracle with Binwalk 3.1.0 and Unblob 26.6.4 |

"Parity" means the test runs the original REA and Tracewise on the same input and compares the whole MCP result, field by field. Each test header lists every ignored field and the reason (wall-clock times, host paths, run ids). Tests that need an external engine skip with a reason when it is missing. With `TRACEWISE_REQUIRE_ORACLE=1` they fail instead.

### JavaScript application graph

`analyze_javascript_application` runs a native Rust port of REA's JavaScript pipeline (`crates/js/src/jsgraph/`) on any application directory or archive:

1. **Parse.** oxc parses each file and the result is converted into the Babel-shaped tree REA's `@babel/parser` produces (same node types, fields and UTF-16 offsets).
2. **Static layer.** References, endpoints, storage, bundler runtimes, Electron boundaries (BrowserWindow, IPC, preload, utility processes, native loaders), source-map references and AST fingerprints.
3. **Semantic IR.** Scopes, bindings, value lattice, call resolution, mutations, provenance, plus the derived collectors (call sites and flows, promises, events and timers, child processes, configuration/request/boundary effects, resources, objects, function fingerprints).
4. **Application graph and semantic relation graph.** Files, path resolution, module relationships, bundlers, findings, Electron summary and HTML entry points.

The tools that read that graph (`trace_application_feature`, `trace_javascript_semantics`, `compare_application_versions`, `compare_source_to_bundle`, `compare_javascript_export_shapes`) work on the native result. Analysis runs on its own thread, stops at the next checkpoint when the MCP call is cancelled, and returns REA's error envelopes and REA's response-size budget error instead of free-form failures.

How it is checked, always against the compiled REA running live (no recorded answers):

- **Per layer**, exact comparison of the Rust output with REA's on a shared corpus (the REA test fixtures, this repository's fixtures, sources lifted from REA's own unit tests, generated stress and combinatorial scenarios): the Babel-shaped tree node by node, the static layer, the semantic core, the 17 derived fields, and the application graph. Corpus sizes and runs are recorded in [`docs/progress/jsgraph.md`](docs/progress/jsgraph.md).
- **End to end**, `crates/server/tests/jsgraph_mcp_parity_test.rs` drives the original REA MCP server and Tracewise over stdio and compares the whole result of the six tools above (`structuredContent` and the text item) on the fixture apps (`fixtures/js/app`, `app-v2`, `reconstruction_app`, the Electron apps in `fixtures/electron/`, the REA-derived trees in `fixtures/jsgraph/rea/`, a mixed ESM/CJS/TS/JSX app and two pinned npm packages). Only host paths and the evidence ids derived from them are normalized.
- **Hostile inputs** (`jsgraph_hostile_test.rs`): symlinks leaving the root, thousands of modules, import cycles, an 8 MiB module, invalid UTF-8, BOM, empty files, extreme nesting, invalid arguments; the answer must equal REA's, graph or error.

### What is not proven here

- **macOS-only paths.** `observe_native_ui`, `capture_native_ui_scenario`, `observe_native_calls` and the LLDB/assetutil/codesign host paths need macOS. On Linux they return the same `unsupported_host` errors as REA. The real macOS behavior was not run.
- **Commercial engines.** Hopper, IDA and JEB were never installed. Their providers are verified against test doubles that run the real REA bridge code. Behavior against the real products is unverified.
- **Text formats reconstructed without the Apple tool.** The `designated_requirement` text of `inspect_signature`, the exact `lipo -detailed_info` text of `list_architectures` and the per-rendition fields of `inspect_asset_catalog` were not compared with the Apple tools.
- **macOS builds.** The workspace passes `cargo check` for `aarch64-apple-darwin`. It has not been linked or run on a Mac.
- **JavaScript files Babel only recovers from.** REA parses with Babel's `errorRecovery`. For a fixed list of recoverable sloppy-mode errors (`with`, legacy octal literals and escapes, redeclarations, `eval`/`arguments` bindings, `delete x`, reserved words, `break`/`continue` targets and similar), each verified against the live Babel parse to give the same tree and error count, the port records that file as `parse_status: "partial"` like REA. Any other recoverable diagnostic (for example `let let`, `export { undeclared }`, duplicate block-level functions) still makes the analysis return an explicit "not converted by this port" error instead of a different answer. A file ending in a lone `\` is recorded as a parse failure where Babel recovers.
- **Lone surrogates.** A string literal such as `'\ud800'` has no exact Rust `String`. Function fingerprints reproduce REA's output; other string fields that carry such a value (event names, commands, endpoints, configuration keys) can differ.
- **Nesting limits (not compared).** The nesting guard lives inside the parser (a vendored `oxc_parser` 0.75.0 with a weighted depth budget, see `vendor/oxc_parser/TRACEWISE_PATCH.md`): input past it is a parse failure for that file, as when Babel overflows Node's stack. Syntax trees that parse but are deeper than 200,000 levels are refused for the whole application. Babel's limit depends on the construct and on Node's stack (about 350 nested arrays, 400 parentheses, 500 calls, 800 blocks on the measuring machine), so between the two limits the answers differ: for example parentheses nested 400 or 600 deep, or arrays nested 1,500 deep, overflow REA's stack and parse here. That band is not compared. Details: [`docs/progress/jsgraph-depth.md`](docs/progress/jsgraph-depth.md).
- **Smaller edges.** An ambiguous top-level `await (x)` (Babel reads it as a call), and a few `file:` source-map URLs whose path segments look like Windows drive letters (the `url` crate and Node's WHATWG parser disagree) are known to differ.
- **Memory.** Analysis time is similar to REA's or lower, and time and memory grow linearly with the number of files, but memory per file is much higher. Measured through the MCP surface on synthetic 120-line files, Tracewise used 152 / 910 / 3,517 MB against REA's 321 / 428 / 668 MB for 1 / 8 / 32 files, about 105 MB per file against about 11 MB. Projects of about 1,500 such files run out of memory in both. Streaming serialization and hashing of the result is the identified improvement.

Per-family details, including dependencies and known divergences, are in [`docs/progress/`](docs/progress/).

## Quick start

```bash
cargo build --release
./target/release/tracewise tools          # list the tools
./target/release/tracewise mcp            # MCP server on stdio
```

Register it with your agent:

```bash
claude mcp add tracewise -- /abs/path/to/tracewise mcp
```

```json
{
  "mcpServers": {
    "tracewise": { "command": "/abs/path/to/tracewise", "args": ["mcp"] }
  }
}
```

The JSON form works for Cursor (`~/.cursor/mcp.json`) and any client that reads `mcpServers`. More clients and verification steps: [docs/mcp-registration.md](docs/mcp-registration.md).

Requirements: a recent stable Rust (tested with 1.99) and a C/C++ compiler (the Swift demangler is built from C++). Linux is the tested platform.

## Demo: site to spec to SDK

```bash
cargo build -p tracewise --bin tracewise
./scripts/demo.sh
```

The script starts a local fixture API, records a HAR that contains `Authorization` and `Cookie` values, runs `tracewise infer-api-spec` and `tracewise generate-api-client --lang ts,py --replay`, compiles and tests both SDKs, calls the live server through them, and fails if any secret marker reached the spec, the SDKs or the logs. The new tools' contracts are in [docs/new-tools.md](docs/new-tools.md).

## Optional engines

Static analysis of web captures, JavaScript, .NET and Mach-O/ELF/PE/EVM runs in-process and needs nothing else. The rest uses tools you install yourself. Tracewise reads the same environment variables as REA:

| Capability | Variables |
| --- | --- |
| Live browser tools | a loopback Chrome DevTools endpoint you pass in the call (`http://127.0.0.1:<port>`); `capture_browser_scenario` can also launch Chrome itself; `trace_web_module_imports` uses `REA_BROWSER_EXECUTABLE` |
| Electron active capture | `TRACEWISE_ELECTRON_EXECUTABLE` (`:`-separated allowlist of Electron binaries), optional `TRACEWISE_ELECTRON_RUNTIME_DIR` |
| mitmproxy captures | `REA_MITMDUMP_COMMAND` (absolute path to mitmdump 12.2.3) |
| Ghidra | `GHIDRA_INSTALL_DIR`, `JAVA_HOME` (JDK 21) |
| Hopper | `HOPPER_LAUNCHER_PATH` |
| IDA (read-only) | `REA_IDA_MCP_CONFIG` (ida-pro-mcp) |
| Provider choice | `REA_ANALYSIS_PROVIDER` (`ghidra`, `hopper`, `ida`; default auto) |
| Android | `JAVA_HOME`, `REA_JADX_MCP_JAR` (jadx-headless-mcp 0.7.1), `REA_APKTOOL_COMMAND`, `REA_JEB_MCP_URL` |
| adb | `REA_ADB_PATH` |
| Firmware | `REA_BINWALK_COMMAND`, `REA_UNBLOB_COMMAND` |
| Crash cores with pwndbg | `REA_PWNDBG_GDB`, `REA_PWNDBG_VENV_PATH`, `REA_PWNDBG_GDBINIT` |

Missing engines produce a structured `capability_unavailable` error with a remediation hint, never a crash.

Child processes run in their own process group and are killed when a call is cancelled, when the target changes, or when the server exits (stdin closed, SIGTERM, SIGINT). Temporary directories are removed the same way. Disassembler databases are ephemeral and the analyzed file is never modified.

## Development

```bash
cargo build --workspace --all-targets
cargo clippy --workspace --all-targets      # zero warnings
cargo test --workspace --no-fail-fast
```

Last full run of the suite: 434 passed, 0 failed, 0 ignored (`cargo test --workspace` with `TRACEWISE_REQUIRE_ORACLE=1`, 2026-10-13; `cargo clippy --workspace --all-targets` clean).

### Running the parity tests (and what a green CI run means)

- **REA oracle.** The parity tests run the original REA live. They need a checkout of REA at commit `0fa0b04`, built, and Node 22 on `PATH`. Point `REA_SRC` at the REA source directory; the JavaScript application-graph tests (`jsgraph_*`) read it and run the Node drivers in `fixtures/jsgraph/oracle/`. `fixtures/rea_oracle.py`, used by the other families, reads `REA_SRC` and `REA_NODE` (the Node binary) too.
- **Skips pass silently.** Without the oracle (or without an optional engine) a parity test prints why and returns early, so it **passes without comparing anything**. A plain `cargo test` on a machine without REA is therefore not evidence of parity. Set `TRACEWISE_REQUIRE_ORACLE=1` to turn every missing oracle or engine into a failure; a CI job that claims parity must set it.
- **Checkout layout.** Several integration tests and unit tests still assume the repository is checked out at `/workspace/tracewise`, and some look for engines under `/workspace/tools` and REA under `/workspace/rea-map/src`. Outside that layout those tests fail or skip. Making them use `CARGO_MANIFEST_DIR` and environment variables everywhere is pending.

Workspace layout: `domain` (evidence model), `contracts` (tool catalog), `server` (MCP dispatch), `cli`, `web`, `js`, `managed`, `android`, `device` (adb, firmware, native runtime), `native` (Mach-O/ELF/PE/plist/EVM), `engines` (Ghidra/Hopper/IDA), `proc-supervisor`.

## Credits

Tracewise is derived from [REA](https://github.com/morluto/rea), Copyright (c) 2026 morluto, MIT License. The tool catalog and schemas, the evidence model and many behaviors are ported from REA's TypeScript. The Ghidra and Hopper bridge scripts and the JADX bridge are copied from REA with their attribution headers. The JavaScript application-graph pipeline (`crates/js/src/jsgraph/`) is a port of REA's `domain/javascript` and `application/javascript` code, and part of its test corpus is generated from REA's fixtures and unit tests. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full list, including third-party test fixtures and Rust dependencies under other licenses.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
