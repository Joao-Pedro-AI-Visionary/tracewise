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

`tools/list` serves **172 tools**: the 170 tools of REA at commit `0fa0b04`, with identical names and schemas, plus `infer_api_spec` and `generate_api_client`. Every tool dispatches to a Rust implementation; the one partial implementation is listed under [What is not proven here](#what-is-not-proven-here).

| Family | Tools | How parity was checked |
| --- | ---: | --- |
| Foundation: sessions, evidence, unknowns, bundles | 12 | REA oracle; evidence hashes match byte-for-byte |
| Web and APIs: HAR, mitmproxy, live Chrome via CDP, WebMCP, scenarios | 15 + 2 new | REA oracle with real Chrome and mitmproxy 12.2.3 |
| JavaScript and Electron: artifacts, source maps, oxc analysis, V8 runtime, process capture, reconstruction | 23 | REA oracle |
| .NET and Android: ECMA-335, JADX, Apktool, JEB | 19 | REA oracle on real assemblies, the ApiDemos APK, jadx-headless-mcp 0.7.1 and Apktool 2.9.3; JEB against a test double |
| adb | 24 | REA oracle against a scripted `adb` (no device) |
| Native static, pure Rust: Mach-O, signatures, plist, Swift, NIB, PE resources, ELF layout, crash cores, EVM | 14 | REA oracle where REA runs on Linux; Apple goldens elsewhere |
| Disassemblers: Ghidra, Hopper, IDA | 57 | REA oracle against Ghidra 12.1.4; Hopper and IDA against test doubles |
| Native runtime and firmware: macOS UI/LLDB, Binwalk, Unblob | 6 | REA oracle with Binwalk 3.1.0 and Unblob 26.6.4 |

"Parity" means the test runs the original REA and Tracewise on the same input and compares the whole MCP result, field by field. Each test header lists every ignored field and the reason (wall-clock times, host paths, run ids). Tests that need an external engine skip with a reason when it is missing. With `TRACEWISE_REQUIRE_ORACLE=1` they fail instead.

### What is not proven here

- **JavaScript application graph (work in progress).** `analyze_javascript_application` currently rebuilds the graph only for the pinned fixture apps and refuses any other app with a structured error. The tools that consume that graph (`trace_javascript_semantics`, `trace_application_feature`, `compare_application_versions`, `compare_javascript_export_shapes`, `compare_source_to_bundle`) are therefore limited to those fixtures until the oxc-based builder lands.

- **macOS-only paths.** `observe_native_ui`, `capture_native_ui_scenario`, `observe_native_calls` and the LLDB/assetutil/codesign host paths need macOS. On Linux they return the same `unsupported_host` errors as REA. The real macOS behavior was not run.
- **Commercial engines.** Hopper, IDA and JEB were never installed. Their providers are verified against test doubles that run the real REA bridge code. Behavior against the real products is unverified.
- **Text formats reconstructed without the Apple tool.** The `designated_requirement` text of `inspect_signature`, the exact `lipo -detailed_info` text of `list_architectures` and the per-rendition fields of `inspect_asset_catalog` were not compared with the Apple tools.
- **macOS builds.** The workspace passes `cargo check` for `aarch64-apple-darwin`. It has not been linked or run on a Mac.

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

The parity tests call the original REA through `fixtures/rea_oracle.py`. To run them, check out REA at `0fa0b04` next to this repository, build it with Node 22, and install the engines listed above. Without them the parity tests skip and say why.

Workspace layout: `domain` (evidence model), `contracts` (tool catalog), `server` (MCP dispatch), `cli`, `web`, `js`, `managed`, `android`, `device` (adb, firmware, native runtime), `native` (Mach-O/ELF/PE/plist/EVM), `engines` (Ghidra/Hopper/IDA), `proc-supervisor`.

## Credits

Tracewise is derived from [REA](https://github.com/morluto/rea), Copyright (c) 2026 morluto, MIT License. The tool catalog and schemas, the evidence model and many behaviors are ported from REA's TypeScript. The Ghidra and Hopper bridge scripts and the JADX bridge are copied from REA with their attribution headers. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full list, including third-party test fixtures and Rust dependencies under other licenses.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
