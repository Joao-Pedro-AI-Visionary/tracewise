# Progress

Tracewise ports the 170 tools of [REA](https://github.com/morluto/rea) (commit `0fa0b04`) to Rust and adds two of its own. All phases below are closed; every listed tool dispatches to a Rust implementation. Per-track details, dependencies and known divergences are in [`docs/progress/`](docs/progress/).

Last full run of the suite: <!-- TEST_COUNT -->.

## Phase 0: foundation (12 tools)

Workspace (`domain`, `contracts`, `server`, `cli`, `proc-supervisor`), the Evidence model with content-addressed `ev_<sha256>` ids over an RFC 8785 projection (hashes match REA byte for byte), residual unknowns, evidence bundles and bundle comparison, `outputSchema` validation, progress notifications and cancellation, MCP registration docs.

## Phase 1: web and APIs (15 REA tools + 2 new)

HAR and mitmproxy capture inspection with credential redaction, live Chrome over CDP (targets, screenshots, page inspection, session observation, event listeners, execution), bundle analysis, script export, module imports, source locations, WebMCP discovery, browser scenarios, capture and screenshot comparison. New tools: `infer_api_spec` (OpenAPI 3.1 with evidence links) and `generate_api_client` (TypeScript and Python SDKs with replay tests), plus `scripts/demo.sh`.

## Phase 2: JavaScript and Electron (23 tools)

Artifact inspection, extraction and comparison (directories, zip, asar), source-map recovery and source-to-bundle comparison, application analysis and semantic tracing, export shapes, version comparison, feature tracing, the passive V8 Inspector runtime tools, Electron targets and pages over CDP, process capture over a PTY, and the reconstruction workflow (obligation ledger, coverage, verification, changed behavior, static/runtime correlation). `capture_electron_scenario` launches a real Electron over CDP with REA's hook.

## Phase 3: .NET, Android and adb (19 + 24 tools)

ECMA-335 metadata and IL inspection, JADX, Apktool and JEB providers (JEB against a test double), and the 24 adb tools against a scripted `adb`.

## Phase 4: native static analysis (14 tools)

Pure Rust Mach-O, code signatures, plists (including binary plist bomb protection), Swift demangling, NIB, PE resources, ELF layout, recorded crash cores and EVM bytecode.

## Phase 5: disassemblers (57 tools)

Ghidra provider verified against Ghidra 12.1.4; Hopper and IDA providers verified against test doubles that run REA's bridge code. Ephemeral databases; the analyzed file is never modified.

## Phase 6: native runtime and firmware (6 tools)

macOS UI and LLDB paths (REA's `unsupported_host` errors on Linux), Binwalk and Unblob firmware extraction.

## Integration

Full shutdown on stdin close, SIGTERM and SIGINT for every engine and child process; a dispatch test covering all 172 tools; `.app` bundles in `open_binary`; zero clippy warnings; `cargo check` for `aarch64-apple-darwin`.

## JavaScript application graph

`analyze_javascript_application` and the tools that read its graph run on a native port of REA's JavaScript pipeline (`crates/js/src/jsgraph/`): a Babel-shaped AST built from oxc (with a recursion guard in a vendored `oxc_parser`), the static layer, the semantic core and derived collectors, the application graph and the semantic relation graph, REA's response budget, cancellation and depth limits. Each layer and the MCP results are compared with the live REA; see [`docs/progress/jsgraph.md`](docs/progress/jsgraph.md) for the tests and the known gaps.
