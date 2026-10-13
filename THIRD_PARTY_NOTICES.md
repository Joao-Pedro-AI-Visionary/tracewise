# Third Party Notices

Parts of this software are derived from REA (https://github.com/morluto/rea), Copyright (c) 2026 morluto, licensed under the MIT License. Unless stated otherwise below, REA-derived material comes from REA commit `0fa0b04`.

---

## REA (morluto/rea) License

MIT License

Copyright (c) 2026 morluto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Design and catalog

- The Evidence model with semantic `ev_<sha256>` identifiers, ResidualUnknown with revision chaining, EvidenceBundle and bundle comparison follow REA's design.
- The tool catalog (names, descriptions and JSON schemas of REA's 170 tools) is taken from REA for direct interoperability with REA clients and prompts.

---

## Engines track (derived from REA)

The files below derive from morluto/rea (MIT, license above):
- `crates/engines/bridge/ghidra/ReaGhidraBridge.java`, `ReaGhidraExtensions.java`, `ReaGhidraNoReturnFix.java` (copied without behavior changes).
- `crates/engines/bridge/hopper_bridge.py` (copied without behavior changes).
- `fixtures/engines/inventory.c` (from `tests/conformance/ghidra/inventory.c`).

Ghidra (Apache-2.0) and the JDK are provided by the user and are not redistributed.

### Rust modules ported from REA's TypeScript (derivative work, MIT)

Rust rewrites of morluto/rea's TypeScript that keep its structure, messages, limits and behavior; the MIT license above applies to them:
- Ghidra provider: `crates/engines/src/ghidra/` (GhidraClient, GhidraLauncher, GhidraProvider, GhidraProviderClient, GhidraProviderCapabilities, GhidraAnalysisProfile, GhidraInstallation, GhidraInventoryValues, GhidraFunctionValues).
- Hopper provider: `crates/engines/src/hopper/` (HopperClient, HopperRequestQueue, BridgeLauncher, HopperProvider, HopperProviderCapabilities, HopperAnalysisProfile, HopperRegexSearch, HopperFileOffset, parseConfig).
- IDA provider: `crates/engines/src/ida/` (IdaProvider, IdaConfiguration, IdaMcpConnection, IdaOperationRunner, IdaProtocolValues, IdaProviderCapabilities, IdaSessionClient, IdaWorkspace, IdaInput, IdaDoctor and the matching conformance tests).
- Abstraction and selection: `crates/engines/src/provider.rs`, `session.rs`, `error.rs` (AnalysisProvider, AnalysisProviderRegistry, SessionProviderRouter, BinarySessionExecution, AnalysisSnapshotCache, analysisError*).
- Workflows: `crates/engines/src/workflows/` (EnhancedTools, CallPathTracing, EnhancedLiteralTracing, AnalysisContextQueries, NativeValueTrace, NativeApiInspection, NativeDispatchMetadataInspection, symbolAnalysis, swiftSymbolClassification).
- Evidence derivations: `crates/engines/src/derived/` (callPath, functionComparison*, and a reimplementation of the `diffLines` algorithm of the `diff` package (jsdiff, BSD-3-Clause, Copyright (c) Kevin Decker and contributors) that REA uses; the BSD-3-Clause license text ships with that package).
- Recorded oracles (`fixtures/engines/**/oracle_*.json.gz`) are outputs of REA itself on fixtures from this repository.

---

## Other tracks derived from REA

These are also Rust rewrites of morluto/rea's TypeScript (MIT, license above) that keep its messages, limits and behavior: `crates/managed` (src/dotnet), `crates/android` (Android, Apktool and JEB providers), `crates/device` (adb, firmware, host gate, trace_native_ui_action), `crates/native` (native and Apple providers), `crates/web` and `crates/js` (web, JavaScript, Electron, reconstruction). The bridge `crates/android/bridge/ReaJadxBridge.java` is an unchanged copy with an attribution header.

## JavaScript application graph (jsgraph track)

- `crates/js/src/jsgraph/` ports REA's `src/domain/javascript/*` and `src/application/javascript/*` to Rust and reproduces the original logic; the MIT license above covers this material.
- The pipeline parses with the `oxc` crates (MIT) instead of REA's `@babel/parser`. It adds `html5ever` and `markup5ever_rcdom` (MIT OR Apache-2.0, Servo project) to `tracewise-js`, used in place of REA's `parse5` to extract `<script>` and `<base>` from HTML.
- Test material derived from REA (MIT, license above), used only to compare this port with the original:
  - `fixtures/jsgraph/rea/`: application trees generated by `fixtures/jsgraph/gen_rea_apps.mjs` from REA's test fixtures.
  - `fixtures/jsgraph/semantic/snippets.json`: JavaScript sources lifted from REA's unit tests (`src/domain/javascript` and `src/application/javascript` `*.test.ts`) by `scripts/gen_jsgraph_semantic_snippets.mjs`.
  - `crates/js/tests/snippets/` and `crates/js/tests/support/derived_scenarios.rs`: inline scenarios, partly taken from REA's unit tests of the static layer and of the derived collectors.
- `fixtures/jsgraph/npm/`: unmodified published packages `ms@2.1.3` (MIT, Copyright (c) 2020 Vercel, Inc.) and `escape-html@1.0.3` (MIT, Copyright (c) 2012-2013 TJ Holowaychuk, 2015 Andreas Lubbe, 2015 Tiancheng "Timothy" Gu). Each directory carries the package's own license file; tarball integrity and per-file digests are pinned in `fixtures/jsgraph/npm/PINS.json`.
- `fixtures/jsgraph/npm/commander-14.0.3/`: unmodified published package `commander@14.0.3` (MIT, Copyright (c) 2011 TJ Holowaychuk <tj@vision-media.ca>), pinned in `fixtures/jsgraph/npm/PINS.json`.
- `fixtures/jsgraph/dts/`: TypeScript declaration files copied unmodified from `@types/node`, `isomorphic-git`, `mdast-util-to-hast`, `@jridgewell/trace-mapping`, `jose` and `vfile` (MIT) and from `@typescript/typescript-linux-x64` (Apache-2.0; its `LICENSE` and `NOTICE.txt` are kept). Each package's license file sits next to its files; digests are pinned in `fixtures/jsgraph/dts/PINS.json`.
- Origin and license per directory: `fixtures/jsgraph/ATTRIBUTION.md`.
- `vendor/oxc_parser` is `oxc_parser` 0.75.0 from https://github.com/oxc-project/oxc (MIT License, Copyright (c) 2024-present VoidZero Inc. & Contributors, Copyright (c) 2023 Boshen; full text in `vendor/oxc_parser/LICENSE`, taken unchanged from tag `crates_v0.75.0`) with a recursion depth limit added; the change is described in `vendor/oxc_parser/TRACEWISE_PATCH.md`. The other `oxc_*` crates and `stacker` (MIT OR Apache-2.0) come from crates.io unmodified.

## Third-party test fixtures (not part of the binary)

- `fixtures/managed/real_primitives_net8.dll`, `real_primitives_net462.dll`, `real_systemevents_net8.dll`: assemblies from the NuGet packages Microsoft.Extensions.Primitives 8.0.0 and Microsoft.Win32.SystemEvents 8.0.0, Copyright (c) .NET Foundation and Contributors, MIT License (same text as the MIT license above, with that copyright notice). Origin and hashes in `fixtures/managed/PROVENANCE.txt`.
- `fixtures/native_static/assets/vendor/*.car`: catalogs from bartoszj/acextract (MIT, Copyright (c) 2014 Bartosz Janda) and coollazy/AssetsParser (Apache-2.0). License texts in `LICENSE-acextract` and `LICENSE-AssetsParser` in the same folder; per-file origin in that folder's `README.md`.
- Rust dependencies of `crates/native` under licenses other than MIT/Apache-2.0 (Unicode-3.0, Swift Runtime Library Exception): see `crates/native/NOTICE.md`.

External tools used only by the tests (Ghidra, JDK, jadx-headless-mcp, Apktool, Binwalk, Unblob, mitmproxy, Chrome, Electron, Node, REA itself) are not redistributed.
