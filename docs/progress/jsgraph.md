# jsgraph: native JavaScript application graph (overview)

`analyze_javascript_application` no longer replays recorded REA answers for two fixture apps: it runs
a Rust port of REA's JavaScript pipeline (`domain/javascript/*` and `application/javascript/*`, REA
commit `0fa0b04`) under `crates/js/src/jsgraph/`. This page ties the per-layer notes together.

| Layer | Module | Notes |
| --- | --- | --- |
| Babel-shaped AST from oxc | `jsgraph/ast/` | parser boundary, Babel error-recovery handling |
| Static layer | `jsgraph/static_analysis/` | [jsgraph-static.md](jsgraph-static.md) |
| Semantic core | `jsgraph/semantic/` | [jsgraph-semantic.md](jsgraph-semantic.md) |
| Derived collectors (17 IR fields) | `jsgraph/semantic/` | [jsgraph-semantic-derived.md](jsgraph-semantic-derived.md) |
| Application graph | `jsgraph/app_graph/` | files, path resolution, structure, bundlers, relationships, findings, Electron, HTML |
| Semantic relation graph | `jsgraph/semantic_graph/` | nodes, relations, unknowns, fingerprints, node budgets |
| Pipeline and limits | `jsgraph/pipeline.rs`, `jsgraph/control.rs`, `jsgraph/error.rs` | cancellation checkpoints, REA error envelopes, depth limits |

The MCP handlers apply REA's response budget (`REA_MCP_MAX_RESPONSE_BYTES`, floor 10 MiB): a result
whose wire representations do not fit returns REA's budget error.

## Tests

All parity tests run the compiled REA live (`REA_SRC`); none compares against recorded answers.

| Test | What it compares |
| --- | --- |
| `crates/js/tests/jsgraph_ast_parity_test.rs` | the converted tree against REA's `@babel/parser`, node by node; inline snippets, every JS/TS file under `fixtures/` and REA's test fixtures, and `fixtures/jsgraph/syntax_errors.txt` (Babel-recoverable errors must be reported as unsupported, never as a clean tree) |
| `crates/js/tests/jsgraph_layer_types_test.rs` | the Rust layer types round-trip REA's JSON exactly |
| `crates/js/tests/jsgraph_static_test.rs`, `jsgraph_static_functions_test.rs` | static layer and its public functions |
| `crates/js/tests/jsgraph_semantic_test.rs` | semantic core and the two classifier maps |
| `crates/js/tests/jsgraph_semantic_derived_test.rs` | the 17 derived IR fields; oracle run in chunks with a one-line-per-file check |
| `crates/js/tests/jsgraph_app_graph_test.rs` | application graph, Electron summary, statistics and semantic relation graph on 11 fixture applications |
| `crates/js/tests/jsgraph_limits_test.rs` | stack safety and structured refusals on hostile syntax |
| `crates/server/tests/jsgraph_mcp_parity_test.rs` | whole MCP result of `analyze_javascript_application`, `trace_application_feature`, `trace_javascript_semantics`, `compare_application_versions`, `compare_source_to_bundle`, `compare_javascript_export_shapes` against the original REA MCP server |
| `crates/server/tests/jsgraph_hostile_test.rs` | hostile and degenerate applications, same graph or same error envelope as REA |
| `crates/server/tests/jsgraph_cancel_test.rs` | dropping an in-flight call stops the analysis thread; the next call works (Linux only) |

Recorded corpus runs are in the per-layer notes (for example, the static layer: 916 files on the
default corpus and 2,831 + 13,343 files on extra corpora with zero differences outside the AST gaps;
the derived collectors: 1,181 files on the default corpus with zero differences). They describe the
state when each layer landed; the current suite count is reported by the test run, not here.

Environment: `REA_SRC`, `TRACEWISE_REQUIRE_ORACLE`, `TRACEWISE_JSGRAPH_STRIDE`,
`TRACEWISE_JSGRAPH_CORPUS`, `TRACEWISE_AST_CORPUS`.

## Known gaps

1. **Babel error recovery.** REA parses with `errorRecovery: true` and analyzes a partial tree;
   oxc is strict. For the recoverable errors the parser boundary recognizes (early errors such as
   redeclarations and strict-mode rules, and a list of oxc messages Babel records instead of
   throwing), the analysis returns an explicit unsupported error naming the file instead of a
   different parse status. A file ending in a lone `\` is recorded as a parse failure where Babel
   recovers (`KNOWN_PARSER_DISAGREEMENTS` in the AST test).
2. **Lone surrogates.** A Rust `String` cannot hold `'\ud800'`. Fingerprint tokens decode oxc's
   encoding and match REA; `eventName`, `command`, `endpoint`, configuration `key` and similar
   string outputs can differ.
3. **Nesting limits.** More than 1,500 nested brackets is treated as a parse failure (Babel overflows
   too, at a stack-dependent depth); syntax trees deeper than 10,000 levels that still parse are
   refused with a structured error. Babel's limit and the port's fixed one disagree between a few
   hundred and about 1,500 nested brackets; `jsgraph_hostile_test.rs` does not assert that band.
4. **Ambiguous top-level `await (x)`.** Babel (`sourceType: "unambiguous"`) reads it as a call; the
   port reads a top-level await.
5. **`file:` source-map URLs.** The `url` crate and Node's WHATWG parser disagree on path segments
   that look like Windows drive letters (22 of 6,572 fuzz cases in the static functions test); a
   drive prefix with a non-ASCII letter is treated as an invalid path.
6. **Performance.** Not characterized on large real-world applications. The cancellation test was
   sized down because a 1,500-file synthetic app did not finish in a debug build.
