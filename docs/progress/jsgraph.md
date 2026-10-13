# jsgraph: native JavaScript application graph (overview)

`analyze_javascript_application` no longer replays recorded REA answers for two fixture apps: it runs
a Rust port of REA's JavaScript pipeline (`domain/javascript/*` and `application/javascript/*`, REA
commit `0fa0b04`) under `crates/js/src/jsgraph/`. This page ties the per-layer notes together.

| Layer | Module | Notes |
| --- | --- | --- |
| Babel-shaped AST from oxc | `jsgraph/ast/`, `vendor/oxc_parser` | parser boundary, sloppy-mode partial parses, nesting guard: [jsgraph-depth.md](jsgraph-depth.md); definition files: [jsgraph-ast-dts.md](jsgraph-ast-dts.md) |
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
| `crates/js/tests/jsgraph_ast_parity_test.rs` | the converted tree against REA's `@babel/parser`, node by node; inline snippets, every JS/TS file under `fixtures/` and REA's test fixtures, and `fixtures/jsgraph/syntax_errors.txt` (tree and `errors.length` equal to Babel for every accepted recoverable diagnostic; any other one must be reported as unsupported, never as a clean tree) |
| `crates/js/tests/jsgraph_layer_types_test.rs` | the Rust layer types round-trip REA's JSON exactly |
| `crates/js/tests/jsgraph_static_test.rs`, `jsgraph_static_functions_test.rs` | static layer and its public functions |
| `crates/js/tests/jsgraph_semantic_test.rs` | semantic core and the two classifier maps |
| `crates/js/tests/jsgraph_semantic_derived_test.rs` | the 17 derived IR fields; oracle run in chunks with a one-line-per-file check |
| `crates/js/tests/jsgraph_app_graph_test.rs` | application graph, Electron summary, statistics and semantic relation graph on 11 fixture applications |
| `crates/js/tests/jsgraph_limits_test.rs` | 44 recursive constructs at 400,000 levels through the whole pipeline (parse failures, no abort), regex traps, 50,000-link chains, the refusal past `MAX_AST_DEPTH`, sloppy-mode files |
| `crates/js/tests/jsgraph_oracle_guard_test.rs` | the shared oracle helper refuses truncated or unreadable oracle output (no REA needed) |
| `crates/js/tests/jsgraph_cancel_midway_test.rs` | cancellation during the per-file loop stops at the next file boundary (deterministic) |
| `crates/server/tests/jsgraph_mcp_parity_test.rs` | whole MCP result of `analyze_javascript_application`, `trace_application_feature`, `trace_javascript_semantics`, `compare_application_versions`, `compare_source_to_bundle`, `compare_javascript_export_shapes` against the original REA MCP server |
| `crates/server/tests/jsgraph_hostile_test.rs` | hostile and degenerate applications (including member chains of 5,000 / 12,000 / 50,000, a one-million-bracket file behind a regex literal, sloppy-mode files), same graph or same error envelope as REA |
| `crates/server/tests/jsgraph_inventory_parity_test.rs` | artifact inventory (source-map pairing) against the live REA MCP server |
| `crates/server/tests/jsgraph_cancel_test.rs` | dropping an in-flight call stops the analysis thread; the next call works (Linux only) |

Recorded corpus runs are in the per-layer notes (for example, the static layer: 916 files on the
default corpus and 2,831 + 13,343 files on extra corpora with zero differences outside the AST gaps;
the derived collectors: 1,181 files on the default corpus with zero differences). They describe the
state when each layer landed; the current suite count is reported by the test run, not here.

Environment: `REA_SRC`, `TRACEWISE_REQUIRE_ORACLE`, `TRACEWISE_JSGRAPH_STRIDE`,
`TRACEWISE_JSGRAPH_CORPUS`, `TRACEWISE_AST_CORPUS`.

## Known gaps

1. **Babel error recovery.** REA parses with `errorRecovery: true` and analyzes a partial tree;
   oxc is strict. The oxc diagnostics verified against the live Babel parse to map to exactly one
   recoverable Babel error and the same tree (`with`, legacy octal literals and escapes,
   redeclarations, `eval`/`arguments` bindings, `delete x`, reserved words, `break`/`continue`
   targets, `new.target`, `super`, missing `const` initializers, ...) make that file
   `parse_status: "partial"` with `Ast::error_count` equal to the number of diagnostics, as in REA.
   Any other diagnostic (for example `let let`, `export { undeclared }`, duplicate block-level
   functions, or `declare function f() {}` in definition files) is still `Unsupported`: the
   analysis returns an explicit error naming the file instead of a wrong error count. A file ending
   in a lone `\` is recorded as a parse failure where Babel recovers (`KNOWN_PARSER_DISAGREEMENTS`
   in the AST test).
2. **Lone surrogates.** A Rust `String` cannot hold `'\ud800'`. Fingerprint tokens decode oxc's
   encoding and match REA; `eventName`, `command`, `endpoint`, configuration `key` and similar
   string outputs can differ.
3. **Nesting limits (not compared).** The guard is inside the parser: `vendor/oxc_parser` adds a
   weighted depth budget (`MAX_NESTING_DEPTH` 10,000 entries; an array level costs about 5, a
   statement 3, a type 20, a speculative parse 100). Past it the file is a parse failure, as when
   Babel overflows Node's stack. Trees that parse but are deeper than `MAX_AST_DEPTH` (200,000) are
   refused for the whole application (REA analyzes a 200,000-member chain). Babel's limit depends on
   the construct and on Node's stack (about 350 nested arrays, 400 parentheses, 500 calls, 800
   blocks, 3,700 `!`, 6,500 `+` in a chain on the measuring machine), so between the two limits the
   outputs differ: parentheses nested 400 or 600 deep, or arrays nested 1,500 deep, overflow REA's
   stack and parse here (the reverse for long operator chains, which oxc reads iteratively). That
   band is not compared. See [jsgraph-depth.md](jsgraph-depth.md).
4. **Ambiguous top-level `await (x)`.** Babel (`sourceType: "unambiguous"`) reads it as a call; the
   port reads a top-level await.
5. **`file:` source-map URLs.** The `url` crate and Node's WHATWG parser disagree on path segments
   that look like Windows drive letters (22 of 6,572 fuzz cases in the static functions test); a
   drive prefix with a non-ASCII letter is treated as an invalid path.
6. **Memory.** Time is similar to REA's or lower and, like memory, grows linearly with the number of
   files, but memory per file is much higher. Measured through the MCP surface on synthetic 120-line
   files: Tracewise 152 / 910 / 3,517 MB against REA 321 / 428 / 668 MB for 1 / 8 / 32 files, about
   105 MB per file against about 11 MB. Projects of about 1,500 such files run out of memory in both.
   Identified improvement: serialize and hash the result in streaming instead of building it whole.
