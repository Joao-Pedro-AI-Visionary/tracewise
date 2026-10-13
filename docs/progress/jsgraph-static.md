# jsgraph — static layer (REA `analyzeParsedJavaScriptStaticSource`)

Branch `jp-jsgraph-static`. Module `crates/js/src/jsgraph/static_analysis/`.

## Public API (`jsgraph::static_analysis`)

```rust
analyze_static_source(source, &ast, &open_receivers, &electron_bindings) -> StaticAnalysis
fingerprint_javascript_ast(node: N) -> String        // + fingerprint_javascript_file(&ast)
collect_javascript_exports(node: N) -> StaticExports
resolve_source_map_reference(source_name, source_root, map_path) -> SourceMapReference
// exported helpers REA also exposes: callee_name, module_property_name, module_factory,
// factory_require_name, chunk_runtime, static_path, static_path_resolution_context,
// static_array_values, string_value, argument_value, endpoint_argument, storage_kind,
// detect_vendors, registration_key, sorted_unique_registrations, member_path
```

`analyze_static_source` runs the traversal on a thread with a 256 MiB stack: `staticPath` and
`isFilesystemPathExpression` recurse over expression nesting exactly like REA. A source that did
not parse is the caller's job (`StaticAnalysis::failed()`).

## File map

| REA (`domain/javascript/`) | Rust (`jsgraph/static_analysis/`) |
|---|---|
| `javascriptStaticAnalysis.ts` | `mod.rs` (traversal, `inspectNode`, finalize) |
| `javascriptStaticAnalysisState.ts`, `...Findings.ts` | `state.rs` (accumulator, segment-tree module index, located findings) |
| `javascriptStaticAnalysisHelpers.ts` | `helpers.rs` (+ `posix.rs`, `uri.rs`) |
| `javascriptStaticAnalysisCalls.ts` | `calls.rs` |
| `javascriptStaticAnalysisBundler.ts` | `bundler.rs` |
| `electronStaticAnalysis{,Browser,Ipc,Native,Values}.ts` | `electron_{browser,ipc,native,values}.rs` |
| `javascriptAstFingerprint.ts` | `fingerprint.rs` |
| `javascriptSourceMapPaths.ts` | `source_map_paths.rs` |
| `sanitizeEndpointCandidate` (`browserObservation.ts`) | reused: `tracewise_web::browser_observation::sanitize_browser_url` |

JS semantics that leak into the output are replicated: UTF-16 offsets/columns, `Set`/`Map`
insertion order, code-point sort (`compare_code_points`), `String.prototype.trim`
(JS whitespace set), `/iu` case folding where a regex needs it (U+017F, U+212A), ASCII `\b`, JS `\s`
(including U+FEFF, excluding U+0085), `String(number)`, `JSON.stringify` for composite keys and the
fingerprint token array, `decodeURIComponent`, Node `path.posix` (UTF-16 lengths) and
`fileURLToPath`.

## Tests (all against the live compiled REA)

| Test | What it proves |
|---|---|
| `jsgraph_static_test.rs` | `serde_json::to_value(analyze_static_source(..)) == REA static` for every corpus file, exact (keys, array order, values). Corpus = shared one + ~630 inline scenarios (`tests/snippets/`: REA's own unit-test sources for native loaders, Electron options, member-path depth, no-caps, locations, module index, source maps, static path resolution, file URL paths, open classification, plus combinatorial sweeps over callee names, argument shapes, IPC methods, bundler runtimes, path expressions, comment forms). The two semantic maps come from the oracle line. |
| `jsgraph_static_functions_test.rs` | `resolve_source_map_reference` on 6,572 declarations (hand-picked + pseudo-random), `sanitize_browser_url` on ~3,000 endpoint strings, `fingerprint_javascript_file/_ast` + `collect_javascript_exports` on every corpus file, and a large-input smoke test (20,000-module bundle, 100,000-term concatenation, 20,000-deep member chain, 50,000 calls: all well under a few seconds in a debug build). |
| unit tests in `posix.rs`, `uri.rs`, `source_map_paths.rs` | Node `path.posix` examples, `decodeURIComponent` edge cases, source-map happy paths. |

Oracle scripts added: `fixtures/jsgraph/oracle/static_layer.mjs` (static layer only, skips the
semantic IR, synchronous writes) and `fixtures/jsgraph/oracle/static_functions.mjs`.

### Evidence (this branch)

- default corpus (`cargo test -p tracewise-js --test jsgraph_static_test`): 916 files checked, 0 differences
  (oracle findings compared: 11,910 references, 819 endpoints, 160 bundler registrations, 348 IPC, 268
  BrowserWindow, 259 utility processes, 383 role paths, 107 storage, 44 source-map URLs, ...).
- `TRACEWISE_JSGRAPH_STRIDE=1` with `TRACEWISE_JSGRAPH_CORPUS=` REA `node_modules/{vite/dist, rolldown/dist,
  oxfmt/dist, oxlint/dist, playwright-core/lib, @vue, jiti/dist, @modelcontextprotocol, magicast/dist,
  vitepress}`: 2,831 files, 0 differences except the AST-layer gap listed below.
- the unpacked JavaScript of three real Electron applications installed on the development machine
  (application code and bundled `node_modules`): 13,343 files, 0 differences.
- `cargo clippy -p tracewise-js --all-targets`: zero warnings in `static_analysis/` and the new tests
  (two pre-existing warnings remain in `jsgraph/ast/convert_ts.rs`).

Env vars: `TRACEWISE_JSGRAPH_STRIDE`, `TRACEWISE_JSGRAPH_CORPUS` (shared), `TRACEWISE_REQUIRE_ORACLE`,
`REA_SRC`, and `TRACEWISE_SNIPPET_DUMP=<dir>` (debug aid of `jsgraph_static_test`: writes the inline
snippets to disk).

## Known gaps

1. **AST layer (not changed, per brief).** Babel *recovers* from these (`parse_status: "partial"`,
   `parse_error_count > 0`) but `parse_babel` fails or does not count them; the static findings are
   identical wherever the parse succeeds (snippets `astgap_*` assert exactly that):
   - invalid escape in an untagged template (`` `\unicode` ``) -> `Unparseable`;
   - `import(...a)` / `import()` -> `Unparseable`;
   - a `set` accessor with an initializer (`set x(v = 1)` in `vitepress/dist/node/chunk-*.js`) -> `Unparseable`;
   - not counted as recoverable errors: redeclaration (`let a; let a;`), `export { undeclared }`,
     `#p in obj` outside a class (Babel's scope/private-name errors).
   - lone surrogate escapes in string literals (`'\ud800'`) have no exact Rust `String`, so a
     fingerprint token for such a literal differs (`javascriptSemanticGraphQuery.test.ts`).
   - `parse_babel` itself recurses over expression nesting; the tests run it on a 1 GiB-stack thread
     (a 12,000-member chain overflows a 2 MiB test thread).
2. **`url` crate vs ada (source maps).** For `file:` URLs the `url` crate treats any path segment that
   starts with `<letter>:` as a Windows drive letter (it will not pop it on `..` and inserts a slash after
   `x:` in `x:y`), where WHATWG/ada only special-case a lone first segment. Affects
   `resolve_source_map_reference` only for non-Windows references or map paths that contain such a
   segment (22 of 6,572 fuzz cases; the test names the predicate). Everything else, including the
   Windows drive/UNC branch, matches. The `url` crate's backslash-after-port leniency for non-special
   schemes is worked around (`has_invalid_non_special_port`).
3. A drive prefix with a non-ASCII letter (`/^[a-z]:\//iu` folds U+017F/U+212A) makes Node consult
   `process.cwd()`; this port treats it as an invalid path (`Source reference is not a valid URL or
   filesystem path.`) instead of reproducing a host-dependent result.
4. `path.posix.resolve` is only implemented for absolute inputs (the only form REA reaches).

## Touched outside the module

New files only: `fixtures/jsgraph/oracle/static_layer.mjs`, `fixtures/jsgraph/oracle/static_functions.mjs`,
`crates/js/tests/jsgraph_static_test.rs`, `crates/js/tests/jsgraph_static_functions_test.rs`,
`crates/js/tests/snippets/*`. No edits to `ir.rs`, `static_types.rs`, `util.rs`, `ast_values.rs`, `ast/`,
`Cargo.toml` (uses the existing `url`, `fancy-regex`, `sha2`, `hex`, `tracewise-web` dependencies).

Note for the lead: `layers.mjs` loses output on a pipe when a line is tens of MB (a 62 MB line
from the semantic IR of a large bundle made `node` end early with exit code 0 after ~86 files). The
new `static_layer.mjs` writes synchronously; the semantic tests may want the same for big corpora.
