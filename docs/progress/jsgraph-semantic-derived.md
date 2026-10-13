# jsgraph: semantic derived collectors

Branch `jp-jsgraph-sem2`. Port of the eight derived passes REA runs after the lexical/semantic core
(`javascriptSemanticDerivedAnalysis.ts`). `analyze_semantics` now fills the 17 derived fields of the
IR (`derived::collect_derived`, called exactly where REA calls
`collectJavaScriptDerivedSemanticsSteps`).

## File map (TS -> Rust, all under `crates/js/src/jsgraph/semantic/`)

| REA (`domain/javascript/`) | Rust module | Output |
| --- | --- | --- |
| `javascriptSemanticDerivedAnalysis.ts` | `derived.rs` (`collect_derived`) | composition, 17 fields |
| `javascriptSemanticCalls.ts` | `calls.rs` | `callSites`, `argumentFlows`, `callReturnFlows`, `callResultFlows`, `closureCaptures`, `frontiers` |
| `javascriptSemanticPromises.ts` | `promises.rs` | `promiseOperations` |
| `javascriptSemanticAsyncEffects.ts` | `async_effects.rs` | `eventOperations`, `timerOperations` |
| `javascriptSemanticChildProcesses.ts` | `child_processes.rs` | `childProcessSpawns`, `childProcessInteractions` |
| `javascriptSemanticDataEffects.ts` | `data_effects.rs` | `configurationOperations`, `requestOperations`, `boundaryOperations` |
| `javascriptSemanticDataEffectHelpers.ts` | `data_effect_helpers.rs` | shared result-binding projection, built-in method resolution, callable stack |
| `javascriptSemanticResources.ts` | `resources.rs` | `resourceOperations` |
| `javascriptSemanticObjects.ts` | `objects.rs` | `objectOperations` |
| `javascriptSemanticFingerprints.ts` | `fingerprints.rs` | `functionFingerprints` |

Public API: `semantic::analyze_semantics` (unchanged) now returns the populated fields; each module
exposes its `collect_semantic_*` entry point (`calls::collect_semantic_calls`,
`promises::collect_semantic_promises`, ...) taking `(root: N, state, callables)`.

## Porting notes (where Rust differs from the TS shape, results do not)

- Ancestor stacks are the `parent()` chain (REA's `ancestors` array is exactly the path to the node).
  `assigned_semantic_result_bindings` takes the ancestors as an iterator, nearest first.
- `WeakMap<t.Node, _>` -> `HashMap<NodeId, usize>`; `Map` insertion order is kept with `Vec` plus index
  maps; sorts use `compare_code_points` where REA uses `compareUnicodeCodePoints` and UTF-16 order
  (`encode_utf16`) where REA uses the default `.sort()` (resource ids, ASCII anyway).
- Fingerprints: REA walks each callable's subtree separately (quadratic in nesting depth). The port
  walks the program once and attributes every node to its innermost enclosing-or-self callable, which
  yields identical token lists and order (checked by the oracle) while staying linear on deeply nested
  bundles.
- Calls: the "innermost non-class callable" is tracked on the stack (O(1)) instead of `findLast`.

## Deviations forced by the arena AST (documented, behavior-preserving)

- `ClassPrivateMethod` / `ClassPrivateProperty` `computed`: Babel only sets the flag when the member
  name was first parsed as an ordinary property name (`get #x`, `set #x`, `async #x`); the arena AST
  normalizes it to `false`. The fingerprint's `primitiveAttribute(node, "computed")` restores Babel's
  presence rule (`fingerprints::babel_omits_computed`). Found by diffing attribute presence of the six
  fingerprint attributes per node type between Babel and the arena AST over ~1.7k files: these were
  the only two differing types.
- Lone surrogates: oxc encodes them inside `String` values as U+FFFD + four hex digits and the arena AST
  drops oxc's `lone_surrogates` flag. Fingerprint literal/property tokens decode that encoding (only
  when the raw source has an escape and every U+FFFD is followed by a valid code unit) so the
  `JSON.stringify` escape (`\udXXX`) and code-point ordering match REA. Other string outputs
  (`eventName`, `command`, `endpoint`, config `key`) are not decoded: a Rust `String` cannot hold a lone
  surrogate (see known gaps).

## Tests

`crates/js/tests/jsgraph_semantic_derived_test.rs`: for every corpus file, `parse_babel` +
`analyze_semantics`, compare ONLY the 17 derived keys with the oracle line's `ir`
(`support::diff`, exact). Corpus: default support corpus + 8 inline snippets + 12 adversarial
scenario files (`tests/support/derived_scenarios.rs`: call shapes, closures, Promise ownership,
EventEmitter, timers, child processes, config/requests/boundaries, resources, objects, TypeScript and
private-member fingerprints) + `fixtures/jsgraph/semantic/snippets.json` (sources lifted from REA's own
unit tests: `*.calls`, `.promise_ownership`, `.rejection`, `.runtime_boundaries`, `.recoveredArguments`,
`.dataflow`, `.member_mutations`, `.reference_lifetimes`, `Steps`, `GraphBuilder`, `GraphResources`,
`ApplicationService`, `AnalysisControl`).

Environment variables: `TRACEWISE_JSGRAPH_STRIDE`, `TRACEWISE_JSGRAPH_CORPUS` (shared, see
`tests/support/mod.rs`), `TRACEWISE_DERIVED_KEYS=callSites,frontiers` (development aid: compare only
those keys), `TRACEWISE_REQUIRE_ORACLE=1`.

### Oracle output loss found and worked around

REA's `layers.mjs` answers a long file list over a pipe and, on large corpora, its stdout silently
stops after a few lines with exit status 0 (reproduced: the same 2456-file list gives 2 lines over a
pipe and 2456 lines when redirected to a file). The shared `support::stream_oracle` only checks the exit
status, so a `STRIDE=1` or extra-corpus run can "pass" while comparing a tiny prefix. This test runs the
oracle in chunks of 100 files and asserts exactly one output line per file, so the comparison cannot
silently cover a prefix. The other jsgraph layer tests (`jsgraph_semantic_test`, static, app-graph)
use `stream_oracle` and have the same blind spot on big corpora.

## Results

The default-corpus run compares 1,181 files with zero differences on all 17 keys. Counts for other
runs are printed by the test; see [jsgraph.md](jsgraph.md) for the overview.

## Known gaps

- Lone surrogates in string values that surface in `eventName`, `command`, `endpoint`,
  configuration `key`, `property` tokens of non-fingerprint outputs: not representable as a Rust
  `String` (REA's JSON would carry `\udXXX`; the shared test harness cannot read those oracle lines
  either).
- Files the AST layer cannot reproduce (Babel error recovery trees, ambiguous top-level `await (`):
  skipped and counted in the test output, same policy as `jsgraph_semantic_test.rs`.
