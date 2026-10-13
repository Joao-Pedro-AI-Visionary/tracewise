# jsgraph: hostile nesting, deep chains and sloppy-mode JavaScript

Covers the review blockers on `crates/js/src/jsgraph/pipeline.rs` (`bracket_depth_exceeds`) and on
`jsgraph_hostile_test.rs` (`member-chain-50000`), plus the sloppy-mode failure of the whole application.

## What was wrong

1. **Lexical bracket counting is not a guard.** `bracket_depth_exceeds` skipped "strings" without
   knowing about regex literals, so `var r = /'/;` opened a string that swallowed every bracket after
   it; the parser then recursed 1 000 000 levels and the process aborted (a stack overflow is not a
   catchable panic). The same blindness produced false positives (`if (/\(/.test(s)) n++;` x 1 600).
   Brackets are also only one of many recursion sources: prefix operators, `if (a)` chains, nested
   types, `new new new`, `a=b=c=...` and so on recurse the same way, and no scanner can be sound for
   regex/template/JSX contexts.
2. **Chains were refused at 10 000 levels** by a heuristic on the converted tree, after the
   recursive conversion had already run, and the test was shrunk instead of fixed.
3. **Any recoverable Babel error failed the whole application** (`ConvertError::Unsupported`), where
   REA returns the graph with `parse_status: "partial"` for that file.

## What was done

- **The guard is inside the parser.** `vendor/oxc_parser` is `oxc_parser` 0.75.0 plus a depth counter on
  every recursion cycle of the grammar (`vendor/oxc_parser/TRACEWISE_PATCH.md`; selected with
  `[patch.crates-io]`, excluded from the workspace members). Past `MAX_NESTING_DEPTH` the parse ends
  with a fatal error, which `parse_babel` maps to `ConvertError::Unparseable` and the pipeline to a
  parse failure, as REA records when Babel overflows its stack. Nested TypeScript types and
  speculative parses weigh more, which also bounds the quadratic cost of `f<A<f<A<...` (12 s at 1 000
  levels before; milliseconds now).
- **Deep trees no longer need native stack.** `ast::depth` walks the oxc tree with oxc's visitor and
  stops descending at `MAX_AST_DEPTH` (200 000, was 10 000); the converter (`Cx`) recurses through
  `stacker::maybe_grow`, so depth costs heap segments, not the 768 MiB analysis stack. The oxc semantic
  pass and every analysis downstream measured at or below 160 bytes per level (50 000-level chains
  pass on an 8 MiB thread). The 10 000 -> 200 000 change moves the refusal point (REA analyzes a 200 000-member chain); trees deeper than
  that still end as `capability_unavailable`. A chain at the limit (199 000 members) takes 5 s and about 1.5 GB of
  resident memory in a debug build, almost all of it conversion stack segments.
- **Sloppy-mode JavaScript is a partial parse of the file.** `parse_once` now accepts the oxc
  diagnostics that were verified, against the live Babel parse, to map to exactly one recoverable
  Babel error and the same tree (`babel_counts_one_error`: `with`, legacy octal literals and
  escapes, redeclarations, `eval`/`arguments` bindings, `delete x`, reserved words, `break` /
  `continue` targets, `new.target`, `super`, missing `const` initializers, ...). `Ast::error_count` is
  the number of diagnostics. Any other diagnostic is still `Unsupported`, so a wrong error count is
  never answered.

## Evidence

- `crates/js/tests/jsgraph_limits_test.rs`: 44 recursive constructs x 400 000 levels through the whole
  pipeline (all parse failures, none aborts), the regex traps, brackets inside regex literals,
  chains of 50 000 members / calls / operators / tagged templates / `as` / `!`, the refusal at
  `MAX_AST_DEPTH + 10`, and the sloppy cases.
- `crates/js/tests/jsgraph_ast_parity_test.rs` (with `syntax_errors.txt` extended by the sloppy
  cases): tree and `errors.length` equal to Babel for every accepted diagnostic.
- `crates/server/tests/jsgraph_hostile_test.rs`: 26 hostile applications compared with the live REA
  (whole MCP result, byte for byte): member chains of 5 000 / 12 000 / 50 000, the 1M-bracket file
  behind `/'/`, brackets in regex literals, four sloppy files.

## Known gaps

- Babel's recursion limit depends on the construct and on Node's stack (about 350 nested arrays, 400
  parentheses, 500 calls, 800 blocks, 3 700 `!`, 6 500 `+` in a chain on this machine); the port uses
  one budget for all of them (`MAX_NESTING_DEPTH` 10 000 entries; an array level costs about 5, a
  statement 3, a type 20, a speculative parse 100). Inputs between the two limits parse here and fail
  in REA (or the reverse for long operator chains, which the parser reads iteratively). Not compared.
- A chain deeper than 200 000 levels is refused for the whole application (REA analyzes 200 000
  members in 9 s, and answers 1 000 000 with a response-budget error after 38 s).
- Babel diagnostics outside the accepted list (for example `let let`, `export { undeclared }`, duplicate
  block-level functions) are still reported as unsupported; see `jsgraph-static.md` known gap 1.
- Parser time: repeated speculative constructs (`f<A<f<A<...` in `.ts`) are quadratic in the oxc parser
  (Babel is too, until its stack gives out near 250 levels). The type weight caps them near 250 levels,
  about 0.1 to 1 s in a debug build, instead of the 12 s at 1 000 levels and minutes at the old limit.
  Bounded, not eliminated.
- A call chain (`f()()()...`) of 50 000 links produces a 46 MB result in 112 s in the port because each
  node carries the text of the whole chain (the MCP response budget turns that into an error). REA was
  not run on that input; the test uses 3 000 links.
