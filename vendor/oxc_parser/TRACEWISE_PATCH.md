# Vendored `oxc_parser` 0.75.0 with a recursion-depth guard

This directory is `oxc_parser` 0.75.0 from crates.io (MIT, Boshen and the Oxc contributors,
https://github.com/oxc-project/oxc) with one change, selected through `[patch.crates-io]` in the
workspace `Cargo.toml`. Remove the patch (and this directory) as soon as upstream offers an
equivalent limit.

## Why

The parser is recursive descent. A file made of nested brackets, prefix operators, `if (a)` chains,
nested types and so on overflows the native stack, which aborts the whole process (a stack overflow
is not a catchable panic). `tracewise-js` analyzes untrusted application bundles, so a 2 MB hostile
file must not be able to take the server down. A lexical pre-check cannot be sound (regex literals,
templates and JSX change what a bracket is), so the guard has to live inside the parser.

## What changed

- `src/lib.rs`: new field `nesting` / `nesting_exceeded` on `ParserImpl`, constants
  `MAX_NESTING_DEPTH` (10 000 entries), `SPECULATION_NESTING_WEIGHT` (100),
  `STATEMENT_NESTING_WEIGHT` (3), `TS_TYPE_NESTING_WEIGHT` (20) and `NESTING_ERROR_MESSAGE`.
- `src/error_handler.rs`: `enter_nesting`, `leave_nesting`, `*_weighted`, `nesting_exceeded`
  (raises a fatal error, which unwinds the whole parse like any other fatal error).
- `src/diagnostics.rs`: `nesting_too_deep`.
- Every recursion cycle of the grammar passes through one of these functions, each split into a
  counting wrapper and the original body (`*_nested`): `parse_assignment_expression_or_higher_impl`,
  `parse_binary_expression_or_higher`, `parse_simple_unary_expression`, `parse_update_expression`,
  `parse_primary_expression`, `parse_statement_list_item` (weight 3), `parse_binding_pattern_kind`,
  `parse_ts_type` (weight 20), `parse_type_operator`, `parse_jsx_element`.
- `src/cursor.rs` `try_parse`: speculative parses weigh 100 entries each and a nesting failure inside
  one is not rewound (speculation is re-done when it fails, so nested speculation such as
  `f<A<f<A<...` is quadratic or worse; this bounds it to about a hundred levels).
- `Cargo.toml`: `[[example]]` entries and the `include` list dropped; `examples/` keeps only the two
  files that `lib.rs` pulls in as documentation.

The parse result for any input that stays under the limit is unchanged. The `nesting` counter is
balanced on every path (each wrapper leaves what it entered, rewinds included).

## Evidence

`crates/js/tests/jsgraph_limits_test.rs` runs 44 recursive constructs, 400 000 levels each, through
the whole pipeline, and `crates/server/tests/jsgraph_hostile_test.rs` compares hostile files with
the live REA.
