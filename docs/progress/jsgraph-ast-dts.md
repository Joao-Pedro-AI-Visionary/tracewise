# jsgraph AST: definition files (`.d.ts`, `.d.mts`, `.d.cts`)

## Root cause

REA parses with Babel's `typescript` plugin `{ dts: true }` for `*.d.(ts|mts|cts)`. The port already asked
oxc for a definition-file source type, but oxc builds NO scopes or bindings for those files. The AST layer
decides Babel's recoverable error count (`parse_status`, coverage, semantic roles) partly from oxc's scope
table, so every `export { A as B }` of a declared name looked like "Export 'A' is not defined" (one phantom
error), turning `complete` into `partial` and changing the semantic roles. Other Babel diagnostics that depend
on Babel's own scope handler were never produced for these files either.

## What changed (`crates/js/src/jsgraph/ast/`)

- `convert.rs`: the semantic pass runs on a regular-TypeScript copy of the source type for definition files
  (the parse itself keeps ambient rules); oxc checker messages Babel never reports (bodiless functions,
  constructors, accessors) are filtered; strict-mode binding messages are filtered inside ambient code.
- `convert_scope.rs` (new): the slice of Babel's TypeScript scope tracking that matters for error counts:
  `export { x }` resolution inside `declare module "x"` / `namespace` bodies (class, enum, namespace, interface,
  type, bodiless function, named import, `import =` count; `var`/`let`/`const`, functions with bodies and
  default/namespace imports do not), named imports are never resolved by a LATER import, `declare global`
  shares the file scope (redeclaration clashes), namespace-only errors (imports of modules, exports that are
  not `export <declaration>`), ambient errors (function/method bodies, variable and field initializers), and
  `export = function f();` (Babel throws, so `Unparseable`).
- `convert_decl.rs`/`convert_ts.rs`: `class A implements a.b.C` carries a `MemberExpression` chain (as Babel),
  not a `TSQualifiedName`.
- `export { type X }` / `export type { X }` are checked like Babel does (they used to be skipped).

## Evidence

Corpus additions (all picked up by the AST, static, semantic and application tests through `fixtures/`):
`fixtures/jsgraph/dts/` (real files from `@types/node`, `@typescript/typescript-linux-x64`, `isomorphic-git`,
`mdast-util-to-hast`, `@jridgewell/trace-mapping`, `jose`, `vfile`), `fixtures/jsgraph/npm/commander-14.0.3`
(typings), `fixtures/jsgraph/own/ambient-cases/` (the three minimal cases plus 196 matrix cases) and
`fixtures/jsgraph/own/dts-app` (application root with `.d.ts`/`.d.mts`/`.d.cts`).

Before the fix the new corpus fails (125 static-layer and 64 semantic-layer differences); after it every
layer test is green. Wider sweep (not committed): `TRACEWISE_AST_CORPUS=<every .d.ts/.d.mts/.d.cts of REA's
node_modules, 3934 files>` gives 0 differences, except `@babel/parser/lib/index.d.ts` (pre-existing known
disagreement: it uses `accessor`, which Babel itself rejects without a plugin).

## Known gaps

- Babel's `importsStack` leaks sets for every scope it creates, so an import can stay visible after its
  module/namespace ended; only the simple lifetime (current and enclosing blocks) is modelled.
- `declare const x = (1)`: Babel rejects a parenthesized ambient initializer; oxc drops the parentheses.
- Files where oxc itself reports an error Babel also recovers from (for example `declare function f() {}`)
  stay `Unsupported` (honest), exactly as for non-ambient code.
- Strict-mode messages are only filtered inside top-level `declare` statements and definition files.
