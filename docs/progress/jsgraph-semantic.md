# jsgraph: núcleo semântico (`crates/js/src/jsgraph/semantic/`)

Porte fiel do núcleo da análise semântica do REA (`domain/javascript/javascriptSemantic*.ts`, commit 0fa0b04)
sobre a AST em forma de Babel de `jsgraph/ast`. Os coletores derivados (calls, promises, async effects,
child processes, data effects, resources, objects, fingerprints) NÃO fazem parte desta camada: ficam atrás de
`semantic::derived::collect_derived`, que hoje devolve listas vazias (`// TODO(derived)`).

Legenda de status: **Validado** (executado contra o oráculo REA, com evidência), **Não verificável** (sem
oráculo ou fora do ambiente). Teste: `crates/js/tests/jsgraph_semantic_test.rs`.

## Mapa arquivo TS para módulo Rust

| REA (`domain/javascript/`) | Rust (`semantic/`) |
| --- | --- |
| `javascriptSemanticAnalysis.ts` (definições, `bindPattern`, escopos, `analyzeParsedJavaScriptSemantics`, `analyzeParsedJavaScriptReferences`, classificadores de `.open` e Electron) | `analysis.rs` |
| `javascriptSemanticState.ts` | `state.rs` |
| `javascriptSemanticTraversal.ts` | `traversal.rs` (sem geradores: a travessia é síncrona) |
| `javascriptSemanticProjection.ts` (callables, links de módulo, referências, escopos/bindings imutáveis) | `projection.rs` |
| `javascriptSemanticValues.ts` (lattice de valores, proveniência) | `values.rs` |
| `javascriptSemanticValueTypes.ts` | tipos em `jsgraph/ir.rs` + auxiliares em `value_types.rs` |
| `javascriptSemanticPrimitives.ts` (+ coerções `String`/`Number`/truthiness) | `primitives.rs` |
| `javascriptSemanticSlots.ts` | `slots.rs` |
| `javascriptSemanticPropertyPaths.ts` | `property_paths.rs` |
| `javascriptSemanticMutationValues.ts` | `mutation_values.rs` |
| `javascriptSemanticMutationInitializers.ts` | `mutation_initializers.rs` |
| `javascriptSemanticMemberMutations.ts` | `member_mutations.rs` |
| `javascriptSemanticIterationSources.ts` | `iteration_sources.rs` |
| `javascriptSemanticCallableResults.ts` | `callable_results.rs` |
| `javascriptSemanticCallResolution.ts` | `call_resolution.rs` |
| `javascriptSemanticReturnedReferences.ts` | `returned_references.rs` |
| `javascriptSemanticReturns.ts` (sem `flattenSemanticReturnValue`, que é da camada de grafo) | `returns.rs` |
| `javascriptSemanticRequireOrigin.ts` | `require_origin.rs` |
| `javascriptSemanticProvenance.ts` | `provenance.rs` |
| `javascriptSemanticCoverage.ts` | `coverage.rs` |
| `javascriptSemanticResourceLimits.ts` | `resource_limits.rs` |
| `javascriptAstValues.ts` | `jsgraph/ast_values.rs` (já existia) |
| `javascriptSemanticDerivedAnalysis.ts` | `derived.rs` (esqueleto vazio) |

## API pública (`jsgraph::semantic`)

```rust
pub fn analyze_semantics(ast: &Ast) -> SemanticIr;                              // analyzeParsedJavaScriptSemantics
pub fn analyze_references(ast: &Ast, name: Option<&str>) -> Vec<SemanticReference>; // analyzeParsedJavaScriptReferences
pub fn classify_open_receivers(ast: &Ast) -> HashMap<u32, OpenReceiverFact>;    // chave: início da chamada
pub fn classify_electron_bindings(ast: &Ast) -> HashMap<u32, String>;           // chave: início do identificador raiz
pub struct SemanticAnalysisState<'a> { .. }                                     // estado de construção/avaliação
```

Para os coletores derivados (todos `pub`, nomes TS em snake_case): `state::{resolve_semantic_binding_state,
semantic_resolution_blocked, resolve_semantic_binding_from_scope, is_unshadowed_global, semantic_scope_id,
semantic_variable_scope}`, `values::{evaluate_semantic_binding, evaluate_semantic_expression,
evaluate_semantic_provenance, project_value}`, `call_resolution::{resolve_local_callables, parameter_bindings,
callable_by_id}`, `returned_references::create_semantic_returned_references`, `projection::{semantic_callable_id_for_node,
semantic_reads_before_write, semantic_identifier_role, semantic_reference_role}`, `property_paths::*`, `slots::*`,
`callable_results::semantic_callable_result_expressions`, `require_origin::semantic_require_origin`,
`ast_util::*`. Identidade de objeto JS vira índice de arena: `BindingIx`/`ScopeIx` (`state.bindings[ix]`,
`state.scopes[ix]`) e `N<'a>` (comparado por id) no lugar de `WeakMap<t.Node, ..>`.

## Decisões de porte

- **Ordem e desempates idênticos**: ordem de travessia `VISITOR_KEYS`, `Map`/`Set` com ordem de inserção onde ela
  vaza (pilhas e filas do coletor de mutações), ordenação por ponto de código (a ordem de bytes UTF-8 coincide),
  ids por offset UTF-16, `JSON.stringify` dos identificadores de efeito trocado por chaves estruturadas
  equivalentes (`Number` e `string` seguem distintos: `PathKey::Index` vs `PathKey::Name`).
- **Semântica JS que vaza para a saída**: `String(number)` (`util::js_number_to_string`), `Number(string)`
  (`primitives::js_string_to_number`, `StringToNumber` do ECMAScript), `-0` rejeitado pelo conjunto de primitivos,
  `typeof null === "object"` (por isso um spread sem chave vira `{excludedKeys: [..]}` em
  `objectReferencedValues`), `encodeURIComponent` nos ids de binding.
- **Pilha**: o REA recursa em alguns formatos sem limite (cadeias de alias, padrões profundos) onde o JS lançaria
  `RangeError`. As entradas públicas rodam numa thread com pilha de 256 MiB (`analysis::with_large_stack`); a
  travessia, `patternContains`, `assignedPatternIdentifiers` e o laço de membros são iterativos; as recursões
  limitadas por `SEMANTIC_EXPRESSION_DEPTH_LIMIT` (256) mantêm o mesmo teto.
- **Cooperação**: os geradores `*Steps` do REA (yield a cada 1024 nós) viram funções síncronas; os resultados são
  iguais à forma síncrona, como o REA documenta.

## Cobertura e prova

O teste compara `analyze_semantics` com o IR semântico do REA **exatamente** (mesmas chaves, mesma ordem dentro de
arrays), com os 17 campos derivados removidos dos dois lados (constante `DERIVED_FIELDS`, uma lista para esvaziar
quando os coletores derivados chegarem), mais os mapas dos dois classificadores. Corpus: inline (12 cenários +
11 gerados de estresse: limites de candidatos/bytes/profundidade, 2000 escritas, cadeias de alias, spreads),
870 trechos extraídos dos `*.test.ts` do REA (`scripts/gen_jsgraph_semantic_snippets.mjs` ->
`fixtures/jsgraph/semantic/snippets.json`), fixtures do repositório e do REA, e as fontes TypeScript do REA.

Per-run counts (files compared, AST-layer gaps) are printed by the test on every run; they were not recorded in this note. See [jsgraph.md](jsgraph.md) for the overview.

## Lacunas conhecidas (todas na camada AST, `jsgraph/ast`, fora do escopo desta camada)

O REA parseia com `errorRecovery: true`; o oxc é estrito. O teste mantém essas diferenças visíveis em vez de
ignorá-las (contadores `AstLayerGaps` impressos a cada execução, com teto para as não parseáveis):

1. **Erros recuperáveis do Babel que o `Ast::error_count` não conta** (~22 trechos): `with` em modo estrito,
   `import`/`export` fora do topo, identificador redeclarado, `Binding 'eval' in strict mode`, `Export 'x' is not
   defined`, vírgula inesperada. O Babel marca `parserPartial`; o porte vê `error_count == 0`. O teste reanalisa
   com `error_count = 1` quando o oráculo mostra a recuperação, então tudo o mais é comparado exatamente.
2. **Fontes que o Babel recupera e o oxc rejeita** (~14 trechos): buracos de argumento (`call(, "kept")`),
   `const` sem inicializador, ponto e vírgula ausente, `>` solto em JSX. Não há AST Rust para analisar.
3. **`await (x)` no topo de arquivo ambíguo** (1 trecho): o Babel (`sourceType: "unambiguous"`) lê `await` como
   identificador e chama; a AST Rust lê `await` de topo. Fora do corpus por `ambiguous_top_level_await`.

Nada na semântica em si ficou sem porte, exceto `flattenSemanticReturnValue` (projeção de campos de retorno para o
grafo de exportação), que pertence à camada de grafo e depende de tipos de `javascriptExportShapeComparisonSchemas`.

## Variáveis de ambiente

`TRACEWISE_JSGRAPH_STRIDE`, `TRACEWISE_JSGRAPH_CORPUS` (ver `tests/support/mod.rs`), `REA_SRC`,
`TRACEWISE_REQUIRE_ORACLE`.
