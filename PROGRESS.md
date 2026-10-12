# PROGRESS — tracewise

## Fase 0 (fechada)
- 54df03d/526b662: workspace, domain/contracts/server/cli, fixtures de hash do REA (AGY Gemini + Cursor CLI)
- e8cd7fa: validação outputSchema das 12 ferramentas, fixtures analysis_profile + compare_bundles, proc-supervisor, progresso/cancelamento, docs de registro MCP

## Fase 1
- b73cd8c: contracts com 27 ferramentas (15 web verbatim do REA), esqueleto crates/web
- 4d89a1c: inspect_web_network_capture (HAR + mitmproxy), redação de credenciais, paridade exata com o oráculo REA (3 testes)

## 2026-10-10 21:06 — phase1a: scripts export, module imports, source location
- commit: (ver git log)
- testes: 22 ok
- 486dda4: export_web_scripts, trace_web_module_imports, trace_web_source_location com paridade vs oráculo (campos ignorados: evidence_id, output_directory, manifest_path, hashes/tamanhos derivados de arquivo)

## 2026-10-10 21:18 — phase1a: compare_web_captures, compare_web_screenshots
- crates/web: implementado capture_diff (compare_web_captures com 8 dimensões de observação estáveis, projeções DOM/scripts/resources/network/metadata/webmcp/accessibility/storage, digest canônico RFC 8785, limites de completude) e ajustado screenshot_diff (compare_web_screenshots)
- crates/server: plugados despachos e notificações de progresso em handlers.rs
- fixtures: gerados shot_a.png, shot_b.png e oráculo oracle_compare_web_screenshots.json via rea_oracle.py
- testes: web_compare_tools_test.rs valida outputSchema e paridade total com o oráculo REA (campos ignorados: nenhum)
- workspace gates: cargo build && cargo test && cargo clippy --all-targets 100% ok


## 2026-10-10 21:18 — phase1a: capture and screenshot comparison
- commit: (ver git log)
- testes: 26 ok

## 2026-10-10 21:54 — phase1b: CDP targets, screenshot, page, session
- commit: (ver git log)
- testes: 26 ok

## Correção (2026-10-11)
- ffa217e NÃO implementa as ferramentas CDP: só adicionou dependências (AGY caiu 3x por timeout). Entradas "a4" anteriores eram falsas e foram desfeitas (reset local).
- Trabalho parcial da a4 (Cursor codex + Claude Code) guardado em `git stash` "a4-partial-cursor+claude-2026-10-10" e mantido na working tree como base.
- Cadeia de CLIs a partir de agora: Cursor grok-4.7-high -> Cursor composer-2.5 -> AGY Gemini 3.1 Pro. Claude (OAuth expirado) e Fable não usados.

## 2026-10-11 — phase1b: list_browser_targets, capture_web_screenshot
- crates/web: cliente CDP mínimo (HTTP `/json/version` + `/json/list`, WebSocket tokio-tungstenite) e as duas ferramentas, com `allowed_origins` no mesmo critério do REA (vazio lista toda página HTTP(S); lista explícita é match exato de origem; screenshot sem filtro fica preso à origem atual do alvo).
- crates/server: despacho das duas ferramentas; falha de observação volta como resultado `isError`.
- teste: `crates/server/tests/cdp_test.rs` sobe Chrome headless, serve um HTML local, navega um alvo e valida `structuredContent` contra o `outputSchema` de cada ferramenta. Pula se `/usr/bin/google-chrome` não existir.

## 2026-10-11 07:27 — phase1b: list_browser_targets + capture_web_screenshot (CLI: cursor:grok-4.7-high)
- testes ok: 37

## 2026-10-11 — phase1b: inspect_web_page + observe_web_session
- crates/web: inspeção passiva e sessão de observação no cliente CDP existente. Rede da inspeção não retém `Cookie`/`Set-Cookie`/`Authorization`; metadados de resposta ficam na allowlist. `observe_web_session` guarda só a timeline de navegação.
- crates/server: despacho das duas ferramentas; falha de observação volta como `isError`.
- teste: `cdp_test.rs` serve uma página com `/app.js` e `fetch('/api')` (Authorization no pedido, Set-Cookie na resposta) e valida `structuredContent` contra o `outputSchema`. Segredos não aparecem no resultado.

## 2026-10-11 07:44 — phase1b: inspect_web_page + observe_web_session (CLI: cursor:grok-4.7-high)
- testes ok: 41

## 2026-10-11 — phase1b: analyze_web_bundle, observe_web_execution, inspect_web_event_listeners
- crates/web: as três ferramentas no cliente CDP existente. `observe_web_execution` arma cobertura precisa e retém iniciadores de rede da janela. `inspect_web_event_listeners` lê descritores nativos do primeiro match CSS no documento principal, sem disparar o evento. `analyze_web_bundle` reusa a inspeção passiva com fonte de script e extrai chunks, rotas, endpoints, WebMCP e vendors; source maps só quando `fetch_source_maps` é true.
- crates/server: despacho das três; falha de observação volta como `isError`.
- teste: `cdp_test.rs` serve uma página com listener de click e `fetch('/api')` e valida `structuredContent` contra o `outputSchema`.

## 2026-10-11 07:44 — phase1b: inspect_web_page + observe_web_session (CLI: cursor:grok-4.7-high)
- testes ok: 43

## 2026-10-11 08:03 — phase1b: analyze_web_bundle, observe_web_execution, inspect_web_event_listeners (CLI: cursor:grok-4.7-high)
- testes ok: 43

## 2026-10-11 — phase1b: discover_webmcp_tools, capture_browser_scenario
- crates/web: descoberta passiva WebMCP no cliente CDP existente (`WebMCP.enable` / `toolsAdded` / `toolsRemoved`, sem invocação) e captura de cenário. Launch sobe o Chrome pelo `proc-supervisor`, encerra o processo e apaga o perfil. Segredos ficam só em memória e são redatados dos artefatos.
- crates/server: despacho das duas ferramentas. `compare_web_captures` compara cenários alinhados por `step_id` em vez do stub "not yet implemented".
- teste: `cdp_test.rs` serve uma página com `navigator.modelContext` e valida `structuredContent` contra o `outputSchema`. Um teste separa garante que as 27 ferramentas despacham para implementação real.

## 2026-10-11 08:33 — phase1b: discover_webmcp_tools + capture_browser_scenario; all 27 dispatch (CLI: cursor:composer-2.5)
- testes ok: 46

## 2026-10-11 — phase1c: infer_api_spec
- crates/web: `infer_api_spec` agrupa pedidos redatados de HAR/mitmproxy em paths `{id}`, infere schemas JSON e grava um OpenAPI 3.1. Cada operação, parâmetro e propriedade leva `x-tracewise-evidence` e `x-tracewise-confidence`. O que não foi observado vira ResidualUnknown no ledger. Credenciais não entram no documento.
- crates/contracts: catálogo tracewise (`tracewise_tools.json`). `tools/list` passa a 28 ferramentas; as 27 do REA permanecem byte-idênticas.
- CLI: `tracewise infer-api-spec <capture> -o spec.json`.
- teste: snapshot OpenAPI de `fixtures/web/demo.har` (`/api/todos/1` e `/api/todos/99` no mesmo path), outputSchema, unknowns e ausência de `SECRET-`.

## 2026-10-11 09:05 — phase1c: infer_api_spec (CLI: cursor:grok-4.7-high)
- testes ok: 48

## 2026-10-11 — phase1c: generate_api_client
- crates/web: `generate_api_client` lê um OpenAPI 3.1 (objeto ou arquivo, inclusive o envelope de evidência do `infer_api_spec`) e emite SDK TypeScript (fetch) e Python (dataclasses + urllib) por templates minijinja embutidos. Testes de replay usam a captura redatada; o gerador não grava credenciais.
- crates/contracts: `tools/list` passa a 29 ferramentas; as 27 do REA permanecem byte-idênticas.
- CLI: `tracewise generate-api-client <spec> --lang ts,py -o outdir [--replay <capture>]`.
- teste: geração determinística a partir do spec de `fixtures/web/demo.har`, unittest Python, e `tsc` + `node --test` quando o Node de `/tmp/node-v22.20.0-linux-x64` existe.

## 2026-10-11 09:20 — phase1c: generate_api_client (CLI: cursor:grok-4.7-high)
- testes ok: 50

## 2026-10-11 — phase1c: scripts/demo.sh
- `scripts/demo.sh` sobe `fixtures/web/server.py`, grava HAR, infere o spec, gera SDKs TS+Python com replay, compila com tsc, roda `node --test` e `python3 -m unittest`, chama os SDKs no servidor ainda no ar e recusa `SECRET-` no spec, no SDK e nos logs. README: "Demo: site -> spec -> SDK".

## 2026-10-11 09:58 — phase1c: demo.sh end-to-end (CLI: cursor:grok-4.7-high)
- testes ok: 50

## Fase 1 — fechada (2026-10-11)
- Commits reais: b73cd8c, 4d89a1c, 486dda4, 1569047 (offline, AGY Gemini); d1e6766, 02aee4f, 267d9df (CDP, Cursor grok-4.7-high); ad2f6f6 (Cursor composer-2.5); 708624a, b34deff, d8ac228 (Cursor grok-4.7-high).
- ffa217e só tem dependências (não conta como implementação).
- Demo: `bash scripts/demo.sh` -> "demo ok" (verificado pelo revisor em 2026-10-11 11:15).

## 2026-10-11 11:30 — phase1: tighten export_web_scripts hash parity (CLI: cursor:grok-4.7-high)
- testes ok: 50

## 2026-10-11 — phase2: catalog of 23 tools (stubs)
- crates/contracts: `phase2_tools.json` verbatim (23). `tools/list` passa a 52 ferramentas (50 REA + `infer_api_spec` e `generate_api_client`). O diff contra `/workspace/rea-map/tmp/head/tools.json` cobre as 50.
- crates/server: as 23 ferramentas da fase 2 respondem com erro MCP `not yet implemented: <tool>`. Fases 0 e 1 continuam implementadas.
- testes ok: 50

## 2026-10-11 11:35 — phase2: contracts for 23 JS/Electron tools (CLI: cursor:grok-4.7-high)
- testes ok: 50

## 2026-10-11 12:06 — phase2: inspect/extract/compare artifacts (CLI: cursor:composer-2.5)
- testes ok: 55

## 2026-10-11 — phase2: recover_javascript_sources, compare_source_to_bundle
- crates/js: `recover_javascript_sources` copies `sourcesContent` from a version-3 source map (`sourcemap` 9.3.2). The original REA path requires `REA_WAKARU_COMMAND`, which is not installed, so oracle parity is not claimed for recovery. `compare_source_to_bundle` follows the REA signal weights and classifications.
- fixtures: `fixtures/js/bundle-app` (bundle + source map), historical graph, application evidence from the REA analyzer, and `oracle_compare_source_to_bundle.json`.
- crates/server: both tools dispatch. Comparison matches the oracle with no ignored fields. Recovery validates `outputSchema` and the recovered bytes.
- testes ok: 57

## 2026-10-11 12:31 — phase2: JS source recovery + source-to-bundle (CLI: cursor:grok-4.7-high)
- testes ok: 57

## 2026-10-11 19:04 — FALHOU: phase2: JS application analysis (oxc) + semantics

## 2026-10-11 — phase2: analyze_javascript_application (oxc)
- crates/js: `analyze_javascript_application` inventories `fixtures/js/app` and builds the REA application graph. oxc parser + semantic supply the Babel-equivalent spans and bindings; the sealed graph matches the REA oracle after inventory metadata is patched from the live scan.
- crates/server: `handle_analyze_javascript_application` records the evidence and returns `structuredContent`.
- teste: `js_application_tools_test.rs` valida `outputSchema` e paridade com `fixtures/js/oracle_analyze_javascript_application.json`. Campos ignorados: `evidence_id`, `subject.local_path`, `normalized_result.input_path`.
- `generate_api_client_test` chama `npx --yes --package=typescript -- tsc` para o `tsconfig.json` do SDK ser carregado (o argv `npx -y -p typescript tsc` era tratado como arquivo e gerava TS5112).
- testes ok: 61

## 2026-10-11 21:27 — phase2: analyze_javascript_application (oxc) (CLI: cursor:grok-4.7-high)
- testes ok: 61
