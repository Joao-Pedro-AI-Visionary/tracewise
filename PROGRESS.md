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

## 2026-10-11 07:44 — phase1b: bundle, execution, listeners (CLI: cursor:grok-4.7-high)
- testes ok: 43

## 2026-10-11 08:03 — phase1b: analyze_web_bundle, observe_web_execution, inspect_web_event_listeners (CLI: cursor:grok-4.7-high)
- testes ok: 43
