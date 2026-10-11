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
