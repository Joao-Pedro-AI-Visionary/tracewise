# Trilha electron (fase 2): `capture_electron_scenario` ativo

Branch `jp-electron`. A pendência da fase 2 era o modo ativo: a ferramenta validava a entrada e devolvia o erro "provider unavailable" do REA. Agora lança um Electron real, controla por CDP e devolve a Evidence do REA.

## Estado por ferramenta

| Ferramenta | Estado | Prova |
|---|---|---|
| `capture_electron_scenario` (ativo) | [Validado] com Electron 44.7.0 real | `electron_active_test`, `electron_active_mcp_test`, `electron_active_cancel_test`, `crates/cli/tests/electron_shutdown_test` |
| `capture_electron_scenario` (sem Electron configurado) | [Validado] erro idêntico ao do REA | `electron_tools_test::capture_electron_scenario_errors_match_rea` (não alterado) |
| `list_electron_targets`, `inspect_electron_page` | sem mudança (já validadas na fase 2) | `electron_tools_test` |

## Arquitetura

- `crates/web/src/electron_active/` (nova, dentro da crate `web` por causa do cliente CDP):
  - `process.rs`: dono do processo. Diretório privado 0700 por execução (hook, perfil `--user-data-dir`, `TMPDIR`), líder em grupo de processos próprio, `PR_SET_PDEATHSIG`, `Drop` que mata o grupo e apaga o diretório, hook `atexit`, varredura de diretórios abandonados.
  - `driver.rs`: as duas conexões CDP e o mapeamento Playwright → CDP.
  - `mod.rs`: configuração, ações, projeção e Evidence (reaproveita `project_electron_active_capture` e `create_electron_active_evidence` que já existiam).
- `crates/web/hooks/electron-active-hook*.cjs`: hook do REA **sem mudança** (só cabeçalho de atribuição MIT), embutido no binário com `include_str!` e escrito no diretório privado a cada execução. O corpo é comparado byte a byte com o do REA por teste.
- Playwright **não** é usado: `_electron.launch` só faz (1) `--inspect=0 --remote-debugging-port=0`, (2) lê `Debugger listening on ws://` / `DevTools listening on ws://` do stderr, (3) fala CDP nesses dois WebSockets. O mapeamento está documentado no cabeçalho de `driver.rs`.

| Playwright (REA) | tracewise |
|---|---|
| `application.evaluate(fn)` | `Runtime.evaluate` no inspector do Node com `includeCommandLineAPI` (é como o próprio Playwright obtém `require('electron')`) |
| `application.windows()` | alvos `page` do endpoint DevTools, ordenados pelo id do `webContents` (`webContents.fromDevToolsTargetId`, o mesmo mapeamento de `browserWindow(page)`) |
| `locator(css).click({timeout:0})` | sonda de acionabilidade na página (único, visível, habilitado, rolado, estável em duas amostras, sem sobreposição) + `Input.dispatchMouseEvent` |
| `page.reload({timeout:0})` | `Page.reload` + `Page.loadEventFired` |
| `forcefullyCrashRenderer`, `app.emit(open-url / second-instance)` | mesmas expressões do REA, no inspector do Node |
| `readApplicationState` | uma expressão só no processo principal (janelas, métricas, versão, snapshot do hook), validada como os esquemas zod |

## Seleção e configuração

O REA constrói o provedor sempre e lança qualquer `executable_path`. Aqui só roda um executável que o operador configurou:

- `TRACEWISE_ELECTRON_EXECUTABLE`: caminhos absolutos separados por `:`. Sem ela, o erro é exatamente o do REA ("active Electron observation provider is not configured"). Com ela, um `executable_path` fora da lista devolve o mesmo código (`capability_unavailable`) com motivo próprio.
- `TRACEWISE_ELECTRON_RUNTIME_DIR`: pai dos diretórios privados (padrão: tmp do sistema).
- Ambiente do Electron: só `HOME LANG PATH USER DISPLAY WAYLAND_DISPLAY` (a lista do REA) mais `REA_PROCESS_RUN_ID`; `TMPDIR`/`TMP` apontam para o diretório privado.
- Electron instalado: `/workspace/tools/electron-44.7.0` (v44.7.0, a versão que a documentação do REA dá como verificada; SHA-256 `3ae7d5bd…555a` conferido contra o `SHASUMS256.txt` do release). Precisa de display: os testes sobem um Xvfb privado. `--headless` e `--ozone-platform=headless` **não** servem aqui (o primeiro ainda usa o X11 do WSLg e abre janela na tela do usuário; o segundo derruba o Electron com SIGSEGV ao criar `BrowserWindow`).

## Paridade com o oráculo REA

`fixtures/electron/gen_oracle.sh` roda o REA original (mesmo Electron, mesmo app, as seis ações do `verify:electron` do REA) e grava `oracle_capture_electron_scenario.json`.

**Achado: o REA não consegue concluir esta ferramenta no Linux.** Termina a cena e depois não verifica a limpeza: o Chromium reescreve a área argv/environ dos processos auxiliares (`setproctitle`), então `/proc/<pid>/environ` não tem `REA_PROCESS_RUN_ID` e o REA responde `cleanup_incomplete` ("process tree contains an unowned or PID-reused process" ou "owned Electron lineage was unavailable"), **deixando o Electron rodando** (o gerador mata os processos). O golden é a captura que o REA guarda em `details.partial_observation`, e o teste compara com ela, mais o corpo do erro `cleanup_incomplete`.

Comparado exatamente: `application` (menos `cleanup`), `actions` (menos `elapsed_ms`), `windows`, `processes.items` (multiconjunto tipo/nome/serviço), `ipc.events` (multiconjunto, todos os campos exceto `sequence`/`correlation_id`), `coverage`, `limitations`, contadores de `retention` que não dependem de tempo, e o multiconjunto dos eventos determinísticos da linha do tempo (`STABLE_EVENTS` no teste).

Ignorado, com o motivo (também no cabeçalho do teste):
- `application.cleanup`: REA diz `unverified` (acima); aqui `terminated-owned-process`, provado pelo grupo de processos.
- `elapsed_ms`, `sequence`, `correlation_id`, pids: tempo/processo.
- Eventos de foco, mouse, pintura, `ready-to-show`, listeners e o download do dicionário ortográfico (um perfil novo o dispara): dependem de gerenciador de janelas, pintura e tempo. Três execuções do oráculo e três do Rust concordaram em todas as assinaturas de linha do tempo menos quatro; `ready-to-show` só aparece sob Playwright, o download de dicionário só sob o perfil privado.
- `sender`/`frame` do IPC do clique: qual das duas janelas idênticas é a "janela 0" é uma corrida **dentro do REA** (a ordem de `windows()` é a ordem em que o DevTools anunciou as páginas; o golden gerado em momentos diferentes deu `webContents:1` e `webContents:2`). Aqui a ordem é determinística (id do `webContents` crescente, após 300 ms sem páginas novas).

Evidence (envelope): provedor, `predicate_type`, `authority`, `confidence`, `environment`, `scenario_sha256` (recomputado), primeira/última limitação, `parameters.args` verbatim (o REA não redige argumentos; validado no teste de lançamento). `structuredContent` valida contra o `outputSchema` do catálogo.

## Limpeza (cancelamento MCP e shutdown)

`tokio::select!` de `handlers.rs` cancela largando o future. Testes com Electron real:
- durante a partida, num clique que nunca resolve (o REA: "permanece pendente até o cancelamento") e numa espera longa: sem processo e sem diretório quando o `drop` retorna (`electron_active_cancel_test`);
- via `call_tool_local` com o mesmo `select!` (`electron_active_mcp_test`);
- o binário `tracewise mcp` de verdade: `notifications/cancelled` (o servidor segue respondendo), stdin fechado, SIGTERM (143, via `atexit`, já que o handler chama `process::exit` e não larga futures) e SIGKILL do servidor (o líder morre por `PR_SET_PDEATHSIG`; o diretório pequeno fica e é varrido pela próxima execução, coberto em `abandoned_run_directories_are_swept_by_the_next_run`).

## Divergências deliberadas do REA

- Perfil e `TMPDIR` privados, apagados com a execução (o REA usa `~/.config/Electron` e `/tmp`). Consequência: o Electron baixa o dicionário ortográfico a cada execução (eventos `spellcheck-dictionary-download-*` na linha do tempo). Qualquer rede do app continua sem sandbox, como o REA já avisa nas limitações.
- Propriedade por grupo de processos (o líder nasce com `setpgid`), não por token de ambiente. Processos que saíram do grupo só são sinalizados se o token ainda estiver legível; os demais vão para as limitações como o REA faz ("Ownership of unrelated process N could not be verified; it was left untouched").
- Se `app.quit()` não encerrar em 5 s, SIGTERM e depois SIGKILL no grupo; a execução continua válida se o grupo for verificado vazio (o REA vira `cleanup_failed`).
- Seletores só CSS; `text=`, `role=`, `>>` etc. falham a ação com mensagem explícita. Locators estritos: mais de um elemento falha a ação ("strict mode violation"); o texto não é o multilinha do Playwright.
- Cancelamento: sem `partial_observation` de cancelamento (o cliente MCP nunca recebe resposta de uma requisição cancelada).
- `window_index` de `click`/`renderer-reload`/`wait`/`target`: ordem por id do `webContents`. `renderer-crash` usa `BrowserWindow.getAllWindows()[i]`, como o REA (as duas ordens diferem no app de fixture e o REA tem o mesmo comportamento).
- A espera inicial das janelas é sem prazo (igual ao REA); a partida tem 60 s (`ElectronActiveConfig::startup_timeout`).

## Dependências externas

- Electron 44.7.0 em `/workspace/tools/electron-44.7.0` (`TRACEWISE_TEST_ELECTRON` troca o caminho).
- Xvfb (`-displayfd`; onde o diretório `/tmp/.X11-unix` é somente leitura, como no WSLg, cai para um número fixo servido pelo socket abstrato).
- Oráculo: REA em `/workspace/rea-map/src` (só para regenerar o golden e para o teste que compara o hook byte a byte; sem ele esse trecho pula, ou falha com `TRACEWISE_REQUIRE_ORACLE=1`).

## Incidente de ambiente (não é da trilha)

Durante a execução o disco `C:` do Windows ficou com 0 byte livre, o ext4 do WSL entrou em `emergency_ro`, o `cargo` morreu com SIGBUS e o WSL caiu duas vezes. Os `target/` das worktrees somam centenas de GB (engines 67 GB, native_static 61 GB, integration 38 GB, managed_android 32 GB, engines-ida 29 GB, adb_runtime 23 GB, engines-derived 13 GB); nada disso foi apagado. Nenhum dado desta trilha se perdeu.

## Demo "clone esta funcionalidade" (PORTING.md, fase 2)

Os testes que existiam **não** provavam o critério: `trace_application_feature` roda sobre `fixtures/js/app` (módulos ESM, não Electron) e `verify_reconstruction` sobre capturas de `node` (`reconstruction_app/original.js`). Teste novo, de ponta a ponta com Electron real: `crates/server/tests/electron_clone_e2e_test.rs` (app `fixtures/electron/invoice_app`, clone correto `invoice_clone`, clone errado `invoice_regression`):

1. `capture_electron_scenario` (Electron 44.7.0): clica em `#export` e observa o handler `invoice:export` (canal, direção, formas de argumento e resultado; o valor `9.75` não aparece na Evidence).
2. `capture_process_scenario` + `compare_process_captures`: original x clone (terminal igual) e original x regressão (`9.75` vs `9.8`).
3. `verify_reconstruction`: clone `pass`, regressão `fail`.
4. `build_reconstruction_obligation_ledger`: obrigação revisada `electron/ipc` ligada ao clone. A captura ativa do Electron é aceita como autoridade `runtime` do original (somem `missing-original-case`, `weak-original-case-authority`, `static-only`); sem ela voltam `missing-original-case`. O que fica aberto é só o lado da prova (`missing-verifier`, `missing-case`), que nenhuma ferramenta do catálogo produz (`verify_reconstruction_obligations` é interno do REA).

**Lacuna fora desta trilha, não escondida: `analyze_javascript_application` só reconstrói as duas aplicações fixture do REA** (`fixtures/js/app` e `app-v2`; `crates/js/src/application/artifact_graph.rs` devolve o corpo gravado do REA, indexado pelo digest do artefato, e recusa qualquer outro com "only implemented for the tracewise fixture apps"). Logo o passo "rastrear a feature até o código" (`trace_application_feature`) não pode apontar para um app Electron de verdade, e o critério "encontra a feature em um app Electron real" do PORTING.md **segue aberto** até existir um construtor real do grafo de aplicação (oxc). No teste, o passo de rastreio é substituído pela observação em tempo de execução (passo 1), que é o que o ledger consome.

> **Update (jsgraph track):** the recorded-answer builder described above was removed. `analyze_javascript_application` now runs the native pipeline (`crates/js/src/jsgraph/`, see [jsgraph.md](jsgraph.md)) on any application, and `trace_application_feature` is compared with the live REA MCP server on `fixtures/electron/invoice_app` and `readiness_app` (`crates/server/tests/jsgraph_mcp_parity_test.rs`). `electron_clone_e2e_test.rs` itself was not changed and still uses the runtime observation for the trace step; its header comment predates this change.

## Gate (resultado real)

- `cargo clippy -p tracewise-web -p tracewise-js -p tracewise-server -p tracewise --all-targets`: sem warning nos arquivos da trilha (o único warning restante, `tracks/mod.rs::pending` nunca usada, é pré-existente e de outra trilha).
- `cargo test -p tracewise-domain -p tracewise-contracts -p proc-supervisor -p tracewise-web -p tracewise-js -p tracewise-server -p tracewise --no-fail-fast` (com `source /workspace/tools/env.sh`, `TRACEWISE_REQUIRE_ORACLE=1`): **229 passaram, 0 falharam**, doc-tests incluídos; isso compila todos os alvos (testes) dessas 7 crates. Inclui os testes da trilha: `electron_active_test` (8), `electron_active_mcp_test` (3), `electron_active_cancel_test` (4), `electron_clone_e2e_test` (1), `crates/cli/tests/electron_shutdown_test` (4), unitários de `electron_active` (8) e `electron_tools_test`.
- **Não executado: `cargo build --workspace --all-targets` e `cargo test --workspace` nas 5 crates que a trilha não toca** (`device`, `managed`, `android`, `native`, `engines`; nenhuma depende de `web`/`js`). Duas tentativas de build do workspace inteiro encheram o disco `C:` do Windows e derrubaram o WSL (ver "Incidente de ambiente"); a segunda foi substituída pelo conjunto acima, depois de `cargo clean` do `target/` desta worktree (34 GB, saída de build minha). Os testes dessas crates que rodam via `tracewise-server` (engines, native, managed, android) passaram nesse conjunto.
