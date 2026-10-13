# Trilha adb_runtime — progresso

Escopo: 24 ferramentas adb (Fase 3) e 6 de runtime/firmware (Fase 6). Crate nova:
`crates/device` (`tracewise-device`). Despacho: `crates/server/src/tracks/adb.rs` e
`crates/server/src/tracks/native_runtime.rs`. Nenhuma ferramenta responde mais
`pending port`.

Estados: **Validado** (executado neste ambiente contra o oráculo REA, sem campo
ignorado), **Parcial** (validado só em parte, o resto descrito), **Não verificável**
(depende de algo que não existe aqui).

## Método de prova

Todo teste de paridade roda o REA original (`fixtures/rea_oracle.py`, node 22) e a
porta Rust com o mesmo ambiente, os mesmos argumentos e os mesmos caminhos
absolutos, e compara o resultado MCP inteiro. Nada de golden gravado.

| Alvo | Dublê/ferramenta usada | Observação |
|---|---|---|
| adb (24) | `fixtures/adb/fake-adb`, script que imita o adb 34, escolhido por `REA_ADB_PATH` (a variável do REA) | Não há adb real nem dispositivo aqui. Além do resultado, compara-se o argv de cada chamada ao adb (`argv.log`), os efeitos no sandbox e o banco de pacotes do fake. |
| firmware (2) | Binwalk 3.1.0 e Unblob 26.6.4 **reais**, pinados em `/workspace/tools/` | Binwalk: `cargo install binwalk --version =3.1.0 --locked` com `RUST_FONTCONFIG_DLOPEN=on` (o `plotters` pede fontconfig só para gráficos de entropia). Unblob: venv com `pip install unblob==26.6.4`. Mais `fake-binwalk`/`fake-unblob` para provocar falhas de relatório e de processo. |
| nativas macOS (3) | oráculo no Linux (`unsupported_host`) | O caminho real do macOS não foi portado. |
| trace_native_ui_action | workflow compilado do REA (`dist/.../EnhancedTools.js`) com porta roteirizada | O fluxo precisa de engine (Ghidra/Hopper) e do decoder de Interface Builder, que não existem aqui. |

## Por ferramenta

### adb (24): Validado contra o oráculo com adb falso
`inspect_adb_client`, `list_adb_devices`, `inspect_adb_device`, `list_adb_packages`,
`pull_adb_package`, `read_adb_logcat`, `inspect_adb_package`, `pull_adb_file`,
`push_adb_file`, `capture_adb_screen`, `list_adb_processes`, `list_adb_directory`,
`list_adb_features`, `list_adb_services`, `inspect_adb_display`, `inspect_adb_window`,
`read_adb_setting`, `collect_adb_bugreport`, `resolve_adb_packages`,
`install_adb_package`, `uninstall_adb_package`, `start_adb_app`,
`start_adb_activity`, `stop_adb_app`.

- Prova: `crates/server/tests/adb_tools_test.rs` (6 testes): inspeção (36 casos),
  aquisição (18, inclui rollback com limpeza incompleta), mutação (30, push/install/
  uninstall/start/stop), seleção do binário e erros do cliente (8), admissão
  de argumentos em lote (51 entradas inválidas, mensagem a mensagem) e roteamento.
- Campos ignorados: nenhum. `evidence_id` é igual porque o binário, a versão e os
  caminhos são os mesmos nas duas execuções.
- As validações e "confirmações" do REA foram portadas literalmente: push recusa
  destino existente sem `overwrite` e compara o `sha256sum` do dispositivo; install
  e uninstall decidem pelo texto (`Failure [...]` com exit 0); extras tipados do
  `start_adb_activity` são checados antes de qualquer chamada; o argv só cita o que
  tem caracteres especiais.
- Cancelamento MCP (o `tokio::select!` de `handlers.rs` dropa o future): o filho adb morre
  junto (`kill_on_drop`) e um diretório de pacote deixado pela metade entra no registro de
  limpeza (guard RAII) e é removido pela chamada adb seguinte. Prova:
  `cancelled_pull_package_leaves_no_process_and_cleans_up_on_next_call`. Diferença para o
  REA: ele devolve `partial_observation` com o que já foi baixado; aqui o cancelamento só limpa.
- Não coberto: prazos de 30–600 s e a escalada SIGTERM→SIGKILL (5 s) nas ferramentas adb.
- Dependência externa: nenhuma além do `adb` do usuário em produção.

### Fase 6

| Ferramenta | Estado | Prova |
|---|---|---|
| `inspect_firmware_regions` | Validado (Binwalk 3.1.0 real) | `firmware_tools_test.rs` |
| `extract_firmware` | Validado (Unblob 26.6.4 real) | `firmware_tools_test.rs` |
| `observe_native_ui` | Parcial | `native_runtime_test.rs`: admissão, ausência de alvo e `unsupported_host` idênticos ao REA no Linux (80 chamadas). Caminho macOS **Não verificável** (não portado). |
| `capture_native_ui_scenario` | Parcial | idem |
| `observe_native_calls` | Parcial | idem |
| `trace_native_ui_action` | Parcial | Fluxo inteiro validado contra o workflow compilado do REA (46 cenários, 34 traces e 12 erros, incluindo os 13 do teste do próprio REA) em `crates/device/tests/ui_trace_parity.rs`. Com o Mach-O aberto o servidor responde o mesmo `provider_unavailable` (`details.operation = list_names`, candidatos ghidra/hopper/ida) que o REA, comparado ao oráculo em `native_runtime_test.rs` (o `pending port` das trilhas irmãs é mapeado para essa resposta apenas no estado "nenhum engine configurado"; com Java, Ghidra, IDA ou Hopper presentes cai em erro de protocolo em vez de inventar diagnósticos). Admissão, "sem alvo" e a passagem por `call_sibling_via` (erro projetado, texto puro, sucesso, `pending port`) têm teste. A integração com decoder e engine reais é **Não verificável** até as trilhas `native_static` e `engines` entrarem. |

Firmware: 5 testes: ferramentas reais (16 casos), seleção de ferramenta (20), falhas do Binwalk (20), falhas do Unblob (39) e admissão (17 entradas em lote). Comparado sem ignorar campo, exceto o que é aleatório
por execução: sufixo do diretório privado `/tmp/rea-firmware-XXXXXX`, UUIDs do Binwalk,
a parte `pid` dos blob ids do Unblob e `evidence_id` (que faz hash desses valores).
Compara-se também a árvore publicada (modos 0700/0600, digests, links), a ausência de
diretórios privados e de processos órfãos. Mutação do código mostrou que o teste falha
quando uma string muda.

Portado em Rust: resolução de `REA_*_COMMAND` e `prlimit`, snapshot privado (com
intervalo), admissão da versão (verificada/compatível/recusada), execução sob
`prlimit` em grupo de processos próprio com token de execução e limpeza verificada
por token, normalização dos dois relatórios, inventário de staging com ordenação ICU
(`localeCompare`, verificada contra o Node), publicação em árvore exclusiva com
leitura de volta e rollback.

Cancelamento: guards RAII matam o grupo de processos (com o token já validado) e removem o
root privado `/tmp/rea-firmware-XXXXXX` no Drop, e só então liberam a fila do provedor.
Prova: `cancelled_requests_leave_no_process_or_private_root` (inspect com fake-binwalk lento e
extract com fake-unblob lento: nenhum processo do grupo, nenhum root, nenhum diretório de
saída, fila livre). Publicação: `Tree::rollback` agora porta `removeOwnedTree` (só entradas
criadas aqui, verificadas por identidade, diretórios vazios) e `#assertLineage`/
`throwIfDestinationCaseCollision`. Em ext4 a colisão de caixa não é alcançável; ela tem só
teste unitário da mensagem. Fora: a verificação de identidade ao desfazer um `create`
falho (o REA confere `pathHasIdentity` antes do `rmdir`; aqui é `remove_dir` de um diretório vazio).

Não portado: o registro de limpeza retida entre chamadas (`#pendingCleanup`) do
provedor de firmware e a observação parcial no cancelamento. O prazo de 120 s é coberto por
teste unitário do runner com prazo curto, não ponta a ponta.

Dependências externas e versões: Binwalk 3.1.0, Unblob 26.6.4 (venv Python 3.12),
util-linux `prlimit` do sistema, `7z`, `unsquashfs` e `zstd` do sistema (extratores do
Unblob). REA em `/workspace/rea-map/src` (commit 0fa0b04).

## Arquivos fora da trilha que foram tocados

- `Cargo.toml` (membro `crates/device`), `Cargo.lock`.
- `crates/server/Cargo.toml`: dependência `tracewise-device` e dev-dependency `regex`.
- Nenhum arquivo de `handlers.rs`, `contracts/*`, `PROGRESS.md`, `README.md` ou de outra trilha.

## Suíte completa

`cargo test --workspace --no-fail-fast`: tudo verde na trilha. Falham só
`capture_matches_rea_oracle_except_time_fields` (process_tools_test) e
`test_trace_web_module_imports` (web_scripts_tools_test), as duas pré-existentes e fora da trilha.
Limitação conhecida: a crate `device` usa APIs Unix (`libc`, `MetadataExt`); sem porte para Windows.

## Skips e oráculo

Os testes que precisam do REA ou de uma ferramenta externa usam um único helper
(`tracewise_device::testing::require_or_skip`): com `TRACEWISE_REQUIRE_ORACLE=1` (o `env.sh`
seta) a falta do oráculo dá panic dizendo o que falta; sem a env, o teste imprime `SKIP` e
passa. Prova: `testing::tests::missing_prerequisites_skip_or_panic_by_environment`.
