# Trilha engines (fases 5 e 5b): 57 ferramentas

Branch `jp-engines`. Dispatch em `crates/server/src/tracks/engines.rs`; lógica na crate nova `crates/engines`.

## Arquitetura
- `provider.rs`: traits `AnalysisProvider` / `AnalysisClient`, `Capability`, `AnalysisExecution` (porta de `AnalysisProvider.ts`).
- `session.rs`: registro de provedores e seleção (`auto`, `REA_ANALYSIS_PROVIDER`, `provider_id` do `open_binary`), `ActiveRoute` (capacidade, perfil, cache de snapshot de leituras imutáveis como o `AnalysisSnapshotCache` do REA, com a limitação "Loaded from a local REA analysis snapshot") e `EngineSession`.
- `ghidra/`: instalação (checks idênticos aos do REA), perfil, launcher (`LaunchSupport`, JVM direta), cliente (socket Unix com token, `ping` de identidade, fila serial, `shutdown`), pontes Java copiadas sem mudança de `bridge/ghidra/` (cabeçalho de atribuição MIT).
- `hopper/`: cliente da ponte `hopper_bridge.py` (copiada sem mudança), launcher nativo, perfil (`launcher-sha256`), busca regex supervisionada, mapeamento de offset de arquivo.
- `ida/`: ver seção própria.
- `workflows/`: binary_overview, call graph, xrefs por nome, batch_decompile (concorrente, para reproduzir os request ids), objc/swift, dispatch metadata, trace_native_values, inspect_native_api, trace_feature, trace_call_path, inspect_address_context, get_navigation_context.
- `derived/`: compare_functions e build_call_path (Evidence inline ou retida; sem provedor).
- `contract_input.rs`: validação e defaults de entrada derivados do catálogo (mensagens no estilo do SDK do REA).
- Ganchos em `crates/server/src/session.rs` (2 linhas): `open()` e `close()` chamam `tracks::engines::note_open/note_close`, que soltam o provedor vivo. O estado do motor fica numa tabela global chaveada pelo ledger da sessão.

## Evidência de teste (todos executados, nenhum `#[ignore]`)
| Teste | Alvo | Resultado |
|---|---|---|
| `engines_ghidra_direct_test` | 28 operações diretas do Ghidra 12.1.4 real, 59 chamadas vs oráculo, hash do alvo inalterado, projeto/JVM removidos no `close_binary` | ok |
| `engines_ghidra_workflows_test` | 14 workflows sobre o Ghidra, 38 chamadas vs oráculo | ok |
| `engines_ghidra_inventory_test` | fixture `inventory.c` do REA (-O2 -g): jump tables, fluxo, DWARF, regex que estoura a pilha Java; 49 chamadas | ok |
| `engines_hopper_test` | 36 operações Hopper + workflows + ferramentas 5b, 90 chamadas vs oráculo contra o Hopper falso | ok |
| `engines_derived_test` | compare_functions / build_call_path, 115 casos + 708 casos de diff | ok |
| `engines_selection_test` | seleção de provedor sem motor configurado (diagnósticos por candidato) | ok |
| `engines_cancel_test` | cancelar durante a partida do Ghidra não vaza processo; próxima chamada recupera | ok |
| testes unitários da crate `engines` | símbolos, parsers, entrada, projeção de erro | ok |

## Dependências externas
- Ghidra 12.1.4 (Apache-2.0) em `/workspace/tools/ghidra-12.1.4`, Temurin 21.0.5 em `/workspace/tools/temurin-21.0.5+11`. Os testes pulam, imprimindo o motivo, se faltarem (`TRACEWISE_GHIDRA_INSTALL_DIR`, `TRACEWISE_JAVA_HOME`).
- Hopper (comercial) só via falso: `fixtures/engines/hopper/` (launcher em shell script com digest determinístico, runtime Python que implementa o subconjunto da API de Hopper usado pela ponte, modelo gerado de `sample_elf` por `gen_model.py`). Requer `/usr/bin/python3`.

## Como o oráculo foi gerado
`fixtures/engines/oracle_session.py <calls.json> <out.json>` chama o REA original numa sessão. Ghidra: `GHIDRA_INSTALL_DIR` e `JAVA_HOME`. Hopper: `HOPPER_LAUNCHER_PATH` = launcher falso e `REA_ORACLE_NODE_ARGS='["--import","<force_darwin.mjs>"]'` (só o construtor do provedor Hopper enxerga "darwin", para o REA usar o launch direto em vez do adaptador de demo Linux).

## Campos ignorados
`subject.local_path` e caminhos do checkout (normalizados para `$ROOT`); `open_binary` (fase 0). Quando o teste roda fora do checkout que gerou o golden, `evidence_id` é descartado apenas nas respostas cujo conteúdo embute caminho (ex.: `address_to_file_offset`).

## Divergências e não portado
- `open_binary` (fase 0) não seleciona provedor: o erro de seleção (`provider_id` desconhecido ou indisponível) aparece na primeira ferramenta de motor, com o mesmo corpo do REA.
- Windows P0, DOS MZ/COM (verificação independente de load image), MIPS, extensões NativeAOT do Ghidra: alvo recusado com `unsupported`.
- Hopper: só launch nativo (macOS ou launcher compatível). O adaptador de demo Linux (Xvfb, `hopper-demo-x11.py`), leases entre sessões, FAT/FAT64 Mach-O (mapeamento de offset e imagem preparada) e `HOPPER_TARGET_PATH` na partida do servidor não foram portados. Regex do Hopper usa a crate `regex` (não ECMAScript: sem lookaround/backreference; mensagem de padrão inválido difere).
- Falha de partida do Hopper: o corpo agregado de `cleanup_incomplete` do REA (com diretório temporário aleatório) não é reproduzido; o Rust devolve `HopperStart`/`HopperProcess` simples.
- `binary_session` (fase 0) não mostra binding/candidatos de provedor.
- `inspect_native_dispatch_metadata` com Ghidra devolve `unreadable_output`, igual ao REA (inventário de nomes do Ghidra tem campo extra).
- Validação de saída do bridge é estrutural (nível superior), não o esquema zod completo; a entrada do contrato valida só o nível superior do JSON Schema.
