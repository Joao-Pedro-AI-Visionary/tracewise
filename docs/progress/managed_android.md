# Trilha managed_android (Fase 3, parte sem adb): 19 ferramentas

Branch `jp-managed_android`. Despacho em `crates/server/src/tracks/managed_android.rs`,
handlers em `crates/server/src/tracks/managed_android/`, crates novas `crates/managed`
(leitor PE/CLI ECMA-335 e fluxos .NET) e `crates/android` (ponte JADX, Apktool, JEB,
grafo de aplicacao Android). Nenhuma ferramenta responde mais `pending port`.

Oraculo: REA 0fa0b04 (MIT), servidor MCP stdio, mesmos argumentos. Cada teste compara o
`structuredContent` inteiro (e o envelope de erro) com o que o REA devolveu, valida o
resultado contra o `outputSchema` do catalogo e confere que o `evidence_id` recalculado
bate com o registro.

## Dependencias externas (nada instalado fora de /workspace/tools, tudo pinado)

| Dependencia | Versao | Origem | Uso |
|---|---|---|---|
| Temurin JDK | 21.0.5+11 | adoptium (sha256 3c654d98...) | compila e roda a ponte JADX; roda o Apktool |
| jadx-headless-mcp | 0.7.1 (sha256 6e5eacf5...) | release oficial | motor do JADX, JAR sem modificacao |
| ReaJadxBridge.java | REA 0fa0b04 (sha256 5a5a4e32...) | copiada para `crates/android/bridge/` | fronteira de metadados |
| Apktool | 2.9.3 (jar sha256 7956eb04...) | release oficial | `decode_android_resources` |
| Appium ApiDemos | 6.0.18 (sha256 a9eecf37...) | release oficial, Apache-2.0 | fixture APK |
| Node | 22.x | ja no ambiente | so o dublê do JEB (`fake-jeb.mjs`) |
| JEB | nao instalado, comercial | | so o dublê |

Crates novas (versoes pinadas pelo `Cargo.lock`): `sha1 0.10`, `zip 0.6`, `tempfile 3.14`,
`url 2.5`, `reqwest 0.12` (blocking), `jsonschema 0.58.6` (no server, para reproduzir as
mensagens de validacao do SDK). O parser ECMA-335 e proprio (porte linha a linha de
`src/dotnet`), sem `object`/`pelite`/`dotnetdll`: os resultados do REA dependem de
detalhes do leitor dele (orcamento de decodificacao, mensagens de `RangeError` do Node,
ordenacao UTF-16), entao uma crate generica nao daria paridade.

## Status por ferramenta

Estado real, por familia (todos os testes rodam neste ambiente; com `TRACEWISE_REQUIRE_ORACLE=1`,
que o `env.sh` define, a falta de uma dependencia externa falha o teste em vez de pular):

* .NET (7 ferramentas): **[Validado]** contra o REA real.
* JADX / Android estatico (6 ferramentas): **[Validado]** contra o REA real com o motor
  jadx-headless-mcp 0.7.1 e o APK ApiDemos. Fora desse APK e dos erros listados nao ha
  paridade medida.
* Apktool (2 ferramentas): **[Validado]** contra o REA real com o Apktool 2.9.3 e tres
  launchers falsos.
* JEB (4 ferramentas): **[Validado contra o dublê]**. O JEB real e comercial e nunca foi
  executado; a paridade e com o REA falando com `fake-jeb.mjs`, entao o comportamento
  com um motor JEB de verdade e **[Nao verificavel]** aqui.
* Cancelamento (limpeza de filhos e diretorios temporarios ao dropar o future):
  **[Validado]** em `managed_android_cancel_test` para Apktool, JADX e JEB.
* Robustez dos leitores .NET a bytes hostis: `proptest` (sem panic), ver abaixo.

| Ferramenta | Teste que prova | O que foi comparado |
|---|---|---|
| inspect_managed_artifact | `managed_android_inspect_test::managed_inspectors_match_rea_oracle_on_every_fixture` e `..._sessions_...` | 66 imagens PE (sinteticas do REA + 3 assemblies reais do NuGet) x 3 inspetores = 198 resultados, mais 19 passos de sessao (selecao de caminho, alvo nao-PE, validacao de entrada) e, em `special_targets_...`, `/dev/zero`, FIFO e PE esparso de 200 MiB (erro `not a regular file` e `resource_constraint`, rapidos e sem ler o alvo inteiro) |
| inspect_managed_members | idem | idem |
| inspect_managed_native_boundaries | idem | idem |
| compare_managed_members | `managed_android_workflows_test` | 95 cenarios (22 deixam unknowns residuais no registro) + 3 sequencias na mesma sessao (registro de unknowns, conflito de revisao) |
| verify_managed_native_boundaries | idem | idem (evidencias nativas `inspect_macho`/`analyze_function` fabricadas com `createEvidence` do REA) |
| import_managed_reconstruction | idem | idem |
| project_managed_application_graph | idem | idem |
| inspect_android_package | `managed_android_android_test::android_tools_match_rea_oracle_on_apidemos` | 59 chamadas em 15 cenarios no ApiDemos, 19 sucessos (o resto: classe/metodo inexistente, sobrecargas, APK invalido/truncado, configuracao ausente/ruim) |
| search_android_classes | idem | idem |
| inspect_android_class | idem | idem |
| inspect_android_method | idem | idem |
| trace_android_references | idem | idem |
| project_android_application_graph | `managed_android_android_test::android_application_graph_matches_rea_oracle` | 16 cenarios, 8 projecoes bem-sucedidas + 8 erros (inventario parcial, formato de no invalido, nao-APK, contagem/commitment errado, evidencia adulterada, operacao errada) sobre o inventario real do ApiDemos |
| inspect_apktool_client | `managed_android_providers_test::apktool_tools_match_rea_oracle` | 41 chamadas (19 sucessos): Apktool real 2.9.3, launcher ausente/relativo/sem versao, 3 launchers falsos |
| decode_android_resources | idem | idem (locales, `include_strings`, workspace gigante, manifesto truncado, APK invalido) |
| inspect_jeb_client | `managed_android_providers_test::jeb_tools_match_rea_oracle_with_test_double` | 39 cenarios, 136 chamadas (39 sucessos) contra o dublê (normal, SSE, GUI, sem versao, recusas, envelopes malformados, erros HTTP/JSON-RPC, validacao de entrada, endpoint invalido, sem servidor) |
| open_jeb_project | idem | idem |
| list_jeb_units | idem | idem |
| decompile_jeb_item | idem | idem |

Sem JEB instalado o REA e o port respondem `capability_unavailable` com o mesmo envelope
(cenarios "no server" e "default endpoint"), que e a paridade minima pedida.

## Campos normalizados ou ignorados nos testes

* `evidence_id`: nos testes de Android e JEB/Apktool e removido da comparacao porque o
  hash cobre `raw_result` com nomes de diretorio temporario e portas efemeras; e conferido
  por autoconsistencia (`Evidence::verify`). Nos testes .NET e comparado byte a byte.
* Nome do workspace privado (`/tmp/rea-android-XXXXXX/`, `/tmp/rea-apktool-XXXXXX`), a
  duracao `load_duration_ms` do motor JADX, a porta do dublê do JEB e o prefixo do
  checkout (`/workspace/wt/managed_android/fixtures/...` onde o oraculo rodou).
* Respostas do motor JADX embutidas como JSON em texto sao comparadas por conteudo: o
  `ReaJadxBridge` monta mapas com `Map.of`, cuja ordem de iteracao muda entre execucoes da JVM.
* Cenario "version blank" do Apktool (launcher `/bin/true`): o REA devolve a string de
  versao do coreutils da maquina; o teste normaliza `(GNU coreutils) <versao>` nos dois
  lados e compara o resto.
* Cenarios do JEB com endpoint invalido (`http://example.com`, credenciais, query,
  esquema, texto qualquer): o REA falha ao montar o provider e a chamada vira erro
  JSON-RPC -32603 "Internal server error"; o port devolve o mesmo erro JSON-RPC.

## Limites conhecidos

* O cliente MCP do JEB e HTTP/1.1 simples sobre `TcpStream` (`Connection: close`, corpo
  limitado a 16 MiB); nao ha TLS: uma URL
  `https` loopback responde `capability_unavailable` ("fetch failed"), o mesmo desfecho do
  REA com a porta fechada, mas diferente se houvesse um servidor TLS real.
* O Apktool e o JADX rodam como processos externos; sem Java/Apktool/JAR o port responde o
  mesmo `capability_unavailable` estruturado do REA (cenarios "no apktool", "missing command").
* Deadlines por chamada nao sao configuraveis (REA propaga `AbortSignal`); o port usa
  timeouts fixos (5 min por chamada MCP, 10 min no decode do Apktool, orcamentos do motor JADX).
  O cancelamento em si (drop do future) e tratado, ver "Cancelamento".
* Alvos: o resolvedor faz hash em streaming (blocos de 64 KiB) e so mantem em memoria os
  primeiros 128 MiB (PE gerenciado) ou 16 MiB (APK). PE acima de 128 MiB recebe
  `resource_constraint` como no REA. Um alvo Android acima de 16 MiB que nao seja um
  artefato reconhecido pelo nome/assinatura (por exemplo um executavel gigante) e
  classificado so pelo prefixo retido, o que pode divergir do REA na mensagem de erro.
* O Apktool e o JADX rodam como processos externos; sem Java/Apktool/JAR o port responde o
  mesmo `capability_unavailable` estruturado do REA (cenarios "no apktool", "missing command").

## Cancelamento

O `tokio::select!` de `handlers.rs` dropa o future da ferramenta. Cada chamada cria um
`CancelToken` (`crates/android/src/cancel.rs`) cujo guard vive no future: ao ser dropado
sem `disarm`, ele mata por `killpg(SIGKILL)` todo grupo de processos registrado (o
launcher do Apktool e a JVM do JADX sao lideres de grupo, entao um wrapper sem `exec`
nao deixa orfaos), e o lado bloqueante, que consulta o token no loop de espera, faz o
join dos leitores e remove o diretorio privado (`/tmp/rea-apktool-*`, `/tmp/rea-android-*`).
No JEB o token interrompe a leitura do socket (fatias de 50 ms). Chamadas que esperam o
lock da sessao tambem desistem ao serem canceladas. A sessao JADX retida morre em
`Drop` (grupo morto antes do diretorio) e por um unico thread de expiracao (60 s ocioso).

## Robustez

`crates/managed/tests/robustness.rs` (`proptest = 1.6.0`, dev-dependency) alimenta os tres
inspetores com bytes aleatorios, cabecalho MZ sintetico, mutacoes de bytes e truncamentos
dos 66 fixtures e todos os prefixos de `il_rich.dll`; falha se houver panic. Rodado
tambem com `PROPTEST_CASES=6000` (debug, com overflow checks) e `30000` (release): sem panic.

## Como regenerar o oraculo

Os geradores ficam em `fixtures/managed/*.py|mjs` e `fixtures/android/gen/` (cada um chama o
REA via `fixtures/android/gen/oracle.py`, que fala MCP stdio com
`$TRACEWISE_REA_SRC/scripts/rea.mjs`, padrao `/workspace/rea-map/src`, usando o node de
`$TRACEWISE_ORACLE_NODE`, padrao `/tmp/node-v22.20.0-linux-x64/bin/node`). Os scripts
gravam intermediarios em `/tmp/tracewise-oracle` e os `.mjs` importam do `dist/` do checkout
construido do REA (0fa0b04). Os caminhos `/workspace/wt/managed_android/...` ficam gravados
nas respostas do oraculo e os testes os normalizam.
Imagens PE sinteticas: `node fixtures/managed/gen.mjs <checkout do REA> fixtures/managed`
(precisa de Node >= 22.18). Assemblies reais: ver `fixtures/managed/PROVENANCE.txt`.
