# Trilha `native_static` (Fase 4): progresso

Crate nova: `crates/native` (`tracewise-native`). Despacho: `crates/server/src/tracks/native_static.rs` e
`crates/server/src/tracks/native_static/`. Testes: `crates/server/tests/native_static_*_test.rs`,
`crates/native/tests/*`. Fixtures e geradores: `fixtures/native_static/`.

Legenda de status: **Validado** (executado, com evidência), **Não verificável** (sem oráculo ou sem
ambiente para provar paridade; o que foi provado está na coluna de prova).

Ambiente do oráculo: REA em `/workspace/rea-map/src` (Linux). Para `inspect_binary_layout` e
`inspect_recorded_crash` foi criado um venv pinado em `/workspace/tools/pwntools-4.15.0`
(pwntools 4.15.0, pyelftools 0.33, unicorn 2.1.2) e o REA rodou com `REA_PWNTOOLS_PYTHON`.

Verificações **manuais, não reproduzíveis a partir do repositório**: comparações com `rcodesign` 0.29.0
(`/workspace/tools/rcodesign`) e com LIEF 1.0.0 (`/workspace/tools/macho-oracle`) sobre binários Mach-O que existem
nesta máquina (prebuilds de `node-pty`, `bare-*`, `argon2`, caches do electron-builder; 57 arquivos, 25 com CDHash
comparável, 0 divergências na última rodada; antes, 17 arquivos no LIEF e 28 no `rcodesign` com o parser antigo).
Os scripts estão versionados (`fixtures/native_static/tools/lief_check.py`, `rcodesign_check.py`), mas os arquivos de
entrada não: não contam como prova de CI. O que é reproduzível e versionado: as fixtures assinadas com `rcodesign` em
`fixtures/native_static/codesign/` (valores esperados fixos nos testes) e os goldens Apple do REA.

Sobre a "visão `plutil`" do `inspect_plist`: o REA no Linux não tem `plutil`, então os testes **emulam** essa visão
com `plistlib` do Python (`plists/gen_plist_golden.py` converte cada plist para o JSON/XML que o `plutil` imprimiria e
repassa ao `NativeMacOSProvider` do REA). A paridade vale para essa emulação, não para a saída de um `plutil` real.

## Ferramentas

| Ferramenta | Status | Prova | Dependências (versão) |
| --- | --- | --- | --- |
| `trace_dylib_resolution` | Validado | `native_static_artifact_test::trace_dylib_resolution_matches_oracle`: 18 cenários, resultado idêntico ao oráculo REA (Linux) | só std + sha2 |
| `inspect_keyed_archive` | Validado | `...::inspect_keyed_archive_matches_oracle`: 25 cenários, inclui o golden `foundation.plist` capturado em macOS | roxmltree 0.20 |
| `decode_interface_builder` | Validado | `...::decode_interface_builder_matches_oracle`: 6 cenários (NIBArchive AppKit/UIKit, ibtool XML/binário, keyed, truncamento por limites) | roxmltree |
| `inspect_pe_resources` | Validado | `native_static_binary_test::inspect_pe_resources_matches_oracle`: 28 cenários PE32/PE32+ (árvore, duplicatas, ciclos, limites, truncamento) | std |
| `inspect_evm_interface` | Validado | `...::inspect_evm_interface_matches_oracle`: 27 cenários (hex/raw, metadados CBOR, EOF, ruído, erros) contra o REA com a engine WASM do evmole 0.9.3 | evmole 0.9.3 (crate Rust, sem WASM) |
| `inspect_binary_layout` | Validado | `...::inspect_binary_layout_matches_oracle` (55 cenários: 13 ELFs compilados + 42 variantes danificadas + modos de erro) e `..._matches_bridge_reference` (46 arquivos contra o adaptador `layout_impl.py` do REA sem o limite de 3 GiB) | iced-x86 1.21.0 |
| `inspect_recorded_crash` | Validado | `...::inspect_recorded_crash_matches_oracle`: 40 cenários com cores sintéticos (notas, PRSTATUS/SIGINFO, cobertura, erros) | std |
| `project_apple_application_graph` | Validado | `native_static_artifact_test::project_apple_application_graph_matches_oracle`: 17 cenários (app dir macOS/iOS, IPA, ZIP, orçamento de bridge parcial, evidência adulterada, mensagens de erro). DMG só em teste unitário (REA monta DMG com `hdiutil`) | std |
| `list_architectures` | Validado (estrutura) / Não verificável (texto exato do `lipo`) | `macho_tools::tests` (tabela de slices do golden `lipo-fat.txt`), `native_static_macho_test::list_architectures_*` e `macho_golden_test` (campo `architectures`) | std |
| `inspect_macho` | Validado | `crates/native/tests/macho_golden_test.rs`: Mach-O reconstruídos das capturas Apple `otool -l`/`dyld_info`/`nm` do REA; o texto `otool` impresso confere com a captura e o resultado confere com o REA original rodando sobre a captura. Além disso, verificação manual não reproduzível com LIEF em 17 binários Mach-O reais da máquina (segmentos, seções, dependências, UUID, imports e exports idênticos) | icu_collator 2 |
| `inspect_signature` | Validado (campos) / Não verificável (texto do requisito) | Fixtures versionadas assinadas por `rcodesign` (cert Developer ID autoassinado + carimbo Apple RFC 3161, entitlements, runtime, ad hoc, universal misto) em `native_static_macho_test`, mais testes unitários hostis em `sigparse` (super blob com contagem de 4 bilhões, offsets fora do blob, requisito de 1 milhão de `Not`, DER aninhado). Verificação manual não reproduzível com `rcodesign` em binários reais (ver acima) | `sigparse` (parser próprio) + cms 0.2.3, x509-cert 0.2.5, der 0.7.10, sha1 0.10.7 (RustCrypto, MIT/Apache-2.0). O `apple-codesign` (MPL-2.0) foi removido do build: restou só como ferramenta de geração das fixtures |
| `inspect_plist` | Validado (XML/binário) | `native_static_macho_test::inspect_plist_matches_rea_on_plutil_equivalent_input`: o REA original (`NativeMacOSProvider`) alimentado com a visão `plutil` **emulada com plistlib** vs a decodificação nativa, valores/bundle/limitações. Mais testes hostis: 4000 arrays XML/JSON aninhados, bplist 2^50 e bplist autorreferente | roxmltree |
| `demangle_swift` | Validado (golden) | `demangle::tests` + `native_static_macho_test::demangle_swift_*` com o golden `demangle.txt` (`Test.foo() -> ()`) | symbolic-demangle 12.18.3 (demangler C++ do Swift embutido; exige compilador C++ no build) |
| `inspect_asset_catalog` | Validado (descoberta, hash, paginação, junção de chaves do IB, erros do REA) / **Não verificável** (`records`: campos por rendition vs `assetutil`) | `native_static_assets_test` (11 cenários do REA original com um `assetutil` **injetado que devolve os registros do próprio tracewise**: por isso `records` não entra na afirmação de paridade, seria tautológico), `car_real_catalogs` (a contagem de renditions do CARHEADER, escrita pela Apple, bate com os registros de 7 catálogos versionados em `fixtures/native_static/assets/vendor`: 6 do acextract, CoreUI 366/374, e 1 do AssetsParser, CoreUI 868; licenças MIT/Apache-2.0 no README) | BOM/CAR decodificado em Rust (formato de skytoup/car-parser, MIT) |

## Campos ignorados nas comparações com o oráculo (e por quê)

- Todos: `evidence_id` de topo (hash inclui caminho absoluto); prefixo do checkout normalizado para `$ROOT`.
- `inspect_keyed_archive`: a remediação "inspect_plist requires a macOS host" do REA/Linux é trocada pela redação
  do REA/macOS, porque `inspect_plist` agora existe.
- `inspect_evm_interface`: `limitations` (limites do processo-worker do REA vs execução em processo aqui).
- `inspect_binary_layout`: `provider`, `diagnostics`, `linkage.plt` e os ids derivados (o REA sob RLIMIT_AS de
  3 GiB não completa a emulação de PLT do pwntools; o `linkage.plt` e o stderr vêm do adaptador sem limite:
  `bridge_reference`), e a frase de limites do sandbox Python.
- `inspect_recorded_crash`: `provider` e as duas frases de limitação que citam o sandbox Python / o modo em processo.
- `inspect_macho`: `endian` (o REA lê `file -b`, que no macOS não imprime endianness), `provenance`, `limitations`,
  texto de `time stamp` (otool usa o fuso do host; aqui UTC).
- `project_apple_application_graph`: a entrada é o Evidence `inspect_artifact` do ORÁCULO (campo `only` em
  `scenarios.json`), para isolar a ferramenta do inventário da Fase 2.
- `inspect_asset_catalog`: as três frases de limitação que citam o decodificador.

## Desvios deliberados em relação ao REA (todos documentados na saída da ferramenta)

- `provenance` das ferramentas nativas descreve uma execução em processo (`tool: tracewise-native`), com o SHA-256
  do executável do servidor, em vez de invocações `lipo`/`otool`/`codesign`.
- `inspect_macho`: `file_type` e `flags` seguem o `otool -h` numérico do REA (`"2"`, `["0x00200085"]`);
  `platform`/`tool` do LC_BUILD_VERSION idem (`"1"`, `"3"`). Quatro limitações textuais citam as fontes nativas.
- `inspect_plist`: aceita plist JSON (`format: "json"`); plist OpenStep e inteiros de 128 bits em plist binário
  não são suportados. A frase sobre `plutil` foi trocada por uma que descreve a representação tipada.
- `inspect_signature`: a lista de authorities contém só os certificados embutidos no CMS (sem Apple Root CA se não
  embutido); o requisito designado usa a sintaxe do `Requirement::Dumper` da Apple reconstruída de memória/
  documentação (`and`/`or`/`!` com níveis, valores simples sem aspas) e não foi comparada com `codesign -d -r-` real
  (não há macOS): **Não verificável** o texto exato para requisitos fora do trivial. Assinatura ad hoc sem
  requisito embutido gera `cdhash H"..."`; assinatura com certificado e sem requisito não gera o requisito implícito.
- `inspect_asset_catalog`: decodifica o `.car` em Rust (cabeçalho, KEYFORMAT, FACETKEYS, RENDITIONS, CSI) com os nomes
  de campo do `assetutil`, mas só um subconjunto (sem `SHA1Digest`, `Template Mode`, slices etc.).
- `inspect_binary_layout`: o PLT é descoberto com um interpretador sobre iced-x86 (não Unicorn); a paridade foi
  provada nas 13 amostras compiladas e nos pontos da referência, mas stubs atípicos podem divergir
  (frase de limitação na saída).

## Achados fora da trilha (resolvidos na trilha integration)

- `open_binary` sobre diretório `.app` agora resolve o executável pelo `Info.plist`, como o REA
  (`open_binary_bundle_test`, 17 alvos contra o oráculo).
- `inspect_artifact` passou a classificar dylib/`.so`/`.node` Mach-O como `mach-o` e a hashear diretórios
  aninhados depois dos filhos; os cenários `apple_*` também rodam com o Evidence do nosso `inspect_artifact`
  (`project_apple_application_graph_from_own_inventory_matches_oracle`, 68 chamadas).

## Comandos de verificação

```
cargo test -p tracewise-native
cargo test -p tracewise-server --test native_static_artifact_test --test native_static_binary_test \
  --test native_static_macho_test --test native_static_assets_test
```

Execução: os testes não pulam por falta de oráculo (os resultados do REA estão versionados em
`fixtures/native_static/oracle/`). `car_real_catalogs` aceita `TRACEWISE_CAR_CATALOGS` com catálogos extras e, com
`TRACEWISE_REQUIRE_ORACLE=1`, falha se o diretório indicado não puder ser lido. Os geradores aceitam `REA_NODE`,
`REA_ROOT` e `REA_PWNTOOLS_PYTHON`.

Regeneração (não roda no CI): `fixtures/native_static/gen_*.py`, `gen_oracle.py`, `macho_golden/gen_macho_golden.py`,
`plists/gen_plist_golden.py`, `codesign/gen_codesign_fixtures.py`, `assets/gen_assets.py`.
