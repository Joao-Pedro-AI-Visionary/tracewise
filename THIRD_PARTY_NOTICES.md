# Third Party Notices

Partes deste software derivam de REA (https://github.com/morluto/rea), Copyright (c) 2026 morluto, licenciado sob a licença MIT.

---

## REA (morluto/rea) License

MIT License

Copyright (c) 2026 morluto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Attribution Details

Conforme ATTRIBUTION.md:
- Os conceitos de modelo de Evidence com identificadores semânticos `ev_<sha256>`, ResidualUnknown com encadeamento de revisões, EvidenceBundle e comparação de bundles derivam do design do REA.
- As definições e esquemas das 12 ferramentas da Fase 0 (Foundation) foram portadas para interoperabilidade direta com o ecossistema e ferramentas existentes do REA.

---

## Trilha engines (derivados de REA)

Os arquivos abaixo derivam de morluto/rea (MIT, Copyright (c) 2026 morluto), cujo texto de licença está acima:
- crates/engines/bridge/ghidra/ReaGhidraBridge.java, ReaGhidraExtensions.java, ReaGhidraNoReturnFix.java (copiados sem mudança de comportamento).
- crates/engines/bridge/hopper_bridge.py (copiado sem mudança de comportamento).
- fixtures/engines/inventory.c (de tests/conformance/ghidra/inventory.c).
Ghidra (Apache-2.0) e o JDK são fornecidos pelo usuário e não são redistribuídos.

### Módulos Rust portados do TypeScript do REA (obra derivada, MIT)

Reescritas em Rust do código TypeScript de morluto/rea (MIT, Copyright (c) 2026 morluto), mantendo
estrutura, mensagens, limitações e comportamento; a licença MIT acima se aplica a eles:
- Provedor Ghidra: `crates/engines/src/ghidra/` (GhidraClient, GhidraLauncher, GhidraProvider, GhidraProviderClient, GhidraProviderCapabilities, GhidraAnalysisProfile, GhidraInstallation, GhidraInventoryValues, GhidraFunctionValues).
- Provedor Hopper: `crates/engines/src/hopper/` (HopperClient, HopperRequestQueue, BridgeLauncher, HopperProvider, HopperProviderCapabilities, HopperAnalysisProfile, HopperRegexSearch, HopperFileOffset, parseConfig).
- Provedor IDA: `crates/engines/src/ida/` (IdaProvider, IdaConfiguration, IdaMcpConnection, IdaOperationRunner, IdaProtocolValues, IdaProviderCapabilities, IdaSessionClient, IdaWorkspace, IdaInput, IdaDoctor e os testes de conformidade correspondentes).
- Abstração e seleção: `crates/engines/src/provider.rs`, `session.rs`, `error.rs` (AnalysisProvider, AnalysisProviderRegistry, SessionProviderRouter, BinarySessionExecution, AnalysisSnapshotCache, analysisError*).
- Workflows: `crates/engines/src/workflows/` (EnhancedTools, CallPathTracing, EnhancedLiteralTracing, AnalysisContextQueries, NativeValueTrace, NativeApiInspection, NativeDispatchMetadataInspection, symbolAnalysis, swiftSymbolClassification).
- Derivadas de Evidence: `crates/engines/src/derived/` (callPath, functionComparison*, e uma reimplementação do algoritmo `diffLines` do pacote `diff` (jsdiff, BSD-3-Clause, Copyright (c) Kevin Decker e colaboradores), que o REA usa; o texto da licença BSD-3-Clause do jsdiff acompanha aquele pacote).
- Oráculos gravados (`fixtures/engines/**/oracle_*.json.gz`) são saídas do próprio REA sobre fixtures deste repositório.

---

## Outras trilhas derivadas de REA

Também são reescritas em Rust do TypeScript de morluto/rea (MIT, licença acima), mantendo mensagens,
limites e comportamento: `crates/managed` (src/dotnet), `crates/android` (providers Android, Apktool, JEB),
`crates/device` (adb, firmware, gate de host, trace_native_ui_action), `crates/native` (providers nativos
e Apple), `crates/web` e `crates/js` (web, JavaScript, Electron, reconstrução). A ponte
`crates/android/bridge/ReaJadxBridge.java` é cópia sem mudança, com cabeçalho de atribuição.

## Fixtures de teste de terceiros (não fazem parte do binário)

- `fixtures/managed/real_primitives_net8.dll`, `real_primitives_net462.dll`, `real_systemevents_net8.dll`:
  assemblies dos pacotes NuGet Microsoft.Extensions.Primitives 8.0.0 e Microsoft.Win32.SystemEvents 8.0.0,
  Copyright (c) .NET Foundation and Contributors, licença MIT (mesmo texto da licença MIT acima, com esse
  aviso de copyright). Origem e hashes em `fixtures/managed/PROVENANCE.txt`.
- `fixtures/native_static/assets/vendor/*.car`: catálogos de bartoszj/acextract (MIT, Copyright (c) 2014
  Bartosz Janda) e coollazy/AssetsParser (Apache-2.0). Textos das licenças em `LICENSE-acextract` e
  `LICENSE-AssetsParser` na mesma pasta; origem por arquivo em `README.md` da pasta.
- Dependências Rust de `crates/native` com licenças diferentes de MIT/Apache-2.0 (Unicode-3.0, Swift
  Runtime Library Exception): ver `crates/native/NOTICE.md`.

Ferramentas externas usadas só nos testes (Ghidra, JDK, jadx-headless-mcp, Apktool, Binwalk, Unblob,
mitmproxy, Chrome, Node, o próprio REA) não são redistribuídas.
