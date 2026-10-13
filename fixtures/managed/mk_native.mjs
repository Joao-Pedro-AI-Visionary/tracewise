import { createEvidence } from "/workspace/rea-map/src/dist/domain/evidence.js";
import { writeFileSync } from "node:fs";
const provider = { id: "fixture-native", name: "Fixture native provider", version: "1" };
const sha = (c) => c.repeat(64);
const cov = (items) => ({ items, total: items.length, exhaustive: true, limitations: [] });
const macho = (path, exportsList, fillChar) => createEvidence(
  { path, sha256: sha(fillChar), format: "mach-o", architecture: "x86_64" }, provider, {
    operation: "inspect_macho", parameters: {},
    result: {
      format: "mach-o", endian: "little", word_size: 64, file_type: "dylib", flags: [], uuid: null,
      entrypoints: cov([]), architectures: cov([]), build_metadata: cov([]), load_commands: cov([]),
      dependencies: cov([]), imports: cov([]),
      exports: cov(exportsList.map((name, i) => ({ name, address: `0x${(0x1000 + i * 16).toString(16)}`, weak: false, reexport: false, source: null }))),
      segments: cov([]), provenance: [], limitations: [],
    }, rawResult: null, limitations: [],
  });
const dossier = (path, name, address, fillChar) => createEvidence(
  path === null ? undefined : { path, sha256: sha(fillChar), format: "pe", architecture: "x86_64" }, provider, {
    operation: "analyze_function", parameters: { address },
    result: {
      procedure: { address, name, classification: null, body: { available: false, reason: "fixture" }, signature: null, locals: [] },
      pseudocode: "", assembly: [], comments: [], callers: [], callees: [], incoming_references: [], outgoing_references: [],
      referenced_strings: [], referenced_names: [], basic_blocks: [], native_api: null, native_value_flow: null, limitations: [],
    }, rawResult: null, limitations: [],
  });
const out = {
  macho_user32: macho("/native/user32.dll", ["DefWindowProcW", "GetProcessWindowStation", "SendMessageW", "_PostQuitMessage", "SetTimerEx", "TranslateMessage", "MessageBoxW", "puts"], "a"),
  macho_gdi32: macho("/native/gdi32.dll", ["SetTimer", "TranslateMessage", "DestroyWindow"], "b"),
  macho_libkernel32: macho("/native/libkernel32.so", ["GetCurrentThreadId", "LoadLibraryW", "CreateWindowEx"], "c"),
  macho_libc: macho("/native/libc.so.6", ["puts", "_puts"], "d"),
  macho_empty: macho("/native/empty.dylib", [], "e"),
  func_loadlibrary: dossier("/native/kernel32.dll", "LoadLibraryW", "0x401000", "f"),
  func_messagebox: dossier("/native/user32.dll", "MessageBoxW", "0x402000", "9"),
  func_nosubject: dossier(null, "GetProcAddress", "0x403000", "0"),
};
writeFileSync("/tmp/tracewise-oracle/crafted_native.json", JSON.stringify(out));
console.log(Object.keys(out).join(","));
