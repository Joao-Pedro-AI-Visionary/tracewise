#!/usr/bin/env node
// Standalone fake of the upstream ida-pro-mcp server (MCP over stdio, one JSON-RPC
// message per line, no dependencies). It models ONE binary: fixtures/engines/sample_elf
// (built from fixtures/engines/sample.c), so every answer is deterministic.
//
// Two upstream tool families are served, selected by `--profile`:
//   legacy  the 1.4 profile REA's attached mode needs: get_metadata, list_functions,
//           list_strings, get_function_by_name, get_function_by_address,
//           decompile_function, disassemble_function, get_callers, get_callees,
//           get_xrefs_to.
//   modern  the database-supervisor profile REA's headless mode needs: idb_open, idb_list,
//           idb_close, server_health, list_funcs, lookup_funcs, find_regex, decompile,
//           disasm, callees, xrefs_to (every analysis call is scoped by `database`).
// Both families also advertise mutating tools (rename/comment/save) so a consumer that
// must stay read-only can be proven never to call them.
//
// Environment (read from the process that launched the fake, never from the config):
//   FAKE_IDA_LOG          append one JSON line {tool, arguments} per tools/call
//   FAKE_IDA_PID_FILE     write the fake's pid there on start (orphan checks)
//   FAKE_IDA_STALL_TOOL   never answer calls to this tool (cancellation/timeout checks)
//   FAKE_IDA_MALFORMED    comma list of tools that answer {"unexpected": true}
//   FAKE_IDA_TOOL_ERROR   comma list of tools that answer an MCP error result (isError)
//   FAKE_IDA_TRUNCATE     comma list of tools whose result carries output_truncated metadata
//
// Transports: stdio by default; `--http <port>` serves the same tools as streamable HTTP
// (POST /mcp answering application/json, no session) on 127.0.0.1. `/redirect` answers a
// 307 to /mcp so a client that must not follow redirects can be checked. Requests carrying
// an `X-Fixture-Key` header have its value recorded in the call log.
//
// The fake pages every inventory with small caps (functions 6, strings 5, pseudocode 6
// lines, assembly 8 instructions) so clients must follow the upstream cursors.

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";

const argValue = (flag) => {
  const index = process.argv.indexOf(flag);
  return index >= 0 ? process.argv[index + 1] : undefined;
};
const PROFILE = argValue("--profile") ?? "legacy";
if (PROFILE !== "legacy" && PROFILE !== "modern") {
  process.stderr.write(`unknown --profile ${PROFILE}\n`);
  process.exit(2);
}
if (process.env.FAKE_IDA_PID_FILE) writeFileSync(process.env.FAKE_IDA_PID_FILE, String(process.pid));

// ---------------------------------------------------------------- the modeled binary

const SAMPLE_SHA256 = "61ec630145d9a6b8ddb77a33a5d31b3a75589df9e02eb68c749044e1c4a5a83e";
const IMAGE_BASE = "0x400000";
const MODULE = "sample_elf";
// What an attached IDA reports as the recorded input path (synthetic and location-free).
const ATTACHED_INPUT_PATH = "/analysis/sample_elf";
const SERVER_INFO = { name: "ida-pro-mcp-fixture", version: "1.0.0-fixture" };

const hex = (n) => `0x${n.toString(16)}`;
const parse = (text) => BigInt(text.toLowerCase().startsWith("0x") ? text : `0x${text}`);

const FUNCTIONS = [
  [0x401000, "_init", 0x1b],
  [0x401060, "_start", 0x26],
  [0x401090, "_dl_relocate_static_pie", 5],
  [0x4010a0, "deregister_tm_clones", 0x21],
  [0x4010d0, "register_tm_clones", 0x31],
  [0x401110, "__do_global_dtors_aux", 0x21],
  [0x401140, "frame_dummy", 6],
  [0x401146, "engine_leaf", 0x22],
  [0x401168, "engine_branch", 0x2b],
  [0x401193, "engine_apply", 0x1c],
  [0x4011af, "engine_measure", 0x26],
  [0x4011d5, "engine_entry", 0x3f],
  [0x401214, "main", 0x31],
  [0x401248, "_term_proc", 0xd],
].map(([address, name, size]) => ({ address, name, size }));
const byName = new Map(FUNCTIONS.map((fn) => [fn.name, fn]));
const view = (fn) => ({ address: hex(fn.address), name: fn.name, size: hex(fn.size) });
const viewModern = (fn) => ({ addr: hex(fn.address), name: fn.name, size: hex(fn.size) });
const containing = (address) =>
  FUNCTIONS.find((fn) => address >= fn.address && address < fn.address + fn.size);

// PLT stubs are imports here: calls into them are "external" and they are not functions.
const IMPORTS = new Map([
  [0x401030, "puts"],
  [0x401040, "strlen"],
  [0x401050, "printf"],
  [0x403fd8, "__libc_start_main"],
]);
const CALLEES = {
  _start: [0x403fd8],
  __do_global_dtors_aux: [0x4010a0],
  engine_leaf: [0x401030],
  engine_branch: [0x401146],
  engine_measure: [0x401040],
  engine_entry: [0x401168, 0x401193, 0x4011af],
  main: [0x4011d5, 0x401050],
};
const calleeDescriptor = (address) => {
  const external = IMPORTS.get(address);
  if (external !== undefined) return { address, name: external, type: "external" };
  const fn = containing(address);
  return { address: fn.address, name: fn.name, type: "internal" };
};
const calleesOf = (fn) => (CALLEES[fn.name] ?? []).map(calleeDescriptor);
const callersOf = (fn) =>
  FUNCTIONS.filter((candidate) => (CALLEES[candidate.name] ?? []).includes(fn.address));

const XREFS_TO = new Map([
  [0x401146, [[0x40117e, "code"], [0x40118c, "code"]]],
  [0x401168, [[0x4011e8, "code"], [0x4011f5, "data"]]],
  [0x401193, [[0x4011fa, "code"]]],
  [0x4011af, [[0x401207, "code"]]],
  [0x4011d5, [[0x401228, "code"]]],
  [0x401214, [[0x401078, "data"]]],
  [0x4010a0, [[0x401121, "code"]]],
  [0x4010d0, [[0x401144, "code"]]],
  [0x401030, [[0x401156, "code"]]],
  [0x401040, [[0x4011c2, "code"]]],
  [0x401050, [[0x401239, "code"]]],
  [0x404028, [[0x40115b, "data"], [0x4011c7, "data"]]],
  [0x402010, [[0x401202, "data"]]],
  [0x402026, [[0x401151, "data"]]],
  [0x40203a, [[0x40122f, "data"]]],
]);

const STRINGS = [
  [0x400318, "/lib64/ld-linux-x86-64.so.2"],
  [0x400451, "puts"],
  [0x400456, "strlen"],
  [0x40045d, "__libc_start_main"],
  [0x40046f, "printf"],
  [0x400476, "libc.so.6"],
  [0x400480, "GLIBC_2.2.5"],
  [0x40048c, "GLIBC_2.34"],
  [0x400497, "__gmon_start__"],
  [0x402010, "ENGINE_FIXTURE_BANNER"],
  [0x402026, "ENGINE_LEAF_MESSAGE"],
  [0x40203a, "%d\n"],
].map(([address, string]) => ({ address, string }));

// Hand-written for the engine functions and main (IDA flavored); generated from the
// binary's own disassembly for the remaining ones.
const asm = (rows) => rows.map(([address, instruction, comment]) => ({
  address: hex(address),
  instruction,
  ...(comment === undefined ? {} : { comments: [comment] }),
}));
const ASM = {
  engine_leaf: asm([
    [0x401146, "push    rbp"],
    [0x401147, "mov     rbp, rsp"],
    [0x40114a, "sub     rsp, 10h"],
    [0x40114e, "mov     [rbp+var_4], edi"],
    [0x401151, "mov     edi, offset aEngineLeafMess", "\"ENGINE_LEAF_MESSAGE\""],
    [0x401156, "call    _puts"],
    [0x40115b, "mov     edx, cs:engine_counter"],
    [0x401161, "mov     eax, [rbp+var_4]"],
    [0x401164, "add     eax, edx"],
    [0x401166, "leave"],
    [0x401167, "retn"],
  ]),
  engine_branch: asm([
    [0x401168, "push    rbp"],
    [0x401169, "mov     rbp, rsp"],
    [0x40116c, "sub     rsp, 10h"],
    [0x401170, "mov     [rbp+var_4], edi"],
    [0x401173, "cmp     [rbp+var_4], 0Ah"],
    [0x401177, "jle     short loc_401185"],
    [0x401179, "mov     eax, [rbp+var_4]"],
    [0x40117c, "mov     edi, eax"],
    [0x40117e, "call    engine_leaf"],
    [0x401183, "jmp     short locret_401191"],
    [0x401185, "mov     eax, [rbp+var_4]"],
    [0x401188, "neg     eax"],
    [0x40118a, "mov     edi, eax"],
    [0x40118c, "call    engine_leaf"],
    [0x401191, "leave"],
    [0x401192, "retn"],
  ]),
  engine_apply: asm([
    [0x401193, "push    rbp"],
    [0x401194, "mov     rbp, rsp"],
    [0x401197, "sub     rsp, 10h"],
    [0x40119b, "mov     [rbp+var_8], rdi"],
    [0x40119f, "mov     [rbp+var_C], esi"],
    [0x4011a2, "mov     eax, [rbp+var_C]"],
    [0x4011a5, "mov     rdx, [rbp+var_8]"],
    [0x4011a9, "mov     edi, eax"],
    [0x4011ab, "call    rdx"],
    [0x4011ad, "leave"],
    [0x4011ae, "retn"],
  ]),
  engine_measure: asm([
    [0x4011af, "push    rbp"],
    [0x4011b0, "mov     rbp, rsp"],
    [0x4011b3, "sub     rsp, 10h"],
    [0x4011b7, "mov     [rbp+var_8], rdi"],
    [0x4011bb, "mov     rax, [rbp+var_8]"],
    [0x4011bf, "mov     rdi, rax"],
    [0x4011c2, "call    _strlen"],
    [0x4011c7, "mov     edx, cs:engine_counter"],
    [0x4011cd, "movsxd  rdx, edx"],
    [0x4011d0, "add     rax, rdx"],
    [0x4011d3, "leave"],
    [0x4011d4, "retn"],
  ]),
  engine_entry: asm([
    [0x4011d5, "push    rbp"],
    [0x4011d6, "mov     rbp, rsp"],
    [0x4011d9, "sub     rsp, 20h"],
    [0x4011dd, "mov     [rbp+var_14], edi"],
    [0x4011e0, "mov     eax, [rbp+var_14]"],
    [0x4011e3, "shl     eax, 2"],
    [0x4011e6, "mov     edi, eax"],
    [0x4011e8, "call    engine_branch"],
    [0x4011ed, "mov     [rbp+var_4], eax"],
    [0x4011f0, "mov     eax, [rbp+var_14]"],
    [0x4011f3, "mov     esi, eax"],
    [0x4011f5, "mov     edi, offset engine_branch"],
    [0x4011fa, "call    engine_apply"],
    [0x4011ff, "add     [rbp+var_4], eax"],
    [0x401202, "mov     edi, offset engine_banner", "\"ENGINE_FIXTURE_BANNER\""],
    [0x401207, "call    engine_measure"],
    [0x40120c, "add     [rbp+var_4], eax"],
    [0x40120f, "mov     eax, [rbp+var_4]"],
    [0x401212, "leave"],
    [0x401213, "retn"],
  ]),
  main: asm([
    [0x401214, "push    rbp"],
    [0x401215, "mov     rbp, rsp"],
    [0x401218, "sub     rsp, 10h"],
    [0x40121c, "mov     [rbp+var_4], edi"],
    [0x40121f, "mov     [rbp+var_10], rsi"],
    [0x401223, "mov     eax, [rbp+var_4]"],
    [0x401226, "mov     edi, eax"],
    [0x401228, "call    engine_entry"],
    [0x40122d, "mov     esi, eax"],
    [0x40122f, "mov     edi, offset aD", "\"%d\\n\""],
    [0x401234, "mov     eax, 0"],
    [0x401239, "call    _printf"],
    [0x40123e, "mov     eax, 0"],
    [0x401243, "leave"],
    [0x401244, "retn"],
  ]),
};
// GENERATED_ASM_BEGIN (objdump of sample_elf, trimmed to each function's size)
const GENERIC_ASM = {
  "_init": [
    ["0x401000", "endbr64"],
    ["0x401004", "sub     rsp, 0x8"],
    ["0x401008", "mov     rax, QWORD PTR [rip+0x2fd1]"],
    ["0x40100f", "test    rax, rax"],
    ["0x401012", "je      401016"],
    ["0x401014", "call    rax"],
    ["0x401016", "add     rsp, 0x8"],
    ["0x40101a", "ret"],
  ],
  "_start": [
    ["0x401060", "endbr64"],
    ["0x401064", "xor     ebp, ebp"],
    ["0x401066", "mov     r9, rdx"],
    ["0x401069", "pop     rsi"],
    ["0x40106a", "mov     rdx, rsp"],
    ["0x40106d", "and     rsp, 0xfffffffffffffff0"],
    ["0x401071", "push    rax"],
    ["0x401072", "push    rsp"],
    ["0x401073", "xor     r8d, r8d"],
    ["0x401076", "xor     ecx, ecx"],
    ["0x401078", "mov     rdi, 0x401214"],
    ["0x40107f", "call    QWORD PTR [rip+0x2f53]"],
    ["0x401085", "hlt"],
  ],
  "_dl_relocate_static_pie": [
    ["0x401090", "endbr64"],
    ["0x401094", "ret"],
  ],
  "deregister_tm_clones": [
    ["0x4010a0", "mov     eax, 0x404030"],
    ["0x4010a5", "cmp     rax, 0x404030"],
    ["0x4010ab", "je      4010c0"],
    ["0x4010ad", "mov     eax, 0x0"],
    ["0x4010b2", "test    rax, rax"],
    ["0x4010b5", "je      4010c0"],
    ["0x4010b7", "mov     edi, 0x404030"],
    ["0x4010bc", "jmp     rax"],
    ["0x4010be", "xchg    ax, ax"],
    ["0x4010c0", "ret"],
  ],
  "register_tm_clones": [
    ["0x4010d0", "mov     esi, 0x404030"],
    ["0x4010d5", "sub     rsi, 0x404030"],
    ["0x4010dc", "mov     rax, rsi"],
    ["0x4010df", "shr     rsi, 0x3f"],
    ["0x4010e3", "sar     rax, 0x3"],
    ["0x4010e7", "add     rsi, rax"],
    ["0x4010ea", "sar     rsi, 1"],
    ["0x4010ed", "je      401100"],
    ["0x4010ef", "mov     eax, 0x0"],
    ["0x4010f4", "test    rax, rax"],
    ["0x4010f7", "je      401100"],
    ["0x4010f9", "mov     edi, 0x404030"],
    ["0x4010fe", "jmp     rax"],
    ["0x401100", "ret"],
  ],
  "__do_global_dtors_aux": [
    ["0x401110", "endbr64"],
    ["0x401114", "cmp     BYTE PTR [rip+0x2f11], 0x0"],
    ["0x40111b", "jne     401130"],
    ["0x40111d", "push    rbp"],
    ["0x40111e", "mov     rbp, rsp"],
    ["0x401121", "call    4010a0"],
    ["0x401126", "mov     BYTE PTR [rip+0x2eff], 0x1"],
    ["0x40112d", "pop     rbp"],
    ["0x40112e", "ret"],
    ["0x40112f", "nop"],
    ["0x401130", "ret"],
  ],
  "frame_dummy": [
    ["0x401140", "endbr64"],
    ["0x401144", "jmp     4010d0"],
  ],
  "_term_proc": [
    ["0x401248", "endbr64"],
    ["0x40124c", "sub     rsp, 0x8"],
    ["0x401250", "add     rsp, 0x8"],
    ["0x401254", "ret"],
  ],
};
// GENERATED_ASM_END
for (const [name, rows] of Object.entries(GENERIC_ASM))
  ASM[name] = rows.map(([address, instruction]) => ({ address, instruction }));

const SIGNATURES = {
  engine_leaf: ["int", [["a1", "int"]]],
  engine_branch: ["int", [["a1", "int"]]],
  engine_apply: ["int", [["a1", "int (__fastcall *)(int)"], ["a2", "int"]]],
  engine_measure: ["size_t", [["a1", "const char *"]]],
  engine_entry: ["int", [["a1", "int"]]],
  main: ["int", [["argc", "int"], ["argv", "const char **"]]],
};

const PSEUDOCODE = {
  engine_leaf: [
    "int __fastcall engine_leaf(int a1)",
    "{",
    "  puts(\"ENGINE_LEAF_MESSAGE\");",
    "  return engine_counter + a1;",
    "}",
  ],
  engine_branch: [
    "int __fastcall engine_branch(int a1)",
    "{",
    "  if ( a1 > 10 )",
    "    return engine_leaf(a1);",
    "  else",
    "    return engine_leaf(-a1);",
    "}",
  ],
  engine_apply: [
    "int __fastcall engine_apply(int (__fastcall *a1)(int), int a2)",
    "{",
    "  return a1(a2);",
    "}",
  ],
  engine_measure: [
    "size_t __fastcall engine_measure(const char *a1)",
    "{",
    "  return engine_counter + strlen(a1);",
    "}",
  ],
  engine_entry: [
    "__int64 __fastcall engine_entry(int a1)",
    "{",
    "  int v1; // [rsp+1Ch] [rbp-4h]",
    "",
    "  v1 = engine_branch(4 * a1);",
    "  v1 += engine_apply(engine_branch, a1);",
    "  return (unsigned int)(engine_measure(engine_banner) + v1);",
    "}",
  ],
  main: [
    "int __fastcall main(int argc, const char **argv, const char **envp)",
    "{",
    "  printf(\"%d\\n\", (unsigned int)engine_entry(argc));",
    "  return 0;",
    "}",
  ],
};
const pseudocodeOf = (fn) =>
  PSEUDOCODE[fn.name] ?? [`void __fastcall ${fn.name}()`, "{", "  ;", "}"];

// ---------------------------------------------------------------- caps (forces paging)

const FUNCTION_PAGE = 6;
const STRING_PAGE = 5;
const DECOMPILE_PAGE = 6;
const DISASM_PAGE = 8;

// ---------------------------------------------------------------- tool implementations

class ToolError extends Error {}

const functionAt = (text) => {
  if (typeof text !== "string" || !/^0x[0-9a-f]+$/iu.test(text)) throw new ToolError(`Invalid address: ${String(text)}`);
  const fn = containing(Number(parse(text)));
  if (fn === undefined) throw new ToolError(`No function contains ${text}`);
  return fn;
};
const functionNamed = (text) => {
  const fn = typeof text === "string" ? byName.get(text) : undefined;
  if (fn === undefined) throw new ToolError(`Function not found: ${String(text)}`);
  return fn;
};
// Modern lookups accept a name first, then a (possibly bare) hexadecimal address.
const entryOf = (text) =>
  typeof text === "string" && byName.has(text)
    ? byName.get(text)
    : functionAt(typeof text === "string" && /^[0-9a-f]+$/iu.test(text) ? `0x${text}` : text);
const page = (items, offset, cap, requested) => {
  const start = Number.isInteger(offset) && offset >= 0 ? offset : 0;
  const count = Math.min(cap, Number.isInteger(requested) && requested > 0 ? requested : cap);
  const data = items.slice(start, start + count);
  return { data, next: start + count < items.length ? start + count : null };
};
const cursorFor = (next) => (next === null ? { done: true } : { next });

const legacyLine = (line) => line;
const modernLine = ({ address, instruction, comments }) => ({
  addr: address,
  instruction,
  ...(comments === undefined ? {} : { comments }),
});
const asmView = (fn, lines, line) => ({
  name: fn.name,
  start_ea: hex(fn.address),
  lines: lines.map(line),
  ...(SIGNATURES[fn.name] === undefined
    ? {}
    : {
        return_type: SIGNATURES[fn.name][0],
        arguments: SIGNATURES[fn.name][1].map(([name, type]) => ({ name, type })),
      }),
});

const xrefsFor = (address) =>
  (XREFS_TO.get(address) ?? []).map(([from, type]) => ({ from, type, fn: containing(from) ?? null }));

const sessions = new Map();
const requireDatabase = (args) => {
  const session = sessions.get(args.database);
  if (args.database === undefined) throw new ToolError("database is required");
  if (session === undefined) throw new ToolError(`Unknown database ${String(args.database)}`);
  return session;
};

const LEGACY = {
  get_metadata: () => ({
    path: ATTACHED_INPUT_PATH,
    module: MODULE,
    base: IMAGE_BASE,
    size: "0x3680",
    sha256: SAMPLE_SHA256,
  }),
  list_functions: ({ offset, count }) => {
    const { data, next } = page(FUNCTIONS, offset, FUNCTION_PAGE, count);
    return { data: data.map(view), next_offset: next };
  },
  list_strings: ({ offset, count }) => {
    const { data, next } = page(STRINGS, offset, STRING_PAGE, count);
    return {
      data: data.map(({ address, string }) => ({ address: hex(address), string, length: [...string].length })),
      next_offset: next,
    };
  },
  get_function_by_name: ({ name }) => view(functionNamed(name)),
  get_function_by_address: ({ address }) => {
    const fn = functionAt(address);
    // Legacy producers echo the queried (possibly interior) address.
    return { ...view(fn), address: hex(Number(parse(address))) };
  },
  decompile_function: ({ address }) => pseudocodeOf(entryOf(address)).join("\n"),
  disassemble_function: ({ start_address }) => {
    const fn = functionAt(start_address);
    return asmView(fn, ASM[fn.name], legacyLine);
  },
  get_callers: ({ function_address }) => callersOf(functionAt(function_address)).map(view),
  get_callees: ({ function_address }) =>
    calleesOf(functionAt(function_address)).map(({ address, name, type }) => ({ address: hex(address), name, type })),
  get_xrefs_to: ({ address }) =>
    xrefsFor(Number(parse(address))).map(({ from, type, fn }) => ({
      address: hex(from),
      type,
      function: fn === null ? null : view(fn),
    })),
  // Mutating tools: advertised so a read-only consumer can be audited; never to be called.
  rename_function: () => ({ success: true }),
  set_comment: () => ({ success: true }),
  declare_c_type: () => ({ success: true }),
};
const LEGACY_TEXT_ONLY = new Set(["decompile_function", "get_metadata"]);

const MODERN = {
  idb_open: (args) => {
    if (typeof args.input_path !== "string") throw new ToolError("input_path is required");
    if (!existsSync(args.input_path)) throw new ToolError(`Input not found: ${args.input_path}`);
    const digest = createHash("sha256").update(readFileSync(args.input_path)).digest("hex");
    if (digest !== SAMPLE_SHA256) throw new ToolError("Unsupported input: not the modeled sample_elf");
    const id = args.preferred_session_id ?? `fixture-${sessions.size + 1}`;
    const session = {
      session_id: id,
      input_path: args.input_path,
      idb_path: `${args.input_path}.i64`,
      backend: "worker",
      owned: true,
      is_active: true,
    };
    sessions.set(id, session);
    return { success: true, session };
  },
  idb_list: () => ({ sessions: [...sessions.values()] }),
  idb_close: (args) => {
    const session = requireDatabase(args);
    sessions.delete(session.session_id);
    return {
      success: true,
      session_id: session.session_id,
      saved: args.save === true ? true : false,
      owned: session.owned,
      backend: session.backend,
    };
  },
  server_health: (args) => {
    const session = requireDatabase(args);
    return {
      status: "ok",
      input_path: session.input_path,
      idb_path: session.idb_path,
      module: MODULE,
      imagebase: IMAGE_BASE,
      auto_analysis_ready: true,
    };
  },
  list_funcs: (args) => {
    requireDatabase(args);
    const { offset, count } = args.queries ?? {};
    const { data, next } = page(FUNCTIONS, offset, FUNCTION_PAGE, count);
    return [{ data: data.map(viewModern), next_offset: next }];
  },
  lookup_funcs: (args) => {
    requireDatabase(args);
    return (args.queries ?? []).map((query) => {
      try {
        return { query, fn: viewModern(entryOf(query)), error: null };
      } catch (error) {
        return { query, fn: null, error: error.message };
      }
    });
  },
  find_regex: (args) => {
    requireDatabase(args);
    const flags = /^\(\?s\)/u.test(args.pattern) ? "su" : "u";
    const pattern = new RegExp(args.pattern.replace(/^\(\?s\)/u, ""), flags);
    const matches = STRINGS.filter(({ string }) => pattern.test(string));
    const { data, next } = page(matches, args.offset, STRING_PAGE, args.limit);
    return {
      matches: data.map(({ address, string }) => ({ addr: hex(address), string })),
      cursor: cursorFor(next),
    };
  },
  decompile: (args) => {
    requireDatabase(args);
    let fn;
    try {
      fn = entryOf(args.addr);
    } catch (error) {
      return { code: null, error: error.message, cursor: { done: true } };
    }
    const lines = pseudocodeOf(fn);
    const { data, next } = page(lines, args.offset, DECOMPILE_PAGE, args.max_lines);
    return {
      code: data.join("\n"),
      cursor: cursorFor(next),
      line_count: data.length,
      total_lines: lines.length,
    };
  },
  disasm: (args) => {
    requireDatabase(args);
    let fn;
    try {
      fn = entryOf(args.addr);
    } catch (error) {
      return { asm: null, error: error.message, cursor: { done: true } };
    }
    const { data, next } = page(ASM[fn.name], args.offset, DISASM_PAGE, args.max_instructions);
    return { asm: asmView(fn, data, modernLine), cursor: cursorFor(next) };
  },
  callees: (args) => {
    requireDatabase(args);
    return (args.addrs ?? []).map((addr) => {
      try {
        const fn = entryOf(addr);
        return {
          callees: calleesOf(fn).map(({ address, name, type }) => ({ addr: hex(address), name, type })),
          more: false,
        };
      } catch (error) {
        return { callees: null, error: error.message };
      }
    });
  },
  xrefs_to: (args) => {
    requireDatabase(args);
    return (args.addrs ?? []).map((addr) => {
      const rows = xrefsFor(Number(parse(addr)));
      return {
        xrefs: rows.slice(0, args.limit ?? 1000).map(({ from, type, fn }) => ({
          addr: hex(from),
          type,
          fn: fn === null ? null : viewModern(fn),
        })),
        more: false,
      };
    });
  },
  idb_save: () => ({ success: true }),
  rename_functions: () => ({ success: true }),
  set_comments: () => ({ success: true }),
};

const TOOLS = PROFILE === "legacy" ? LEGACY : MODERN;

// ---------------------------------------------------------------- JSON-RPC plumbing

const sendStdio = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const toolResult = (name, value) => {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (PROFILE === "legacy" && LEGACY_TEXT_ONLY.has(name)) return { content: [{ type: "text", text }] };
  const structuredContent = value !== null && typeof value === "object" && !Array.isArray(value) ? value : { result: value };
  return { content: [{ type: "text", text }], structuredContent };
};

const handle = (message, send = sendStdio, requestHeaders = undefined) => {
  const { id, method, params } = message;
  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: params?.protocolVersion ?? "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      },
    });
  } else if (method === "ping") {
    send({ jsonrpc: "2.0", id, result: {} });
  } else if (method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id,
      result: { tools: Object.keys(TOOLS).map((name) => ({ name, inputSchema: { type: "object" } })) },
    });
  } else if (method === "tools/call") {
    const name = params?.name;
    const args = params?.arguments ?? {};
    if (process.env.FAKE_IDA_LOG)
      appendFileSync(
        process.env.FAKE_IDA_LOG,
        `${JSON.stringify({
          tool: name,
          arguments: args,
          ...(requestHeaders === undefined ? {} : { fixture_key: requestHeaders["x-fixture-key"] ?? null }),
        })}\n`,
      );
    if (process.env.FAKE_IDA_STALL_TOOL === name) return;
    if (!Object.hasOwn(TOOLS, name)) {
      send({ jsonrpc: "2.0", id, error: { code: -32602, message: `Unknown tool: ${String(name)}` } });
      return;
    }
    try {
      const faulty = (variable) => (process.env[variable] ?? "").split(",").includes(name);
      if (faulty("FAKE_IDA_TOOL_ERROR")) throw new ToolError("Simulated upstream failure");
      const value = faulty("FAKE_IDA_MALFORMED") ? { unexpected: true } : TOOLS[name](args);
      const result = toolResult(name, value);
      if (faulty("FAKE_IDA_TRUNCATE"))
        result._meta = { ida_mcp: { output_truncated: true, download_hint: "Fixture download hint." } };
      send({ jsonrpc: "2.0", id, result });
    } catch (error) {
      if (!(error instanceof ToolError)) throw error;
      send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: error.message }], isError: true } });
    }
  } else if (id !== undefined) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${String(method)}` } });
  }
};

const httpPort = argValue("--http");
if (httpPort === undefined) {
  const input = createInterface({ input: process.stdin });
  input.on("line", (line) => {
    if (line.trim().length > 0) handle(JSON.parse(line));
  });
  input.on("close", () => process.exit(0));
} else {
  const { createServer } = await import("node:http");
  const server = createServer((request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(307, { Location: "/mcp" }).end();
      return;
    }
    if (request.url !== "/mcp") {
      response.writeHead(404).end();
      return;
    }
    if (request.method === "DELETE") {
      response.writeHead(200).end();
      return;
    }
    if (request.method !== "POST") {
      response.writeHead(405).end();
      return;
    }
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const message = JSON.parse(body);
      if (message.id === undefined) {
        response.writeHead(202).end();
        return;
      }
      handle(
        message,
        (reply) => {
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify(reply));
        },
        request.headers,
      );
    });
  });
  server.listen(Number(httpPort), "127.0.0.1", () => process.stdout.write(`listening ${server.address().port}\n`));
}
