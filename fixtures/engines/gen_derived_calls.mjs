// Generates the ordered call list for the derived-tool oracle golden
// (`oracle_derived_*.json`). Run from the repository root:
//
//   REA_ROOT=<rea checkout> node fixtures/engines/gen_derived_calls.mjs <out.json>
//   python3 fixtures/engines/oracle_session.py <out.json> fixtures/engines/oracle_derived_session.json
//
// The base Evidence comes from `oracle_ghidra_dossiers.json` (real Ghidra dossiers). Variants
// are forged with REA's own `createEvidence`, so every inline record is authentic (semantic
// id included). Retention is part of the sequence: `compare_functions` records its two
// sources in the session, which is what `build_call_path` needs.
import fs from "node:fs";
import zlib from "node:zlib";
import path from "node:path";
import { pathToFileURL } from "node:url";

const reaRoot = process.env.REA_ROOT ?? "/workspace/rea-map/src";
const load = (p) => import(pathToFileURL(path.join(reaRoot, "dist", p)).href);
const { createEvidence } = await load("domain/evidence.js");
const { compareFunctions } = await load("domain/functionComparison.js");
const { FUNCTION_COMPARISON_PROVIDER } = await load("application/InvestigationProviders.js");

const golden = JSON.parse(zlib.gunzipSync(fs.readFileSync("fixtures/engines/oracle_ghidra_dossiers.json.gz")).toString("utf8"));
const ev = (i) => golden[i].result.structuredContent;
const clone = (v) => structuredClone(v);

/** Forge authentic Evidence from `base` with overrides. */
const mk = (base, o = {}) =>
  createEvidence(
    o.noSubject
      ? undefined
      : {
          path: base.subject.local_path,
          sha256: o.sha ?? base.subject.digest.sha256,
          format: base.subject.format,
          architecture: base.subject.architecture,
        },
    o.provider ?? base.provider,
    {
      predicateType: o.predicate ?? base.predicate_type,
      operation: o.operation ?? base.operation,
      parameters: o.parameters ?? base.parameters,
      result: o.result ?? base.normalized_result,
      ...("profile" in o
        ? o.profile === null
          ? {}
          : { analysisProfile: o.profile }
        : base.analysis_profile === null
          ? {}
          : { analysisProfile: base.analysis_profile }),
      ...(o.raw === undefined ? {} : { rawResult: o.raw }),
      confidence: base.confidence,
      authority: base.authority,
      limitations: o.limitations ?? base.limitations,
      locations: base.locations,
      evidenceLinks: base.evidence_links,
    },
  );
/** Forge by editing a clone of the dossier. */
const mod = (base, edit, o = {}) => {
  const dossier = clone(base.normalized_result);
  edit(dossier);
  return mk(base, { ...o, result: dossier });
};
const HOPPER = { id: "hopper", name: "Hopper", version: "5.0" };
const c2 = mk(ev(2)); // compact copy (no raw_result)
const c1 = mk(ev(1));

const ident = (address, name) => ({
  address,
  name,
  classification: null,
  body: { available: false, reason: "synthetic" },
});
const fn = (base, address, name, callees, o = {}) =>
  mk(base, {
    ...o,
    parameters: { procedure: name },
    result: {
      procedure: { ...ident(address, name), signature: null, locals: [] },
      pseudocode: "",
      assembly: [],
      comments: [],
      callers: [],
      callees: callees.map(([a, n]) => ident(a, n)),
      incoming_references: [],
      outgoing_references: [],
      referenced_strings: [],
      referenced_names: [],
      basic_blocks: [],
      native_api: null,
      native_value_flow: null,
      limitations: [],
    },
  });

const calls = [];
const add = (name, args) => calls.push({ name, arguments: args });
const compare = (left, right) => add("compare_functions", { left, right });
const path_ = (functions, start, goal) =>
  add("build_call_path", { functions, start: { address: start }, goal: { address: goal } });
const retain = (list) => {
  for (let i = 0; i < list.length; i += 2) compare(list[i], list[(i + 1) % list.length]);
};

add("open_binary", { path: "/workspace/wt/engines-derived/fixtures/engines/sample_elf" });

// ---- build_call_path before anything is retained: dangling link
path_([ev(2), ev(1)], "0x401168", "0x401146");

// ---- compare_functions on real dossiers
compare(ev(2), ev(2)); // unchanged
compare(ev(2), ev(9)); // changed (rename + comments)
compare(ev(1), ev(3)); // different functions
compare(ev(6), ev(7)); // main vs external thunk
compare(ev(4), ev(5)); // retains measure/entry
compare(ev(2), ev(9)); // repeat: Unknown already registered

// ---- provider identity differs
compare(c2, mk(ev(2), { provider: HOPPER, profile: null }));
// ---- different artifact subjects
compare(c2, mk(ev(2), { sha: "ab".repeat(32) }));
// ---- address-derived names
compare(mod(ev(1), (d) => (d.procedure.name = "FUN_00401146")), c1);
compare(
  mod(ev(1), (d) => (d.procedure.name = "FUN_00401146")),
  mod(ev(1), (d) => (d.procedure.name = "FUN_00401146")),
);
compare(
  mod(ev(1), (d) => (d.callees[0].name = "sub_405008")),
  c1,
);

// ---- pseudocode and assembly text deltas
const lines = (n) => Array.from({ length: n }, (_, i) => `  line ${i};`).join("\n") + "\n";
const base = (text) => mod(ev(3), (d) => (d.pseudocode = text), { raw: undefined });
compare(base(lines(10)), base(lines(10).replace("line 4;", "line four;")));
compare(
  base(lines(10)),
  base(lines(10).replace("  line 2;\n", "  line 2;\n  extra a;\n  extra b;\n  extra c;\n").replace("  line 8;\n", "")),
);
compare(base("a\nb\nc\n"), base("a\r\nb\r\nc\r\n"));
compare(base("a\nb\nc"), base("a\nb\nc\n"));
compare(base(""), base("only\n"));
compare(base("x\ny\nx\ny\nx\n"), base("y\nx\ny\nx\ny\n"));
compare(base("\n\n\na\n\n"), base("\na\n\n\n\n"));
compare(base("café \u{1F600}\n"), base("café \u{1F601}\n"));
compare(
  mod(ev(3), (d) => (d.assembly = ["0x1: nop", "0x2: ret"])),
  mod(ev(3), (d) => (d.assembly = ["0x1: nop", "0x2: leave", "0x3: ret"])),
);

// larger texts: scattered edits (tie-breaking in the edit script) and an abandoned search
const longText = (n, tag = "l") => Array.from({ length: n }, (_, i) => `  ${tag} ${i} ${(i * 7919) % 97};`).join("\n") + "\n";
const edited = (text, every, f) => text.split("\n").map((l, i) => (i % every === 3 ? f(l, i) : l)).join("\n");
compare(base(longText(300)), base(edited(longText(300), 11, (l) => l + " // changed")));
compare(base(longText(300)), base(edited(longText(300), 7, (l, i) => (i % 2 ? "" : l)).replace(/\n\n+/g, "\n")));
compare(base(longText(6000, "x")), base(longText(6000, "y"))); // edit distance 12000 > maxEditLength
compare(base(longText(120)), base(longText(120).split("\n").reverse().join("\n")));

// ---- comments, strings and names relative to the function entry
const withComments = (cs) => mod(ev(3), (d) => (d.comments = cs), { raw: undefined });
const cm = (address, kind, text) => ({ address, kind, text });
compare(
  withComments([cm("0x401193", "comment", "entry"), cm("0x4011a0", "inline", "mid")]),
  withComments([cm("0x4011a0", "inline", "mid"), cm("0x401193", "comment", "entry")]),
);
compare(withComments([cm("0x401000", "comment", "before the entry")]), withComments([]));
compare(withComments([cm("not-an-address", "comment", "x")]), withComments([]));
const withStrings = (strings, names) =>
  mod(
    ev(3),
    (d) => {
      d.referenced_strings = strings.map(([source_address, value]) => ({ address: "0x500000", value, source_address }));
      d.referenced_names = names.map(([source_address, value]) => ({ address: "0x500100", value, source_address }));
    },
    { raw: undefined },
  );
compare(withStrings([["0x401195", "hello"]], [["0x401197", "sym"]]), withStrings([["0x401195", "hello"]], [["0x401197", "sym2"]]));
compare(withStrings([["0x401195", "hello"]], []), withStrings([["0x401195", "hello"]], []));
compare(withStrings([["0x400000", "hello"]], []), withStrings([], []));

// ---- references: kind availability and endpoints
const edge = (dir, name, kind) => ({
  source_address: "0x401195",
  target_address: "0x401146",
  source_procedure: dir === "out" ? ident("0x401193", "engine_apply") : ident("0x4011d5", name),
  target_procedure: dir === "out" ? ident("0x401146", name) : ident("0x401193", "engine_apply"),
  kind,
});
const kindOk = {
  available: true,
  provenance: "synthetic",
  type: "UNCONDITIONAL_CALL",
  flow: true,
  call: true,
  jump: false,
  data: false,
  read: false,
  write: false,
  indirect: false,
  computed: false,
  conditional: false,
  terminal: false,
  primary: true,
  operand_index: 0,
  external: false,
};
const withRefs = (incoming, outgoing) =>
  mod(
    ev(3),
    (d) => {
      d.incoming_references = incoming;
      d.outgoing_references = outgoing;
    },
    { raw: undefined },
  );
compare(withRefs([], [edge("out", "engine_leaf", kindOk)]), withRefs([], [edge("out", "engine_leaf", kindOk)]));
compare(
  withRefs([], [edge("out", "engine_leaf", kindOk)]),
  withRefs([], [edge("out", "engine_leaf", { available: false, reason: "not exposed" })]),
);
compare(
  withRefs([], [edge("out", "engine_leaf", kindOk)]),
  withRefs([], [edge("out", "engine_other", kindOk)]),
);
compare(
  withRefs([edge("in", "engine_entry", kindOk)], []),
  withRefs([edge("in", "engine_entry", { ...kindOk, type: "COMPUTED_CALL", computed: true })], []),
);

// ---- control-flow graphs
const withBlocks = (blocks) => mod(ev(3), (d) => (d.basic_blocks = blocks), { raw: undefined });
const blk = (start, end, successors) => ({ start, end, successors });
compare(
  withBlocks([blk("0x10", "0x20", ["0x20"]), blk("0x20", "0x30", [])]),
  withBlocks([blk("0x1000", "0x1010", ["0x1010"]), blk("0x1010", "0x1020", [])]),
);
compare(
  withBlocks([blk("0x10", "0x20", ["0x20"]), blk("0x20", "0x30", [])]),
  withBlocks([blk("0x10", "0x20", ["0x20"]), blk("0x20", "0x38", [])]),
);
compare(withBlocks([blk("0x10", "0x20", ["0x99"])]), withBlocks([blk("0x10", "0x20", [])]));
compare(withBlocks([blk("0x10", "0x10", [])]), withBlocks([]));
compare(withBlocks([blk("0x10", "0x20", []), blk("0x10", "0x30", [])]), withBlocks([]));
compare(withBlocks([blk("0x20", "0x30", ["0x10"]), blk("0x10", "0x20", ["0x20"])]), withBlocks([blk("0x10", "0x20", ["0x20"]), blk("0x20", "0x30", ["0x10"])]));
compare(withBlocks([blk("0xZZ", "0x20", [])]), withBlocks([]));

// ---- identity: locals ordering (UTF-16 code unit order) and signature
const withLocals = (locals, signature) =>
  mod(
    ev(3),
    (d) => {
      d.procedure.locals = locals.map((description) => ({ description, provenance: "synthetic" }));
      d.procedure.signature = signature;
    },
    { raw: undefined },
  );
compare(withLocals(["～", "\u{1F600}", "a"], "void f()"), withLocals(["a", "\u{1F600}", "～"], "void f()"));
compare(withLocals(["a"], "void f()"), withLocals(["a"], null));

// ---- limitations: merged, prefixed and ordered by code point
compare(
  mod(ev(3), (d) => (d.limitations = ["～ tail", "\u{1F600} face", "shared"]), { raw: undefined, limitations: ["\u{1F601} left only", "shared"] }),
  mod(ev(3), (d) => (d.limitations = ["shared", "～ tail"]), { raw: undefined, limitations: ["shared"] }),
);

// ---- input and integrity failures
add("compare_functions", { left: ev(2) });
add("compare_functions", { left: ev(2), right: ev(2), extra: 1 });
compare({ kind: "retained-evidence", evidence_id: ev(2).evidence_id }, ev(2));
compare({ ...ev(2), evidence_id: "ev_" + "0".repeat(64) }, ev(2));
compare({ ...ev(2), evidence_id: "EV_" + "0".repeat(64) }, ev(2));
compare({ ...ev(2), normalized_result: { ...ev(2).normalized_result, pseudocode: "tampered" } }, ev(2));
compare(ev(2), { ...ev(9), analysis_profile: { ...ev(9).analysis_profile, digest: "0".repeat(64) } });
compare(ev(2), { ...ev(9), provider: { ...ev(9).provider, version: "other" } });
compare(mk(ev(2), { operation: "binary_overview" }), c2);
compare(c2, mk(ev(2), { predicate: "rea.other" }));
compare(mk(ev(2), { noSubject: true }), c2);
const bad = (edit) => mod(ev(3), edit, { raw: undefined });
compare(bad(() => {}), mk(ev(3), { result: {} }));
compare(bad((d) => (d.pseudocode = 5)), c2);
compare(c2, bad((d) => (d.extra_key = 1)));
compare(c2, bad((d) => delete d.native_api));
compare(c2, bad((d) => (d.procedure.body = { available: true, provenance: "p", ranges: [{ start: "0x1", end: "0x3" }], total_bytes: 9, span_bytes: 3, non_contiguous: false, contains_entry: false })));
compare(c2, bad((d) => (d.procedure.body = { available: "maybe" })));
compare(c2, bad((d) => (d.callers = [{ address: "0x1", name: 7, classification: null, body: { available: false, reason: "r" } }])));
compare(c2, bad((d) => (d.comments = [{ address: "0x1", kind: "other", text: "x" }])));
compare(c2, bad((d) => (d.basic_blocks = [{ start: "0x1", end: "0x2" }])));

// nested shape failures, in zod issue order
compare({ ...c2, provider: { ...c2.provider, id: "" } }, c2);
compare({ ...c2, subject: { ...c2.subject, format: "bogus" } }, c2);
compare({ ...c2, subject: { ...c2.subject, digest: { sha256: "XYZ" } } }, c2);
compare({ ...c2, limitations: [1, "ok"] }, c2);
compare({ ...c2, locations: [{ kind: "zzz" }] }, c2);
compare({ ...c2, locations: [{ kind: "file-offset", offset: -1 }] }, c2);
compare({ ...c2, parameters: [] }, c2);
compare({ ...c2, evidence_links: ["x"] }, c2);
compare({ ...c2, confidence: "weird", authority: 4 }, { ...c2, environment: { id: "e", platform: "p", architecture: "a", isolation: "none" } });
compare({ ...c2, environment: { id: "", platform: "p" } }, c2);
compare({ ...c2, analysis_profile: { ...ev(2).analysis_profile, parameters: undefined } }, { ...c2, extra: true });
compare({ ...c2, analysis_profile: { ...ev(2).analysis_profile, digest: "A".repeat(64) } }, 5);
compare(c2, null);

// ---- build_call_path
const real =[ev(5), ev(2), ev(1), ev(3), ev(4), ev(6), ev(7)];
path_(real, "0x4011d5", "0x401146"); // found, via engine_branch
path_([ev(5), ev(2), ev(1)], "0X004011D5", "0x00401146"); // found, frontier incomplete, input normalized
path_([ev(2)], "0x401168", "0x401168"); // zero hops
path_(real, "0x4011d5", "0x401214"); // callers are not edges: goal main unreachable
path_([ev(3)], "0x401193", "0x401146"); // exhaustive, not found
path_([ev(2)], "0x401146", "0x401168"); // no Evidence for the start
path_([ev(2)], "0x401168", "0x999999"); // goal never seen
path_([ev(2), ev(9)], "0x401168", "0x401146"); // duplicate function Evidence
path_([ev(2), ev(2)], "0x401168", "0x401146"); // same record twice

const A = fn(ev(3), "0x1000", "fn_a", [["0x2000", "fn_b"], ["0x3000", "fn_c"], ["0x5000", "fn_e"]]);
const B = fn(ev(3), "0x2000", "fn_b", [["0x4000", "fn_d"]]);
const C = fn(ev(3), "0x3000", "fn_c", [["0x4000", "fn_d"]]);
const D = fn(ev(3), "0x4000", "fn_d", [["0x1000", "fn_a"]]);
const E = fn(ev(3), "0x5000", "fn_e", [["0x6000", "fn_f"]]);
const F = fn(ev(3), "0x6000", "fn_f", [["0x4000", "fn_d"]]);
retain([A, B, C, D, E, F]);
path_([A, B, C, D, E, F], "0x1000", "0x4000"); // two shortest paths, detour ignored
path_([A, B, C, D, E, F], "0x4000", "0x6000"); // through the cycle back to A
path_([D, A, B, C, E, F], "0x1000", "0x6000"); // order of functions is irrelevant
path_([A, B, C], "0x1000", "0x4000"); // frontier: no Evidence for fn_d / fn_e

const Dh = fn(ev(3), "0x4000", "fn_d", [], { provider: HOPPER, profile: null });
retain([A, Dh]);
path_([A, Dh], "0x1000", "0x4000"); // mixed providers
const Dx = fn(ev(3), "0x4000", "fn_d", [], { sha: "cd".repeat(32) });
retain([A, Dx]);
path_([A, Dx], "0x1000", "0x4000"); // mixed subjects
path_([{ ...ev(2), normalized_result: { ...ev(2).normalized_result, pseudocode: "tampered" } }], "0x401168", "0x401146"); // retained id, altered content
const comparison = createEvidence(undefined, FUNCTION_COMPARISON_PROVIDER, {
  predicateType: "rea.function-comparison",
  operation: "compare_functions",
  parameters: { left_evidence_id: ev(2).evidence_id, right_evidence_id: ev(2).evidence_id },
  result: JSON.parse(JSON.stringify(compareFunctions(ev(2), ev(2)))),
  confidence: "derived",
  authority: "analyst-inference",
  limitations: compareFunctions(ev(2), ev(2)).limitations,
  evidenceLinks: [ev(2).evidence_id, ev(2).evidence_id],
});
path_([comparison], "0x401168", "0x401146"); // retained, but not analyze_function Evidence

// address spaces and per-space normalization
const S1 = fn(ev(3), "a%2fb:0X1000", "sp_a", [["a%2fb:0x2000", "sp_b"]]);
const S2 = fn(ev(3), "a%2Fb:0x2000", "sp_b", []);
retain([S1, S2]);
path_([S1, S2], "a%2fb:0x1000", "a%2Fb:0X2000");
const Bad = fn(ev(3), "0x7000", "bad", [["nowhere", "x"]]);
retain([Bad, A]);
path_([Bad], "0x7000", "0x1");

// input failures
path_([ev(2)], "401168", "0x401146");
path_([], "0x401168", "0x401146");
add("build_call_path", { functions: [ev(2)], start: { address: "0x401168" } });
add("build_call_path", { functions: [ev(2)], start: { address: "0x401168", extra: 1 }, goal: { address: "0x1" } });
add("build_call_path", { functions: [{ kind: "retained-evidence", evidence_id: ev(2).evidence_id }], start: { address: "0x1" }, goal: { address: "0x2" } });

add("build_call_path", { functions: "nope", start: { address: 1 }, goal: { address: "0x2", extra: 1 }, other: 1 });
add("build_call_path", { functions: [ev(2), { ...c2, provider: { ...c2.provider, id: "" } }], start: {}, goal: { address: "0x1" } });
add("build_call_path", { functions: [{ ...c2, analysis_profile: { ...ev(2).analysis_profile, digest: "0".repeat(64) } }], start: { address: "0x1" }, goal: { address: "0x2" } });
add("build_call_path", { start: { address: "0x1" } });
add("build_call_path", {});

add("list_unknowns", {});

fs.writeFileSync(process.argv[2], JSON.stringify(calls));
console.log(`${calls.length} calls`);
