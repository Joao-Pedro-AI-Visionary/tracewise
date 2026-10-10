import { createEvidence, parseEvidence } from "/workspace/rea-map/src/dist/domain/evidence.js";
import { digestCanonicalValue } from "/workspace/rea-map/src/dist/domain/canonicalDigest.js";
import * as RU from "/workspace/rea-map/src/dist/domain/residualUnknown.js";
import fs from "node:fs";
const sha = "a".repeat(64);
const prov = { id: "hopper", name: "Hopper", version: "5.1" };
const cases = [];
const add = (name, target, provider, obs) => { const ev = createEvidence(target, provider, obs); cases.push({ name, evidence: ev }); };
add("minimal_no_subject", undefined, prov, { operation: "list_strings", parameters: {}, result: [] });
add("with_subject", { path: "/tmp/bin/a.out", sha256: sha, format: "mach-o", architecture: "arm64" }, prov,
  { operation: "procedure_info", parameters: { address: "0x1000", n: 3 }, result: { name: "main", size: 1.5e21, f: 0.1, neg: -0, big: 123456789012345680000, small: 1e-7, int: 42 } });
add("unicode_keys_and_strings", { path: "x.apk", sha256: "b".repeat(64), format: "apk" }, { id: "jadx", name: "JADX", version: null },
  { operation: "op", parameters: { "é": 1, "a": 2, "\u{1F600}": 3, "\uFF61": 4, "Z": 5 }, result: "ção \u0007 \"q\" \\ / \n\t\u2028 \u{1F600} \u0000 \u001f" ,
    confidence: "inferred", authority: "analyst-inference", limitations: ["l1"],
    locations: [{ kind: "address", address: "0x10" }, { kind: "address-range", start: "0x1", end: "0x2" }, { kind: "artifact-path", path: "a/b" }, { kind: "file-offset", offset: 7 }, { kind: "file-offset-range", start: 1, end: 9 }],
    evidenceLinks: ["ev_" + "c".repeat(64)] });
add("derived_env_raw", undefined, prov, { operation: "trace", parameters: { nested: { b: [1, { z: null, a: true }], a: false } }, result: { x: [] }, rawResult: { raw: "1" },
  confidence: "derived", authority: "controlled-replay", environment: { id: "e1", platform: "linux", architecture: "x86_64", isolation: "container" }, subjectUnavailableReason: "no artifact", predicateType: "custom.pred" });
const canon = [ {b:1,a:[1,2,{d:null,c:"x"}]}, [0.000001, 1e21, 1e-7, 5e-324, 1.7976931348623157e308, 100, -1.25], "\u{10000}\uFFFF", {"\uD800\uDC00":1, "\uFFFF":2} ]
  .map(v => ({ value: v, sha256: digestCanonicalValue(v) }));
// unknowns
console.error(Object.keys(RU));
fs.writeFileSync("evidence_cases.json", JSON.stringify(cases, null, 2));
fs.writeFileSync("canonical_cases.json", JSON.stringify(canon, null, 2));
for (const c of cases) parseEvidence(JSON.parse(JSON.stringify(c.evidence)));
console.log("ok", cases.length);
