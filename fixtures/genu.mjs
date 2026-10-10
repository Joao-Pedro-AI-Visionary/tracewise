import * as RU from "/workspace/rea-map/src/dist/domain/residualUnknown.js";
import fs from "node:fs";
const ev = c => "ev_" + c.repeat(64);
const input = RU.recordUnknownInputSchema.parse({ question: "  What   does\tthe  ção \u{1F600} parser do? ", severity: "high", domain: "parsing",
  supporting_evidence_ids: [ev("b"), ev("a"), ev("b")], required_authority: null, required_confidence: "observed", required_environment: null,
  recommended_probes: [{ operation: "procedure_info", rationale: "check" }], relationships: [{ type: "related-to", unknown_id: "unk_" + "f".repeat(64) }, { type: "depends-on", unknown_id: "unk_" + "e".repeat(64) }] });
const r1 = RU.createResidualUnknown(input, ev("1"), "d".repeat(64));
const r1b = RU.createResidualUnknown({ ...input, contradicting_evidence_ids: [ev("c")] }, ev("2"), null);
const r2 = RU.updateResidualUnknown(r1, RU.updateUnknownInputSchema.parse({ unknown_id: r1.unknown_id, expected_revision: 1, status: "resolved", severity: "low",
  supporting_evidence_ids: [ev("a")], contradicting_evidence_ids: [], required_authority: "shipped-artifact", required_confidence: "derived",
  required_environment: { id: null, platform: "linux", architecture: null, isolation: "process" }, recommended_probes: [], relationships: [],
  resolution: { disposition: "verified", rationale: "seen", evidence_ids: [ev("a")] } }), ev("0"));
fs.writeFileSync("unknown_cases.json", JSON.stringify({ record_input: input, mutation_evidence_id: ev("1"), scope_digest: "d".repeat(64), revision1: r1, contradicted_no_scope: r1b, revision2: r2, update_mutation_evidence_id: ev("0") }, null, 2));
console.log(r1.unknown_id, r2.revision_digest);
