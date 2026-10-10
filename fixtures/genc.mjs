import { createEvidence } from "/workspace/rea-map/src/dist/domain/evidence.js";
import { createAnalysisProfile } from "/workspace/rea-map/src/dist/domain/analysisProfile.js";
import { createEvidenceBundle } from "/workspace/rea-map/src/dist/domain/evidenceBundle.js";
import { compareBundles } from "/workspace/rea-map/src/dist/domain/bundleComparison.js";
import * as RU from "/workspace/rea-map/src/dist/domain/residualUnknown.js";
import fs from "node:fs";
const prov = { id: "ghidra", name: "Ghidra", version: "11.1" };
const prof = createAnalysisProfile(prov, { decompiler: "default", timeout_s: 30, flags: ["a", "b"] });
const t = { path: "/tmp/x.elf", sha256: "1".repeat(64), format: "elf", architecture: "x86_64" };
const e1 = createEvidence(t, prov, { operation: "procedure_info", parameters: { address: "0x10" }, result: { name: "f" }, analysisProfile: prof });
const e2 = createEvidence(t, prov, { operation: "procedure_info", parameters: { address: "0x10" }, result: { name: "g" }, analysisProfile: prof });
const e3 = createEvidence(undefined, prov, { operation: "list_strings", parameters: {}, result: ["s"] });
const e4 = createEvidence(undefined, prov, { operation: "record_unknown", parameters: {}, result: null, confidence: "derived", authority: "analyst-inference" });
const e5 = createEvidence(undefined, prov, { operation: "update_unknown", parameters: {}, result: null, confidence: "derived", authority: "analyst-inference" });
const inp = RU.recordUnknownInputSchema.parse({ question: "Q?", severity: "medium", domain: "d", required_authority: null, required_confidence: "observed", required_environment: null, recommended_probes: [], relationships: [] });
const u1 = RU.createResidualUnknown(inp, e4.evidence_id, null);
const u2 = RU.updateResidualUnknown(u1, { unknown_id: u1.unknown_id, expected_revision: 1, status: "investigating", severity: "high", supporting_evidence_ids: [], contradicting_evidence_ids: [], required_authority: null, required_confidence: "observed", required_environment: null, recommended_probes: [], relationships: [], resolution: null }, e5.evidence_id);
const left = createEvidenceBundle([e1, e3, e4], [u1]);
const right = createEvidenceBundle([e2, e4, e5], [u1, u2]);
const cases = [
  { name: "unpaired", left, right, record_pairs: [] },
  { name: "paired", left, right, record_pairs: [{ left_evidence_id: e1.evidence_id, right_evidence_id: e2.evidence_id }] },
  { name: "identical", left, right: left, record_pairs: [] },
].map(c => ({ ...c, result: compareBundles(c.left, c.right, c.record_pairs) }));
fs.writeFileSync("profile_evidence_cases.json", JSON.stringify([{ name: "with_profile", evidence: e1 }, { name: "with_profile_2", evidence: e2 }], null, 2));
fs.writeFileSync("compare_bundles_cases.json", JSON.stringify(cases, null, 2));
console.log(cases.map(c => c.name + ":" + c.result.status));
