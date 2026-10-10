import { createEvidenceBundle, serializeEvidenceBundle, parseEvidenceBundle } from "/workspace/rea-map/src/dist/domain/evidenceBundle.js";
import fs from "node:fs";
const ev = JSON.parse(fs.readFileSync("evidence_cases.json")).map(c => c.evidence);
const b = createEvidenceBundle(ev, []);
parseEvidenceBundle(b);
fs.writeFileSync("rea_bundle.json", serializeEvidenceBundle(b));
console.log("bundle ok", b.records.length);
