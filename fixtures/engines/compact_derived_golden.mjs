// Compacts a raw `oracle_session.py` output for the derived tools into the committed golden:
//
//   node fixtures/engines/compact_derived_golden.mjs <raw.json> fixtures/engines/oracle_derived_session.json.gz
//
// Inline Evidence records are stored once in an `evidence` table and referenced from the call
// arguments as {"$evidence": "<key>"}; success results keep only `structuredContent` (the
// text content repeats it), failures keep the error text. Records are keyed by exact content,
// so a tampered copy of a record never shares an entry with the original.
import fs from "node:fs";
import zlib from "node:zlib";

const raw = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const table = new Map();
const keyOf = (record) => {
  const text = JSON.stringify(record);
  if (!table.has(text)) table.set(text, `e${table.size}`);
  return table.get(text);
};
const looksLikeEvidence = (v) =>
  v !== null &&
  typeof v === "object" &&
  !Array.isArray(v) &&
  typeof v.evidence_id === "string" &&
  "provider" in v &&
  "normalized_result" in v;
const shrink = (v) => {
  if (looksLikeEvidence(v)) return { $evidence: keyOf(v) };
  if (Array.isArray(v)) return v.map(shrink);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shrink(x)]));
  return v;
};
const calls = raw.map(({ name, arguments: args, result }) => ({
  name,
  arguments: shrink(args),
  result: result.isError
    ? { isError: true, text: result.content.map((c) => c.text).join("") }
    : { isError: false, structuredContent: result.structuredContent },
}));
const evidence = Object.fromEntries([...table].map(([text, key]) => [key, JSON.parse(text)]));
const compact = Buffer.from(JSON.stringify({ evidence, calls }));
// A `.gz` destination is written gzip-compressed (the committed form).
fs.writeFileSync(process.argv[3], process.argv[3].endsWith(".gz") ? zlib.gzipSync(compact, { level: 9 }) : compact);
console.log(`${calls.length} calls, ${table.size} distinct inline records`);
