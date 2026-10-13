// Differential cases for the Rust port of jsdiff's `diffLines` (crates/engines/src/derived/diff.rs).
//
//   REA_ROOT=<rea checkout> node fixtures/engines/gen_diff_cases.mjs fixtures/engines/oracle_diff_lines.json.gz
//
// Texts are drawn from a tiny line alphabet with a seeded generator so repeated lines and
// ties between equally short edit scripts are frequent. Each case records the complete
// component list jsdiff returns, which is stricter than the counts the tool reports.
import fs from "node:fs";
import zlib from "node:zlib";
import path from "node:path";
import { pathToFileURL } from "node:url";

const reaRoot = process.env.REA_ROOT ?? "/workspace/rea-map/src";
const { diffLines } = await import(pathToFileURL(path.join(reaRoot, "node_modules", "diff", "libesm", "index.js")).href);

let state = 0x9e3779b9;
const random = () => {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(random() * list.length)];

const alphabets = [["a", "b"], ["a", "b", "c", "d"], ["x", "", "y", "  z", "x "], ["a", "b", "c", "d", "e", "f", "g", "h"]];
const make = (alphabet, length) => {
  const eol = pick(["\n", "\n", "\n", "\r\n"]);
  const lines = Array.from({ length }, () => pick(alphabet));
  let text = lines.join(eol);
  if (length > 0 && random() < 0.7) text += eol;
  return text;
};
const mutate = (text, alphabet) => {
  const lines = text.split("\n");
  const edits = 1 + Math.floor(random() * 4);
  for (let i = 0; i < edits; i += 1) {
    const at = Math.floor(random() * (lines.length + 1));
    const kind = random();
    if (kind < 0.4) lines.splice(at, 1);
    else if (kind < 0.8) lines.splice(at, 0, pick(alphabet));
    else lines[at] = pick(alphabet);
  }
  return lines.join("\n");
};

const cases = [];
const push = (oldText, newText) => {
  const changes = diffLines(oldText, newText, { timeout: 5000, maxEditLength: 100000 });
  cases.push({
    old: oldText,
    new: newText,
    changes: changes.map(({ count, added, removed }) => [count, Boolean(added), Boolean(removed)]),
  });
};
for (let n = 0; n < 700; n += 1) {
  const alphabet = pick(alphabets);
  const length = Math.floor(random() * 40);
  const oldText = make(alphabet, length);
  push(oldText, random() < 0.5 ? mutate(oldText, alphabet) : make(alphabet, Math.floor(random() * 40)));
}
for (const [a, b] of [["", ""], ["", "a\n"], ["a\n", ""], ["a", "a\n"], ["a\n", "a"], ["a\r\nb", "a\nb"], ["\n\n\n", "\n"], ["a\n\nb\n", "a\nb\n"]]) push(a, b);
const compact = Buffer.from(JSON.stringify(cases));
// A `.gz` destination is written gzip-compressed (the committed form).
fs.writeFileSync(process.argv[2], process.argv[2].endsWith(".gz") ? zlib.gzipSync(compact, { level: 9 }) : compact);
console.log(`${cases.length} cases`);
