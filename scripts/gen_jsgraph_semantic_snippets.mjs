// Lifts the JavaScript sources embedded in REA's own unit tests (domain/javascript and
// application/javascript `*.test.ts`) into one deterministic JSON corpus used by the jsgraph
// layer tests: fixtures/jsgraph/semantic/snippets.json = [{ name, source }].
//
// Every string literal and every substitution-free template literal that Babel parses with REA's
// plugins becomes a snippet; sources containing `return` also get the
// `export function result() { ... }` wrapper REA's value tests use. The oracle (compiled REA)
// supplies the expected analysis for each snippet, so nothing is hand-written.
//
// usage: REA_SRC=/workspace/rea-map/src node scripts/gen_jsgraph_semantic_snippets.mjs
import { createRequire } from "node:module";
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const require = createRequire(join(reaSrc, "package.json"));
const { parse } = require("@babel/parser");

const roots = ["src/domain/javascript", "src/application/javascript"].map((dir) => join(reaSrc, dir));
const files = roots.flatMap((root) =>
  readdirSync(root)
    .filter((name) => name.endsWith(".test.ts"))
    .sort()
    .map((name) => ({ name, path: join(root, name) })),
);

const parses = (source) => {
  try {
    parse(source, {
      sourceType: "unambiguous",
      errorRecovery: true,
      attachComment: false,
      plugins: ["decorators-legacy", "jsx", ["typescript", { dts: false }]],
    });
    return true;
  } catch {
    return false;
  }
};

const interesting = (text) =>
  text.length >= 8 && text.length <= 4000 && /[=;({]|=>|import |export /u.test(text) && /[A-Za-z_$]/u.test(text);

const literals = (node, out) => {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) literals(item, out);
    return;
  }
  if (node.type === "StringLiteral") out.push(node.value);
  else if (node.type === "TemplateLiteral") {
    if (node.expressions.length === 0 && node.quasis[0]?.value.cooked != null) out.push(node.quasis[0].value.cooked);
    // Keep the static pieces of a template with substitutions as separate candidates too.
    else for (const quasi of node.quasis) if (quasi.value.cooked != null) out.push(quasi.value.cooked);
  }
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "extra") continue;
    literals(node[key], out);
  }
};

const seen = new Set();
const snippets = [];
const add = (source) => {
  if (seen.has(source) || !parses(source)) return;
  seen.add(source);
  snippets.push(source);
};

for (const { path } of files) {
  const text = readFileSync(path, "utf8");
  let ast;
  try {
    ast = parse(text, {
      sourceType: "module",
      errorRecovery: true,
      attachComment: false,
      plugins: ["typescript"],
    });
  } catch {
    continue;
  }
  const found = [];
  literals(ast.program, found);
  for (const candidate of found) {
    if (!interesting(candidate)) continue;
    add(candidate);
    if (/\breturn\b/u.test(candidate)) add(`export function result() { ${candidate} }`);
  }
}

const output = snippets.map((source, index) => ({
  name: `snippet_${String(index).padStart(4, "0")}.${/\bimport\b|\bexport\b/u.test(source) ? "mjs" : "js"}`,
  source,
}));
const target = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "jsgraph", "semantic", "snippets.json");
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify(output, null, 1)}\n`);
console.log(`${output.length} snippets from ${files.length} test files -> ${target}`);
