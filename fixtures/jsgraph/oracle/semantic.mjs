// Prints REA's semantic IR and the two receiver classifiers, one JSON line per file listed in
// <list-file>:  { path, ok, ir, openReceivers: [[offset, fact]], electronBindings: [[offset, export]] }
// (a lighter sibling of layers.mjs for the semantic core: no static analysis).
//
// Lines are written with fs.writeSync: `console.log` to a pipe queues in memory while this
// synchronous loop never yields, so a slow reader (large corpora) starved and the queued output was
// lost.
// usage: REA_SRC=<rea checkout> node semantic.mjs <list-file>
import { readFileSync, writeSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const load = (rel) => import(pathToFileURL(`${reaSrc}/dist/${rel}`).href);
const { parseJavaScriptSource } = await load("domain/javascript/javascriptSourceParser.js");
const {
  analyzeParsedJavaScriptSemantics,
  classifyParsedJavaScriptOpenReceivers,
  classifyParsedJavaScriptElectronBindings,
} = await load("domain/javascript/javascriptSemanticAnalysis.js");

const emit = (value) => {
  const buffer = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  let offset = 0;
  while (offset < buffer.length) {
    try {
      offset += writeSync(1, buffer, offset, buffer.length - offset);
    } catch (error) {
      if (error.code !== "EAGAIN") throw error;
    }
  }
};

const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const path of paths) {
  const source = readFileSync(path, "utf8");
  const file = parseJavaScriptSource(source, path);
  if (file === null) {
    emit({ path, ok: false });
    continue;
  }
  emit({
    path,
    ok: true,
    ir: analyzeParsedJavaScriptSemantics(file),
    openReceivers: Array.from(classifyParsedJavaScriptOpenReceivers(file)),
    electronBindings: Array.from(classifyParsedJavaScriptElectronBindings(file)),
  });
}
