// Prints REA's per-file analysis layers, one JSON line per file listed in <list-file>:
//   { path, ok, static, ir, openReceivers: [[offset, fact]], electronBindings: [[offset, export]] }
// `static` = AST-only static analysis; `ir` = full semantic IR (before graph projection).
// usage: REA_SRC=<rea checkout> node layers.mjs <list-file>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const load = (rel) => import(pathToFileURL(`${reaSrc}/dist/${rel}`).href);
const { parseJavaScriptSource } = await load("domain/javascript/javascriptSourceParser.js");
const { analyzeParsedJavaScriptStaticSource } = await load("domain/javascript/javascriptStaticAnalysis.js");
const {
  analyzeParsedJavaScriptSemantics,
  classifyParsedJavaScriptOpenReceivers,
  classifyParsedJavaScriptElectronBindings,
} = await load("domain/javascript/javascriptSemanticAnalysis.js");

const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const path of paths) {
  const source = readFileSync(path, "utf8");
  const file = parseJavaScriptSource(source, path);
  if (file === null) {
    console.log(JSON.stringify({ path, ok: false }));
    continue;
  }
  const openReceivers = classifyParsedJavaScriptOpenReceivers(file);
  const electronBindings = classifyParsedJavaScriptElectronBindings(file);
  const staticAnalysis = analyzeParsedJavaScriptStaticSource(source, file, openReceivers);
  const ir = analyzeParsedJavaScriptSemantics(file);
  console.log(
    JSON.stringify({
      path,
      ok: true,
      static: staticAnalysis,
      ir,
      openReceivers: Array.from(openReceivers),
      electronBindings: Array.from(electronBindings),
    }),
  );
}
