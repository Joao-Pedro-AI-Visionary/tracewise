// Like layers.mjs but only for the static layer: one JSON line per file listed in <list-file>:
//   { path, ok, static, openReceivers: [[offset, fact]], electronBindings: [[offset, export]] }
// It skips the (large, slow) semantic IR, so big bundles stay cheap, and writes with synchronous
// writes so multi-megabyte lines are never lost on a pipe.
// usage: REA_SRC=<rea checkout> node static_layer.mjs <list-file>
import { readFileSync, writeSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const load = (rel) => import(pathToFileURL(`${reaSrc}/dist/${rel}`).href);
const { parseJavaScriptSource } = await load("domain/javascript/javascriptSourceParser.js");
const { analyzeParsedJavaScriptStaticSource } = await load("domain/javascript/javascriptStaticAnalysis.js");
const { classifyParsedJavaScriptOpenReceivers, classifyParsedJavaScriptElectronBindings } = await load(
  "domain/javascript/javascriptSemanticAnalysis.js",
);

const writeAll = (text) => {
  const buffer = Buffer.from(text, "utf8");
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
    writeAll(`${JSON.stringify({ path, ok: false })}\n`);
    continue;
  }
  const openReceivers = classifyParsedJavaScriptOpenReceivers(file);
  const electronBindings = classifyParsedJavaScriptElectronBindings(file);
  const staticAnalysis = analyzeParsedJavaScriptStaticSource(source, file, openReceivers);
  writeAll(
    `${JSON.stringify({
      path,
      ok: true,
      static: staticAnalysis,
      openReceivers: Array.from(openReceivers),
      electronBindings: Array.from(electronBindings),
    })}\n`,
  );
}
