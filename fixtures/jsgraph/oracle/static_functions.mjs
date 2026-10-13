// Calls REA's static-layer functions directly, one JSON request per line of <request-file>, one JSON
// response per line on stdout (same order):
//   { op: "sourceMap", args: [sourceName, sourceRoot|null, mapPath] }
//       -> resolveJavaScriptSourceMapReference(...)
//   { op: "file", path }
//       -> { fingerprint, programFingerprint, exports }  of parseJavaScriptSource(file, path):
//          fingerprintJavaScriptAst(file), fingerprintJavaScriptAst(file.program), collectJavaScriptExports(file).values
//   { op: "sanitize", value } -> sanitizeEndpointCandidate(value)
// usage: REA_SRC=<rea checkout> node static_functions.mjs <request-file>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const load = (rel) => import(pathToFileURL(`${reaSrc}/dist/${rel}`).href);
const { resolveJavaScriptSourceMapReference } = await load("domain/javascript/javascriptSourceMapPaths.js");
const { fingerprintJavaScriptAst, collectJavaScriptExports } = await load("domain/javascript/javascriptAstFingerprint.js");
const { parseJavaScriptSource } = await load("domain/javascript/javascriptSourceParser.js");
const { sanitizeEndpointCandidate } = await load("domain/browserObservation.js");

const lines = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const line of lines) {
  const request = JSON.parse(line);
  try {
    if (request.op === "sourceMap") {
      console.log(JSON.stringify({ ok: true, result: resolveJavaScriptSourceMapReference(...request.args) }));
    } else if (request.op === "file") {
      const source = readFileSync(request.path, "utf8");
      const file = parseJavaScriptSource(source, request.path);
      if (file === null) {
        console.log(JSON.stringify({ ok: false }));
      } else {
        console.log(
          JSON.stringify({
            ok: true,
            result: {
              fingerprint: fingerprintJavaScriptAst(file),
              programFingerprint: fingerprintJavaScriptAst(file.program),
              exports: collectJavaScriptExports(file).values,
            },
          }),
        );
      }
    } else if (request.op === "sanitize") {
      console.log(JSON.stringify({ ok: true, result: sanitizeEndpointCandidate(request.value) }));
    } else {
      console.log(JSON.stringify({ ok: false, error: `unknown op ${request.op}` }));
    }
  } catch (error) {
    console.log(JSON.stringify({ ok: false, error: String(error) }));
  }
}
