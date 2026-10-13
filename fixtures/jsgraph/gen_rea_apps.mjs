// Regenerates the REA-derived application fixtures under fixtures/jsgraph/rea/ from the REA test
// fixtures (https://github.com/morluto/rea, MIT, commit 0fa0b04; see fixtures/jsgraph/ATTRIBUTION.md).
// usage: REA_SRC=<rea checkout> node --experimental-strip-types fixtures/jsgraph/gen_rea_apps.mjs
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "rea");
const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const fixture = (name) => import(pathToFileURL(`${reaSrc}/tests/fixtures/${name}.ts`).href);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const { writeJavaScriptArtifactFixture, writeVersionedJavaScriptApplicationFixtures } =
  await fixture("javascriptArtifactApplication");
await mkdir(join(out, "artifact"), { recursive: true });
await writeJavaScriptArtifactFixture(join(out, "artifact"));
const versions = await writeVersionedJavaScriptApplicationFixtures(join(out, "versions"));
void versions;

const { writeElectronBoundaryFixture } = await fixture("electronBoundaryApplication");
await mkdir(join(out, "electron-boundary"), { recursive: true });
await writeElectronBoundaryFixture(join(out, "electron-boundary"));

// TypeScript/JSX dialect cases (javascriptArtifactTypeScriptDialect.ts).
const dialect = join(out, "ts-dialect");
await mkdir(dialect, { recursive: true });
await writeFile(join(dialect, "dep.js"), "export const dependency = true;");
for (const [path, source] of [
  ["assertion.ts", 'const value = <number>1;\nimport "./dep.js";'],
  ["wrapped.ts", 'const value = <unknown>require("./dep.js");'],
  ["as.ts", 'const value = 1 as number;\nimport "./dep.js";'],
  ["wrapped-as.ts", 'const value = require("./dep.js") as unknown;'],
  ["generic.ts", 'const identity = <T>(value: T): T => value;\nimport "./dep.js";'],
  ["component.tsx", 'const element = <section />;\nimport "./dep.js";'],
  ["component.d.tsx", 'const element = <section />;\nimport "./dep.js";'],
  ["component.jsx", 'const element = <section />;\nimport "./dep.js";'],
]) await writeFile(join(dialect, path), source);

// UTF-8 BOM cases (javascriptArtifactBom.ts).
const bom = join(out, "bom");
await mkdir(bom, { recursive: true });
await writeFile(join(bom, "dep.js"), "export const dependency = 1;");
for (const [path, source] of [
  ["import.js", 'import "./dep.js";'],
  ["require.cjs", 'require("./dep.js");'],
  ["index.html", '<script src="./dep.js"></script>'],
]) await writeFile(join(bom, path), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(source)]));
console.log("written to", out);
