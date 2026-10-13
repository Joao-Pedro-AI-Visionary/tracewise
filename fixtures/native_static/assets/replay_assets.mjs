// Runs the ORIGINAL REA asset-catalog analysis (artifacts/apple/AppleAssetCatalogAnalysis) on a
// bundle with an injected `assetutil`: the injected tool returns the records tracewise's own
// catalog reader produced for that exact file (looked up by content digest). That isolates the
// parts REA computes itself (discovery, hashing, paging, the Interface Builder key join, the
// error behaviour) from the catalog decoding, which REA delegates to macOS.
//
// usage: node replay_assets.mjs <bundle> <targetSha256> <page.json> <records-by-sha256.json> <out.json>

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const REA = "/workspace/rea-map/src/dist";
const { analyzeAppleAssetCatalogs } = await import(`${REA}/artifacts/apple/AppleAssetCatalogAnalysis.js`);

const [bundlePath, targetSha256, pagePath, recordsPath, out] = process.argv.slice(2);
const page = JSON.parse(readFileSync(pagePath, "utf8"));
const records = JSON.parse(readFileSync(recordsPath, "utf8"));

const result = await analyzeAppleAssetCatalogs({
  bundlePath,
  targetSha256,
  environment: {},
  page,
  runAssetUtil: async (path) => {
    const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
    const text = records[digest];
    if (text === undefined) throw Object.assign(new Error("unknown catalog"), { code: "EINVAL" });
    return text;
  },
}).then(
  (value) => ({ ok: true, value }),
  (error) => ({
    ok: false,
    error: { name: error.constructor.name, reason: error.reason ?? null, message: error.message },
  }),
);
writeFileSync(out, JSON.stringify(result, null, 1));
