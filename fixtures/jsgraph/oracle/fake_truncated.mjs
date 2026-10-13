// Test double for the oracle guard test: exits successfully after answering only two files,
// like an oracle whose stdout silently stops.
// usage: node fake_truncated.mjs <list-file>
import { readFileSync } from "node:fs";

const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const path of paths.slice(0, 2)) console.log(JSON.stringify({ path, ok: false }));
