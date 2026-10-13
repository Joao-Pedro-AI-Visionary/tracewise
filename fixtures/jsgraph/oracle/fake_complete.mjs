// Test double for the oracle guard test: answers every listed file with one readable line.
// usage: node fake_complete.mjs <list-file>
import { readFileSync } from "node:fs";

const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const path of paths) console.log(JSON.stringify({ path, ok: false }));
