// Test double for the oracle guard test: one answer per file, but the second line is cut off.
// usage: node fake_unreadable.mjs <list-file>
import { readFileSync } from "node:fs";

const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
paths.forEach((path, index) => {
  const line = JSON.stringify({ path, ok: false });
  console.log(index === 1 ? line.slice(0, -3) : line);
});
