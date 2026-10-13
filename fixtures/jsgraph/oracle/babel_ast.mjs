// Prints the REA/Babel parse of every file listed (one path per line) in <list-file>, one JSON line each.
// usage: REA_SRC=<rea checkout> node babel_ast.mjs <list-file>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reaSrc = process.env.REA_SRC ?? "/workspace/rea-map/src";
const { parseJavaScriptSource } = await import(
  pathToFileURL(`${reaSrc}/dist/domain/javascript/javascriptSourceParser.js`).href
);
const skip = new Set(["loc", "extra", "range", "leadingComments", "trailingComments", "innerComments", "tokens"]);
const replacer = (key, value) =>
  skip.has(key) ? undefined : typeof value === "bigint" ? value.toString() : value;
const paths = readFileSync(process.argv[2], "utf8").split("\n").filter((line) => line.length > 0);
for (const path of paths) {
  const source = readFileSync(path, "utf8");
  const file = parseJavaScriptSource(source, path);
  if (file === null) {
    console.log(JSON.stringify({ path, ok: false }));
    continue;
  }
  console.log(
    JSON.stringify(
      {
        path,
        ok: true,
        errors: file.errors.length,
        comments: file.comments.length,
        program: file.program,
      },
      replacer,
    ),
  );
}
