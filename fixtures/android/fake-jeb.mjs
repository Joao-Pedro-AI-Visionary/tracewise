// Test double for a JEB client that serves MCP over streamable HTTP.
//
//   node fake-jeb.mjs <mode>
//
// Binds 127.0.0.1 on an ephemeral port and prints the endpoint URL on its first
// stdout line. No dependencies. It implements only what REA's JEB provider uses:
// initialize, notifications/initialized, tools/list and tools/call for
// get_client_information, open_project, list_units and decompile_code_item.
// REA never installs or launches JEB; this stands in for the commercial engine.
import { createServer } from "node:http";

const mode = process.argv[2] ?? "normal";
// Transport-level failure modes: http-500, redirect, garbage-init, http-500-call, rpc-error-call, hang-call, huge-call.
const UNITS = [
  { unit_path: "/Bytecode/classes.dex", unit_type: "dex" },
  { unit_path: "/Bytecode/classes2.dex", unit_type: "dex" },
  { unit_path: "/Manifest", unit_type: "xml" },
  { unit_path: "/Resources", unit_type: "arsc" },
  { unit_path: "/Certificate", unit_type: "cert" },
];

const refusal = () => {
  if (mode === "refuse") return { success: false, message: "No project is open" };
  if (mode === "refuse-nested") return { success: false, error: { code: "E_NOPROJECT", message: "nested refusal", recovery_tool: "open_project" } };
  if (mode === "refuse-code-only") return { success: false, error: { code: "E_ONLY_CODE" } };
  if (mode === "refuse-empty") return { success: false };
  return null;
};

const tool = (name, args) => {
  const refused = refusal();
  if (refused !== null) return { structuredContent: refused };
  if (mode === "no-success-field") return { structuredContent: { version: "4.0" } };
  if (mode === "text-json") {
    const inner = engine(name, args);
    return { content: [{ type: "text", text: JSON.stringify(inner.structuredContent) }] };
  }
  if (mode === "text-plain") return { content: [{ type: "text", text: "just words" }] };
  if (mode === "text-string-json") return { content: [{ type: "text", text: JSON.stringify("a string") }] };
  if (mode === "text-two-blocks") return { content: [{ type: "text", text: "{}" }, { type: "text", text: "{}" }] };
  if (mode === "tool-error-text") return { isError: true, content: [{ type: "text", text: "kaboom" }] };
  if (mode === "tool-error-json") return { isError: true, content: [{ type: "text", text: JSON.stringify({ success: false, message: "refused in text" }) }] };
  if (mode === "empty-content") return { content: [] };
  return engine(name, args);
};

const engine = (name, args) => {
  switch (name) {
    case "get_client_information":
      if (mode === "no-version") return { structuredContent: { success: true, message: "no version here" } };
      if (mode === "malformed") return { structuredContent: { success: true, version: 7 } };
      if (mode === "gui") return { structuredContent: { success: true, version: "5.2.0", gui_client: true, startup_ts: 1700000123, message: "GUI client" } };
      return { structuredContent: { success: true, version: "4.31.0.202401010000", gui_client: false, startup_ts: 1700000000, message: null, extra_field: "kept in raw_result" } };
    case "open_project":
      if (mode === "malformed-open") return { structuredContent: { success: true, input_files: [{ file_name: 5 }] } };
      if (mode === "bare-open") return { structuredContent: { success: true } };
      return {
        structuredContent: {
          success: true,
          name: "ApiDemos",
          creation_datetime: "2024-01-01T00:00:00Z",
          input_files: [{ file_name: String(args.file_path).split("/").pop(), file_size: 6521217, contents_sha256_hash: "a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686" }],
          units: UNITS.slice(0, 2),
        },
      };
    case "list_units": {
      const filtered = UNITS.filter((u) => (args.filter === undefined ? true : args.filter === "*" || u.unit_path.includes(String(args.filter).replaceAll("*", ""))))
        .filter((u) => (args.parent_unit_path === undefined ? true : u.unit_path.startsWith(String(args.parent_unit_path))));
      const page = mode === "full-page" ? UNITS.concat(UNITS).slice(args.index, args.index + args.count) : filtered.slice(args.index, args.index + args.count);
      return { structuredContent: { success: true, units: page } };
    }
    case "decompile_code_item":
      if (mode === "malformed-decompile") return { structuredContent: { success: true } };
      return { structuredContent: { success: true, text: `// ${args.item_kind} ${args.item_address} in ${args.unit_path ?? "<first code unit>"}\nclass A { }\n` } };
    default:
      return { isError: true, content: [{ type: "text", text: `unknown tool ${name}` }] };
  }
};

const respond = (res, status, body, headers = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
};

const server = createServer((req, res) => {
  if (req.method === "GET") return void res.writeHead(405).end();
  if (req.method === "DELETE") return void res.writeHead(200).end();
  if (req.method !== "POST" || !req.url?.startsWith("/mcp")) return void res.writeHead(404).end();
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (mode === "http-500") return void respond(res, 500, { oops: "boom" });
    if (mode === "redirect") return void res.writeHead(302, { location: "http://127.0.0.1:1/elsewhere" }).end();
    if (mode === "garbage-init" && message.method === "initialize") {
      res.writeHead(200, { "content-type": "text/plain" });
      return void res.end("hello, not json-rpc");
    }
    if (message.id === undefined) return void res.writeHead(202).end();
    if (message.method === "tools/call") {
      if (mode === "hang-call") return; // never answers: the caller must be able to give up
      if (mode === "huge-call")
        return void respond(res, 200, { jsonrpc: "2.0", id: message.id, result: { structuredContent: { success: true, pad: "a".repeat(20 * 1024 * 1024) } } });
      if (mode === "http-500-call") return void respond(res, 500, { oops: "call failed" });
      if (mode === "rpc-error-call")
        return void respond(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32000, message: "engine exploded" } });
    }
    let result;
    if (message.method === "initialize")
      result = { protocolVersion: message.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "fake-jeb", version: "1.0" } };
    else if (message.method === "tools/list")
      result = { tools: ["get_client_information", "open_project", "list_units", "decompile_code_item"].map((name) => ({ name, inputSchema: { type: "object" } })) };
    else if (message.method === "tools/call") result = tool(message.params.name, message.params.arguments ?? {});
    else return void respond(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } });
    const envelope = { jsonrpc: "2.0", id: message.id, result };
    const headers = message.method === "initialize" ? { "mcp-session-id": "fake-session" } : {};
    if (mode === "sse") {
      res.writeHead(200, { "content-type": "text/event-stream", ...headers });
      res.end(`event: message\ndata: ${JSON.stringify(envelope)}\n\n`);
    } else respond(res, 200, envelope, headers);
  });
});
server.listen(0, "127.0.0.1", () => {
  console.log(`http://127.0.0.1:${server.address().port}/mcp`);
});
