# IDA Pro provider

tracewise adapts an existing [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) server into its
native analysis tools. IDA, Hex-Rays, Python and the upstream server are installed and licensed by
you; tracewise does not install, activate or bundle any of them. IDA is **read-only**: it never
saves, renames, comments or closes a database it does not own.

Choose one lifecycle mode in a JSON registration and point `REA_IDA_MCP_CONFIG` (an absolute path)
at it. Select `ida` with `REA_ANALYSIS_PROVIDER=ida` or `open_binary.provider_id`. Discovery starts
nothing; the upstream process is launched by the first analysis call.

## Registration

A direct object, or an upstream `mcpServers` document with an `ida-pro-mcp` entry (at most 64 KiB):

| key | meaning |
|---|---|
| `command`, `args`, `env` | stdio registration: the upstream proxy runs in its own process group and is stopped with it |
| `url`, `headers` | local `http(s)://localhost`, `127.0.0.1` or `[::1]` streamable-HTTP registration without URL credentials. `headers` are sent on every request; redirects are refused. Only plain `http` connects (see below) |
| `mode` | `attached` (default) or `headless` |
| `timeoutMs` | per-request timeout, default 300000 |
| `workspaceRoot` | headless only: absolute parent of the private input copy |

Unknown keys are rejected. The analysis profile commits to the SHA-256 of the canonical (RFC 8785)
parsed registration, never to its content, so credentials in `env` or `headers` are not reported.

The proxy sees only the environment snapshot handed to the engines (plus `IDA_MCP_MAX_WORKERS=1`
and the registration's own `env`); nothing from the ambient process leaks in.

### Attached (upstream 1.4 legacy tools)

Analyses the database already open in an IDA session. The original input binary must be the one
IDA recorded: its SHA-256 and image base are checked around every request. The close operation only
releases the MCP connection.

### Headless (upstream database supervisor tools)

Copies the target into a private `0700` directory, checks its digest and opens it as an owned worker
(`idb_open`, `force_headless`). Every request is scoped to that worker. On close it calls `idb_close`
with `save: false`, verifies the worker is gone from `idb_list`, stops the proxy and removes only its
own directory. An unverified release keeps the directory and reports incomplete cleanup; a later
close retries. `procedure_callers` is declared unavailable in this profile (upstream reports code
references, not proven call edges).

## Operations

`list_procedures`, `search_procedures`, `list_strings`, `search_strings`, `procedure_address`,
`procedure_pseudo_code`, `procedure_assembly`, `procedure_callers` (attached only), `procedure_callees`,
`read_function_instructions`, `xrefs` (explicit address required) and `analyze_function`. Results are
live (cache policy `live`, never replayed from a snapshot). Every other engines tool answers
`capability_unavailable`, as in REA. The composed workflows that only need these operations
(`get_call_graph`, `trace_call_path`, `batch_decompile`, ...) work; those that need documents, names or
segments report the missing capability.

## Differences from REA

* **HTTPS endpoints.** This build has no TLS stack, so an `https://localhost` registration validates
  like REA's but cannot connect: the first analysis call reports that only plain `http` endpoints
  are supported. Use `http://127.0.0.1` or the stdio proxy. (rmcp 0.11's own reqwest adapter would add
  rustls to every `reqwest` user in the workspace, so the small adapter in `ida/http_client.rs`
  replaces it.)
* **Start-up timing.** REA starts the engine while opening the target, so a bad registration or a
  mismatched attached database fails `open_binary`. tracewise starts engines lazily: `open_binary`
  succeeds and the first analysis call reports the same error.
* **Regex mode** follows ECMAScript for `.`, `\d`, `\w`, `\s` and `\b`, and accepts lookaround and
  backreferences, but is evaluated by `fancy-regex`, not by a JavaScript engine: constructs beyond
  those exercised by the tests (property escapes, unbounded lookbehind, ...) are not guaranteed to
  behave identically.
* **Documents of extracted archives** (`sourcePath`) are not modeled: `document` must be the target path.

## Tests

`engines_ida_test` replays goldens recorded from the original REA against
`fixtures/engines/ida/fake_ida_mcp.mjs`, a dependency-free Node fake of the upstream server that models
`fixtures/engines/sample_elf`. `fixtures/engines/ida/run_oracle.sh` and `generate_variants.py`
regenerate them. Everything runs from the fixed private directory `/tmp/tracewise-ida-parity` so the
registration digest and artifact paths are identical for the oracle and for the Rust server.
