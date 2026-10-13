# engines-ida: IDA provider (phase 5b, read-only ida-pro-mcp client)

Branch `jp-engines-ida` (from `jp-engines`). Port of REA's `src/ida/*` into `crates/engines/src/ida/`.
How to use it: `docs/ida-provider.md`.

## Status

| Area | Status | Proof |
|---|---|---|
| Registration (`REA_IDA_MCP_CONFIG`, strict union, 64 KiB, `mcpServers` envelope, digest) | Validado | `ida::tests`, `registration_errors_match_the_oracle` (8 invalid registrations, IDA's rejection identical to REA's) |
| Identity, 12 capabilities, limitations, `live` cache policy, effects, headless `procedure_callers` unavailable | Validado | `ida::tests::capabilities_*`, `..._through_the_route_and_the_client`, every direct golden |
| Analysis profile (registration digest, no credentials) | Validado | profile and `evidence_id` equal to REA's in attached mode |
| Attached (legacy 1.4) direct operations x12 | Validado | `attached_direct_operations_match_the_oracle` (86 calls) |
| Headless (database supervisor) direct operations x11 (+ callers unavailable) | Validado | `headless_direct_operations_match_the_oracle` (86 calls, modulo random workspace/session ids) |
| Operations IDA does not declare (every other direct tool of phases 5/5b) | Validado | `*_catalog_matches_the_oracle`: `capability_unavailable` with REA's text |
| Workflows over IDA (`get_call_graph`, `trace_call_path`, `batch_decompile`, `trace_native_values`, ...) | Validado | `*_workflows_*`, `*_catalog_*` |
| Upstream faults: malformed (zod wording), truncated, tool errors | Validado | `upstream_faults_match_the_oracle` (19 variants: 10 attached, 9 headless) |
| stdio transport, environment isolation, process-group kill, timeouts, orphan checks | Validado | `ida::tests_stdio` |
| Local streamable HTTP (headers, no redirects) | Validado | `http_registrations_match_the_oracle`, `ida::tests_stdio` |
| IDA never saves/closes the user's database; headless closes only its own worker with `save: false` | Validado | call-log audits in `engines_ida_test`, lifecycle tests in `ida::tests` |
| HTTPS endpoints | Não verificável | validated like REA but cannot connect: no TLS stack in this build |
| `compare_functions`, `build_call_path` | Não testado | evidence-derived stubs of the track, not provider operations |

Oracle entries replayed: 378 (REA 0fa0b04 via `fixtures/oracle_session.py`), all equal.

## Ignored in comparisons

* `subject.local_path` (harness).
* Headless only: `rea-ida-XXXXXX` workspace names, `rea-<uuid>` session ids (rewritten to `$WORKSPACE`/`$SESSION`)
  and `evidence_id`, a digest over them (shape still checked).
* Registration errors: candidate list (REA also lists Hopper).

## External dependency

`node` (v22 here) on `PATH` runs `fixtures/engines/ida/fake_ida_mcp.mjs`, a dependency-free fake of
ida-pro-mcp that models `sample_elf`. With `TRACEWISE_REQUIRE_ORACLE=1` a missing `node` fails the tests.
Tests share the fixed private directory `/tmp/tracewise-ida-parity` (see `engines_common::ida_environment`).

## Divergences from REA

1. REA starts the engine in `open_binary`; tracewise starts it lazily (glue in `tracks/engines.rs`).
2. `https` registrations cannot connect (no TLS stack).
3. Regex mode is evaluated by `fancy-regex` with an ECMAScript class translation, not by a JS engine.
4. `sourcePath` of extracted archives is not modeled.

## Touched outside the provider directory

* `crates/engines/src/error.rs`: additive variant `AnalysisError::Protocol` (REA's `AnalysisProtocolError`).
* `crates/engines/Cargo.toml` + `Cargo.lock`: `process-wrap`, `url`, `fancy-regex`, `reqwest` (feature `stream`),
  `sse-stream`, `futures-util`; rmcp feature `transport-streamable-http-client`.
* `crates/server/tests/engines_common/mod.rs`: additive IDA helpers.
* `docs/ida-provider.md`, `docs/progress/engines-ida.md`.
