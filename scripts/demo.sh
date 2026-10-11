#!/usr/bin/env bash
# Reproducible path: local fixture API -> redacted HAR -> OpenAPI spec -> typed SDKs.
# Exits non-zero on any failed step. Stops the fixture server on the way out.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TRACEWISE="${TRACEWISE:-$ROOT/target/debug/tracewise}"
if [[ ! -x "$TRACEWISE" ]]; then
  echo "tracewise binary missing at $TRACEWISE; building it" >&2
  cargo build -p tracewise --bin tracewise
fi

NODE_PREFIX="/tmp/node-v22.20.0-linux-x64/bin"
if [[ -x "$NODE_PREFIX/node" ]]; then
  export PATH="$NODE_PREFIX:$PATH"
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is not available at $NODE_PREFIX or on PATH" >&2
  exit 1
fi
if ! command -v npx >/dev/null 2>&1; then
  echo "npx is not available next to node ($(command -v node))" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/tracewise-demo.XXXXXX")"
LOG="$WORKDIR/logs"
mkdir -p "$LOG"
SERVER_PID=""

cleanup() {
  local status=$?
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "demo failed; artifacts kept in $WORKDIR" >&2
  else
    rm -rf "$WORKDIR"
  fi
  exit "$status"
}
trap cleanup EXIT

run_log() {
  local name="$1"
  shift
  if ! "$@" >"$LOG/$name.out" 2>"$LOG/$name.err"; then
    echo "step $name failed" >&2
    cat "$LOG/$name.out" >&2 || true
    cat "$LOG/$name.err" >&2 || true
    exit 1
  fi
}

assert_no_secret() {
  local label="$1"
  shift
  local hits
  hits="$(grep -R -n -F -- "SECRET-" "$@" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    printf '%s\n' "$hits" >&2
    echo "SECRET- appeared in $label" >&2
    exit 1
  fi
}

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
BASE="http://127.0.0.1:${PORT}"

python3 "$ROOT/fixtures/web/server.py" "$PORT" >"$LOG/server.out" 2>"$LOG/server.err" &
SERVER_PID=$!

ready=0
for _ in $(seq 1 50); do
  if python3 -c "import urllib.request; urllib.request.urlopen('${BASE}/api/me', timeout=1).read()" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "fixture server exited before accepting connections" >&2
    cat "$LOG/server.out" >&2 || true
    cat "$LOG/server.err" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "fixture server did not become ready on ${BASE}" >&2
  exit 1
fi

HAR="$WORKDIR/capture.har"
SPEC="$WORKDIR/spec.json"
SDK="$WORKDIR/sdk"

run_log record_har python3 "$ROOT/fixtures/web/record_har.py" "$BASE" "$HAR"
run_log infer "$TRACEWISE" infer-api-spec "$HAR" -o "$SPEC" --base-url "$BASE"
run_log generate "$TRACEWISE" generate-api-client "$SPEC" --lang ts,py -o "$SDK" --replay "$HAR"

python3 - "$SPEC" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1], encoding="utf-8"))
paths = spec.get("paths") or {}
missing = [p for p in ("/api/me", "/api/todos", "/api/todos/{id}") if p not in paths]
if spec.get("openapi") != "3.1.0" or missing:
    raise SystemExit(f"unexpected spec openapi={spec.get('openapi')!r} missing={missing}")
if "x-tracewise-evidence" not in json.dumps(spec):
    raise SystemExit("spec has no x-tracewise-evidence")
PY

export NPM_CONFIG_UPDATE_NOTIFIER=false
TS_DIR="$SDK/typescript"
run_log tsc bash -c "cd '$TS_DIR' && npx -y -p typescript tsc --pretty false"
run_log node_test bash -c "cd '$TS_DIR' && node --test dist/test/replay.test.js"

PY_DIR="$SDK/python"
run_log python_test bash -c "cd '$PY_DIR' && python3 -m unittest discover -s . -p 'test_*.py'"

cat >"$WORKDIR/live_py.py" <<'PY'
import importlib
import sys
from pathlib import Path

py_root = Path(sys.argv[1])
base = sys.argv[2]
sys.path.insert(0, str(py_root))
packages = [
    child.name
    for child in sorted(py_root.iterdir())
    if (child / "client.py").is_file() and (child / "__init__.py").is_file()
]
if len(packages) != 1:
    raise SystemExit(f"expected one generated package, found {packages}")
name = packages[0]
client_mod = importlib.import_module(f"{name}.client")
models = importlib.import_module(f"{name}.models")
client = client_mod.Client(base_url=base)

status, me = client.get_api_me()
assert status == 200, status
assert me.email == "dev@example.com", me
assert me.id == "u1", me
print("python get_api_me", status, me.email)

status, todos = client.get_api_todos(models.GetApiTodosQuery(limit=10, offset=0))
assert status == 200, status
assert todos.total >= 1, todos
print("python get_api_todos", status, todos.total)

status, one = client.get_api_todos_by_id(models.GetApiTodosByIdPath(id=1))
assert status == 200, status
assert one.title == "buy milk", one
print("python get_api_todos_by_id", status, one.title)

status, created = client.post_api_todos(
    models.PostApiTodosRequest(title="live sdk", tags=["demo"])
)
assert status == 201, status
assert created.title == "live sdk", created
print("python post_api_todos", status, created.id, created.title)

status, missing = client.get_api_todos_by_id(models.GetApiTodosByIdPath(id=99))
assert status == 404, status
assert missing.error == "not found", missing
print("python get_api_todos_by_id missing", status, missing.error)
PY

cat >"$WORKDIR/live.mjs" <<'JS'
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const clientUrl = pathToFileURL(process.argv[2]).href;
const base = process.argv[3];
const { Client } = await import(clientUrl);
const client = new Client({ baseUrl: base });

const me = await client.getApiMe();
assert.equal(me.status, 200);
assert.equal(me.body.email, "dev@example.com");
assert.equal(me.body.id, "u1");
console.log("typescript getApiMe", me.status, me.body.email);

const todos = await client.getApiTodos({ limit: 10, offset: 0 });
assert.equal(todos.status, 200);
assert.ok(todos.body.total >= 1);
console.log("typescript getApiTodos", todos.status, todos.body.total);

const one = await client.getApiTodosById({ id: 1 });
assert.equal(one.status, 200);
assert.equal(one.body.title, "buy milk");
console.log("typescript getApiTodosById", one.status, one.body.title);

const created = await client.postApiTodos({ title: "live sdk ts", tags: ["demo"] });
assert.equal(created.status, 201);
assert.equal(created.body.title, "live sdk ts");
console.log("typescript postApiTodos", created.status, created.body.id, created.body.title);

const missing = await client.getApiTodosById({ id: 99 });
assert.equal(missing.status, 404);
assert.equal(missing.body.error, "not found");
console.log("typescript getApiTodosById missing", missing.status, missing.body.error);
JS

run_log live_py python3 "$WORKDIR/live_py.py" "$PY_DIR" "$BASE"
run_log live_ts node "$WORKDIR/live.mjs" "$TS_DIR/dist/src/client.js" "$BASE"

# The raw HAR is the capture input and still holds the credential markers
# that redaction is supposed to strip. Spec, SDK, and command logs must not.
assert_no_secret "spec" "$SPEC"
assert_no_secret "sdk" "$SDK"
assert_no_secret "command output" "$LOG/infer.out" "$LOG/infer.err" "$LOG/generate.out" "$LOG/generate.err" \
  "$LOG/tsc.out" "$LOG/tsc.err" "$LOG/node_test.out" "$LOG/node_test.err" \
  "$LOG/python_test.out" "$LOG/python_test.err" "$LOG/live_py.out" "$LOG/live_py.err" \
  "$LOG/live_ts.out" "$LOG/live_ts.err" "$LOG/record_har.out" "$LOG/record_har.err"

echo "demo ok: ${BASE} -> spec -> sdk (python + typescript)"
