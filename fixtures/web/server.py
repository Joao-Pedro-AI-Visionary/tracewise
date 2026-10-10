# Local test API used to produce a deterministic HAR for tracewise demos/fixtures.
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
TODOS = {1: {"id": 1, "title": "buy milk", "done": False, "tags": ["home"]}}
class H(BaseHTTPRequestHandler):
    server_version = 'DemoAPI/1.0'; sys_version = ''
    def date_time_string(self, timestamp=None): return 'Sat, 10 Oct 2026 12:00:00 GMT'
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=SECRET-COOKIE-123; HttpOnly")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/api/todos/"):
            i = int(self.path.rsplit("/", 1)[1]); t = TODOS.get(i)
            return self._send(200 if t else 404, t or {"error": "not found"})
        if self.path.startswith("/api/todos"): return self._send(200, {"items": list(TODOS.values()), "total": len(TODOS)})
        if self.path == "/api/me": return self._send(200, {"id": "u1", "email": "dev@example.com", "plan": "pro"})
        self._send(404, {"error": "not found"})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        i = max(TODOS) + 1; TODOS[i] = {"id": i, "title": body.get("title", ""), "done": False, "tags": body.get("tags", [])}
        self._send(201, TODOS[i])
HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8765), H).serve_forever()
