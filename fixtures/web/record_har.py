# Drive the local API and write a HAR 1.2 file (with auth headers/cookies to exercise redaction).
import json, sys, urllib.request, datetime
base = sys.argv[1]; out = sys.argv[2]
calls = [("GET", "/api/me", None), ("GET", "/api/todos?limit=10&offset=0", None), ("GET", "/api/todos/1", None),
         ("POST", "/api/todos", {"title": "write sdk", "tags": ["work", "rust"]}), ("GET", "/api/todos/99", None)]
entries = []
for m, path, body in calls:
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Authorization": "Bearer SECRET-TOKEN-abc", "Cookie": "session=SECRET-COOKIE-123", "Accept": "application/json"}
    if data: hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, method=m, headers=hdrs)
    try: r = urllib.request.urlopen(req); status, rh, txt = r.status, r.headers.items(), r.read().decode()
    except urllib.error.HTTPError as e: status, rh, txt = e.code, e.headers.items(), e.read().decode()
    from urllib.parse import urlsplit, parse_qsl
    u = urlsplit(base + path)
    entries.append({"startedDateTime": "2026-10-10T12:00:00.000Z", "time": 1,
      "request": {"method": m, "url": base + path, "httpVersion": "HTTP/1.1",
        "headers": [{"name": k, "value": v} for k, v in hdrs.items()], "cookies": [{"name": "session", "value": "SECRET-COOKIE-123"}],
        "queryString": [{"name": k, "value": v} for k, v in parse_qsl(u.query)], "headersSize": -1, "bodySize": len(data or b""),
        **({"postData": {"mimeType": "application/json", "text": data.decode()}} if data else {})},
      "response": {"status": status, "statusText": "", "httpVersion": "HTTP/1.1", "headers": [{"name": k, "value": v} for k, v in rh],
        "cookies": [], "content": {"size": len(txt), "mimeType": "application/json", "text": txt}, "redirectURL": "", "headersSize": -1, "bodySize": len(txt)},
      "cache": {}, "timings": {"send": 0, "wait": 1, "receive": 0}})
json.dump({"log": {"version": "1.2", "creator": {"name": "tracewise-demo", "version": "1"}, "entries": entries}}, open(out, "w"), indent=2)
print("wrote", out, len(entries))
