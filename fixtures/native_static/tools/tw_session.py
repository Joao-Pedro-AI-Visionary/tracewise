#!/usr/bin/env python3
"""tw_session.py <calls.json|@file> [out.json]: runs tool calls in ONE tracewise MCP session."""
import json,subprocess,sys
p=subprocess.Popen(["/workspace/wt/native_static/target/debug/tracewise","mcp"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
i=0
def rq(m,params=None,notify=False):
    global i
    msg={"jsonrpc":"2.0","method":m}
    if params is not None: msg["params"]=params
    if not notify: i+=1; msg["id"]=i
    p.stdin.write(json.dumps(msg)+"\n"); p.stdin.flush()
    if notify: return
    while True:
        r=json.loads(p.stdout.readline())
        if r.get("id")==i: return r
rq("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}})
rq("notifications/initialized",notify=True)
raw=sys.argv[1]
if raw.startswith("@"): raw=open(raw[1:],encoding="utf-8").read()
outs=[]
for c in json.loads(raw):
    r=rq("tools/call",{"name":c["name"],"arguments":c.get("arguments",{})})
    outs.append(r.get("result",r))
out=json.dumps(outs,indent=1)
if len(sys.argv)>2: open(sys.argv[2],"w").write(out)
else: print(out[:6000])
p.kill()
