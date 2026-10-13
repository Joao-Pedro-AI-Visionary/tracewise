#!/usr/bin/env python3
"""oracle_session.py <calls.json | inline json list> [out.json]: runs several tool calls in ONE REA session."""
import json,subprocess,sys
import os
NODE=os.environ.get("REA_NODE","node")
p=subprocess.Popen([NODE,"/workspace/rea-map/src/scripts/rea.mjs","mcp"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,cwd="/workspace/rea-map/src")
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
rq("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"oracle","version":"1"}})
rq("notifications/initialized",notify=True)
raw=sys.argv[1]
if raw.startswith("@"): raw=open(raw[1:],encoding="utf-8").read()
calls=json.loads(raw)
outs=[]
for c in calls:
    r=rq("tools/call",{"name":c["name"],"arguments":c.get("arguments",{})})
    outs.append(r.get("result",r))
out=json.dumps(outs,indent=2)
if len(sys.argv)>2: open(sys.argv[2],"w").write(out)
else: print(out[:6000])
p.kill()
