#!/usr/bin/env python3
"""Call the ORIGINAL REA MCP server over stdio: rea_oracle.py <tool> '<json args>' [out.json]"""
import json,subprocess,sys,os
NODE="/tmp/node-v22.20.0-linux-x64/bin/node"
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
r=rq("tools/call",{"name":sys.argv[1],"arguments":json.loads(sys.argv[2])})
out=json.dumps(r.get("result",r),indent=2)
if len(sys.argv)>3: open(sys.argv[3],"w").write(out)
else: print(out[:3000])
p.kill()
