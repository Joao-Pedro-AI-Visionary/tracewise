#!/usr/bin/env python3
"""Multi-call REA oracle.

    oracle.py out.json [NAME=value ...] < calls.json

stdin is a JSON list of [tool, arguments]; the REA answers (one MCP session, in order)
are written to out.json. NAME=value arguments are added to the server's environment.

Environment:
  TRACEWISE_ORACLE_NODE  node binary (default /tmp/node-v22.20.0-linux-x64/bin/node,
                         the link /workspace/tools/env.sh creates)
  TRACEWISE_REA_SRC      built REA checkout (morluto/rea @ 0fa0b04), default /workspace/rea-map/src
"""
import json,subprocess,sys,os
NODE=os.environ.get("TRACEWISE_ORACLE_NODE","/tmp/node-v22.20.0-linux-x64/bin/node")
REA_SRC=os.environ.get("TRACEWISE_REA_SRC","/workspace/rea-map/src")
env=dict(os.environ)
for kv in sys.argv[2:]:
    k,v=kv.split("=",1); env[k]=v
p=subprocess.Popen([NODE,os.path.join(REA_SRC,"scripts","rea.mjs"),"mcp"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,cwd=REA_SRC,env=env)
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
calls=json.load(sys.stdin)
out=[]
for tool,args in calls:
    r=rq("tools/call",{"name":tool,"arguments":args})
    out.append(r.get("result",r))
open(sys.argv[1],"w").write(json.dumps(out,indent=1))
p.kill()
