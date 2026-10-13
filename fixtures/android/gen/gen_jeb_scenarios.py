import json,subprocess,os,time
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
from concurrent.futures import ThreadPoolExecutor
FX="/workspace/wt/managed_android/fixtures/android"
NODE=__import__("os").environ.get("TRACEWISE_ORACLE_NODE","/tmp/node-v22.20.0-linux-x64/bin/node")
P="/targets/ApiDemos-debug.apk"
def j(tool,**a): return [tool,a]
FULL=[
 j("inspect_jeb_client"),
 j("open_jeb_project",path=P),
 j("list_jeb_units"),
 j("list_jeb_units",count=2,index=1),
 j("list_jeb_units",filter="*Bytecode*"),
 j("list_jeb_units",parent_unit_path="/Bytecode"),
 j("list_jeb_units",count=100,index=3),
 j("decompile_jeb_item",item_address="Lio/appium/A;->m()V",item_kind="method"),
 j("decompile_jeb_item",item_address="Lio/appium/A;",item_kind="type",unit_path="/Bytecode/classes.dex"),
]
SHORT=[j("inspect_jeb_client"),j("open_jeb_project",path=P),j("list_jeb_units",count=3),j("decompile_jeb_item",item_address="A",item_kind="type")]
scen=[]
def add(name,mode,calls,env=None): scen.append({"name":name,"mode":mode,"calls":calls,"env":env or {}})
add("normal","normal",FULL)
add("order: open first","normal",[j("open_jeb_project",path=P),j("inspect_jeb_client"),j("list_jeb_units",count=1)])
add("order: units first","normal",[j("list_jeb_units",count=2),j("decompile_jeb_item",item_address="x",item_kind="type"),j("open_jeb_project",path=P)])
add("order: decompile first","normal",[j("decompile_jeb_item",item_address="x",item_kind="method"),j("inspect_jeb_client")])
add("sse","sse",SHORT)
add("gui","gui",SHORT)
add("no version","no-version",SHORT)
add("malformed version","malformed",SHORT)
add("malformed open","malformed-open",[j("open_jeb_project",path=P),j("inspect_jeb_client")])
add("bare open","bare-open",[j("open_jeb_project",path=P),j("list_jeb_units")])
add("malformed decompile","malformed-decompile",[j("decompile_jeb_item",item_address="x",item_kind="type")])
add("full page","full-page",[j("list_jeb_units",count=5),j("list_jeb_units",count=3),j("list_jeb_units",count=100)])
for m in ["refuse","refuse-nested","refuse-code-only","refuse-empty","no-success-field","text-json","text-plain","text-string-json","text-two-blocks","tool-error-text","tool-error-json","empty-content"]:
    add(m,m,SHORT)
for m in ["http-500","redirect","garbage-init","http-500-call","rpc-error-call"]:
    add("transport: "+m,m,SHORT)
add("validation","normal",[
 j("list_jeb_units",count=0),j("list_jeb_units",count=101),j("list_jeb_units",index=-1),j("list_jeb_units",count=1.5),
 j("list_jeb_units",filter=3),j("list_jeb_units",parent_unit_path=""),
 j("decompile_jeb_item",item_kind="type"),j("decompile_jeb_item",item_address="a",item_kind="field"),j("decompile_jeb_item",item_address="",item_kind="type"),
 j("decompile_jeb_item",item_address="a",item_kind="type",unit_path=""),
 j("open_jeb_project"),j("open_jeb_project",path=""),j("open_jeb_project",path=P,extra=1),
 ["inspect_jeb_client",{"extra":1}],
])
add("no server","normal",SHORT,{"REA_JEB_MCP_URL":"http://127.0.0.1:9/mcp"})
add("default endpoint (nothing listening)","normal",SHORT[:2],{})
add("url: https closed port","normal",SHORT[:1],{"REA_JEB_MCP_URL":"https://127.0.0.1:9/mcp"})
add("url: not loopback","normal",SHORT[:1],{"REA_JEB_MCP_URL":"http://example.com/mcp"})
add("url: credentials","normal",SHORT[:1],{"REA_JEB_MCP_URL":"http://user:pw@127.0.0.1:8425/mcp"})
add("url: query","normal",SHORT[:1],{"REA_JEB_MCP_URL":"http://127.0.0.1:8425/mcp?x=1"})
add("url: scheme","normal",SHORT[:1],{"REA_JEB_MCP_URL":"ftp://127.0.0.1:8425/mcp"})
add("url: garbage","normal",SHORT[:1],{"REA_JEB_MCP_URL":"not a url"})
add("url: localhost name","normal",SHORT[:1],{"REA_JEB_MCP_URL":"http://localhost:8425/mcp"})
json.dump(scen,open(FX+"/jeb_scenarios.json","w"),separators=(",",":"))

def run(i):
    s=scen[i]
    needs_fake = not any(k=="REA_JEB_MCP_URL" for k in s["env"]) and s["name"]!="default endpoint (nothing listening)"
    fake=None; env=dict(s["env"])
    if needs_fake:
        fake=subprocess.Popen([NODE,FX+"/fake-jeb.mjs",s["mode"]],stdout=subprocess.PIPE,text=True)
        env["REA_JEB_MCP_URL"]=fake.stdout.readline().strip()
    try:
        json.dump(s["calls"],open("/tmp/tracewise-oracle/jb_calls_%d.json"%i,"w"))
        args=["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/jb_raw_%d.json"%i]+["%s=%s"%(k,v) for k,v in env.items()]
        r=subprocess.run(args,stdin=open("/tmp/tracewise-oracle/jb_calls_%d.json"%i),capture_output=True,text=True)
        if r.returncode!=0:
            return {"name":s["name"],"startup_failure":r.stderr[-400:]}
        raw=json.load(open("/tmp/tracewise-oracle/jb_raw_%d.json"%i))
    finally:
        if fake: fake.kill()
    return {"name":s["name"],"results":[({"error":x["content"][0]["text"]} if x.get("isError") else {"structuredContent":x["structuredContent"]}) if (x.get("isError") or "structuredContent" in x) else {"unexpected":x} for x in raw]}
with ThreadPoolExecutor(3) as pool: res=list(pool.map(run,range(len(scen))))
json.dump(res,open(FX+"/oracle_jeb.json","w"),separators=(",",":"))
for s,r in zip(scen,res):
    if "startup_failure" in r: print(r["name"],"| STARTUP FAILURE",r["startup_failure"]); continue
    for call,o in zip(s["calls"],r["results"]):
        a=json.dumps(call[1])[:50]
        if "error" in o: print(r["name"],"|",call[0],a,"ERR",o["error"][:420])
        else:
            e=o["structuredContent"]; n=e["normalized_result"]
            print(r["name"],"|",call[0],a,"ok",e["provider"]["version"],e["limitations"][1:],e["confidence"],json.dumps({k:v for k,v in n.items() if k!="engine"})[:160])
