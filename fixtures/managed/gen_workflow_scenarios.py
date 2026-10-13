import json,subprocess,sys,os,hashlib
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
FX="/workspace/wt/managed_android/fixtures/managed"
insp=json.load(open(FX+"/oracle_inspect.json"))
native=json.load(open(FX+"/workflow_inputs_native.json"))
def ev(f,t): return {"$ev":f"{f}/{t}"}
M="inspect_managed_members"; A="inspect_managed_artifact"; B="inspect_managed_native_boundaries"
def resolve(x):
    if isinstance(x,dict):
        if "$ev" in x:
            f,t=x["$ev"].split("/"); return insp[f][t]["structuredContent"]
        if "$native" in x: return native[x["$native"]]
        if "$mutate" in x:
            base=json.loads(json.dumps(resolve(x["$mutate"])))
            base.update(x["set"]); return base
        return {k:resolve(v) for k,v in x.items()}
    if isinstance(x,list): return [resolve(i) for i in x]
    return x
def members(f): return insp[f][M]["structuredContent"]["normalized_result"]
def lock(f, index=0, **over):
    ms=[m for m in members(f)["methods"] if m["body"]["status"]=="present"]
    m=ms[index]
    d={"token":m["token"],"signature_sha256":m["signature"]["raw_sha256"],"normalized_il_sha256":m["body"]["normalized_il_sha256"]}
    d.update(over); return d
scen=[]
def add(name,tool,args): scen.append({"name":name,"tool":tool,"args":args})

# --- compare
pairs=[("basic","il_rich"),("basic","pinvoke"),("il_rich","eh_small"),("il_rich","il_tiny"),("il_tiny","il_truncated_call"),
 ("sig_field_ptr","basic"),("sig_field_trailing","sig_field_ptr"),("sig_method_generic","sig_method_szarray"),("sig_method_truncated","basic"),
 ("sig_method_reserved","basic"),("names","basic"),("modrows","basic"),("badref","basic"),("mvid","basic"),("badsig","basic"),("native","basic"),
 ("eh_small","eh_fat"),("eh_bad","eh_fat"),("eh_filter","eh_small"),("eh_missing","eh_fat"),("fat_header_short","basic"),("il_unknown_op","basic"),
 ("sig_field_empty_class","sig_field_generic"),("sig_method_vararg","sig_method_trailing"),("il_switch_overflow","il_prefix_only"),("il_empty","il_tiny"),
 ("real_primitives_net8","real_primitives_net462"),("real_systemevents_net8","real_primitives_net8"),("real_primitives_net462","real_primitives_net8")]
for l,r in pairs: add(f"compare {l} vs {r}","compare_managed_members",{"left":ev(l,M),"right":ev(r,M)})
add("compare same evidence","compare_managed_members",{"left":ev("basic",M),"right":ev("basic",M)})
add("compare wrong operation","compare_managed_members",{"left":ev("basic",A),"right":ev("il_rich",M)})
add("compare tampered","compare_managed_members",{"left":{"$mutate":ev("basic",M),"set":{"limitations":["tampered"]}},"right":ev("il_rich",M)})
add("compare missing right","compare_managed_members",{"left":ev("basic",M)})

# --- verify
nat={"u":{"$native":"macho_user32"},"g":{"$native":"macho_gdi32"},"k":{"$native":"macho_libkernel32"},"c":{"$native":"macho_libc"},"e":{"$native":"macho_empty"},
 "fl":{"$native":"func_loadlibrary"},"fm":{"$native":"func_messagebox"},"fn":{"$native":"func_nosubject"}}
vsets=[("pinvoke",["u"]),("pinvoke",["g"]),("pinvoke",["e"]),("pinvoke",["fm"]),("pinvoke",["fn"]),("pinvoke",["u","g"]),
 ("pinvoke_cdecl",["c"]),("pinvoke_cdecl",["u"]),("pinvoke_bad_forwarded",["u"]),("pinvoke_null_forwarded",["u"]),
 ("basic",["u"]),("r2r",["u"]),("mixed",["u","fl"]),("badref",["u"]),("native",["u"]),("badsig",["u"]),
 ("real_systemevents_net8",["u","g","k","fl","fn"]),("real_systemevents_net8",["e"]),("real_systemevents_net8",["u","k","c"]),("real_primitives_net8",["u"])]
for f,ns in vsets: add(f"verify {f} with {','.join(ns)}","verify_managed_native_boundaries",{"managed_boundaries":ev(f,B),"native_observations":[nat[n] for n in ns]})
add("verify duplicate native","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",B),"native_observations":[nat["u"],nat["u"]]})
add("verify members as native","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",B),"native_observations":[ev("pinvoke",M)]})
add("verify artifact as boundary","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",A),"native_observations":[nat["u"]]})
add("verify own id as native","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",B),"native_observations":[ev("pinvoke",B)]})
add("verify empty native","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",B),"native_observations":[]})
add("verify tampered native","verify_managed_native_boundaries",{"managed_boundaries":ev("pinvoke",B),"native_observations":[{"$mutate":nat["u"],"set":{"limitations":["x"]}}]})

# --- import
text_cs="public static void Main()\r\n{\r\n    Console.WriteLine(\"héllo\");\r\n}\r"
add("import basic csharp","import_managed_reconstruction",{"static_members":ev("basic",M),
 "decompiler":{"name":"ILSpy","family":"ilspy"},"methods":[{**lock("basic"),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"void Main() { }"}}]})
add("import il_rich full","import_managed_reconstruction",{"static_members":ev("il_rich",M),
 "decompiler":{"name":"dnSpy","version":"6.1.8","family":"dnspy","executable_sha256":"a"*64,"options":["--no-sort","--lang=csharp"]},
 "methods":[{**lock("il_rich"),"reconstruction":{"kind":"decompiled-il","language":"il","text":text_cs,"source_path":"Main.il","start_line":3,"end_line":9}}],
 "notes":["first note","second note"]})
add("import correct text hash","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic"),"reconstruction":{"kind":"semantic-pseudocode","language":"pseudocode","text":"a\nb","text_sha256":hashlib.sha256(b"a\nb").hexdigest()}}]})
add("import wrong text hash","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic"),"reconstruction":{"kind":"semantic-pseudocode","language":"pseudocode","text":"a\nb","text_sha256":"0"*64}}]})
add("import lock mismatch","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic",normalized_il_sha256="1"*64),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"x"}}]})
add("import null il lock","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic",normalized_il_sha256=None),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"x"}}]})
add("import tampered","import_managed_reconstruction",{"static_members":{"$mutate":ev("basic",M),"set":{"limitations":["t"]}},"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic"),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"x"}}]})
add("import artifact evidence","import_managed_reconstruction",{"static_members":ev("basic",A),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic"),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"x"}}]})
add("import empty methods","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},"methods":[]})
add("import three methods","import_managed_reconstruction",{"static_members":ev("real_primitives_net8",M),"decompiler":{"name":"ILSpy","family":"ilspy","options":[]},
 "methods":[{**lock("real_primitives_net8",i),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":f"// method {i}\nreturn;\n"}} for i in (0,3,7)]})
add("import unknown key","import_managed_reconstruction",{"static_members":ev("basic",M),"decompiler":{"name":"x","family":"other"},
 "methods":[{**lock("basic"),"reconstruction":{"kind":"decompiled-csharp","language":"csharp","text":"x"}}],"bogus":1})

# --- graph
gsets=[("basic",1,1,1),("basic",1,0,0),("basic",0,1,0),("basic",0,0,1),("pinvoke",1,1,1),("pinvoke_bad_forwarded",1,1,1),("pinvoke_null_forwarded",0,1,1),
 ("badref",1,1,1),("mixed",1,1,1),("modrows",1,1,1),("unity",1,1,1),("framework",1,0,0),("native",1,1,1),("badsig",1,1,1),("r2r",1,1,1),("names",0,1,1),
 ("real_systemevents_net8",1,1,1),("real_primitives_net8",1,1,1),("real_primitives_net462",1,0,1),("eh_small",0,1,0),("il_rich",1,1,0)]
for f,a,m,b in gsets:
    args={}
    if a: args["managed_artifact"]=ev(f,A)
    if m: args["managed_members"]=ev(f,M)
    if b: args["managed_native_boundaries"]=ev(f,B)
    add(f"graph {f} a{a}m{m}b{b}","project_managed_application_graph",args)
add("graph empty","project_managed_application_graph",{})
add("graph sha mismatch","project_managed_application_graph",{"managed_artifact":ev("basic",A),"managed_members":ev("pinvoke",M)})
add("graph wrong op","project_managed_application_graph",{"managed_artifact":ev("basic",M)})
add("graph tampered","project_managed_application_graph",{"managed_artifact":{"$mutate":ev("basic",A),"set":{"limitations":["t"]}}})


# sequences that share one REA session (unknown registry conflicts)
seqs=[
 {"name":"unknown conflict","steps":[
   {"tool":"compare_managed_members","args":{"left":ev("il_tiny",M),"right":ev("il_truncated_call",M)}},
   {"tool":"compare_managed_members","args":{"left":ev("il_rich",M),"right":ev("il_unknown_op",M)}},
   {"tool":"list_unknowns","args":{}}]},
 {"name":"verify then verify","steps":[
   {"tool":"verify_managed_native_boundaries","args":{"managed_boundaries":ev("pinvoke",B),"native_observations":[nat["g"]]}},
   {"tool":"verify_managed_native_boundaries","args":{"managed_boundaries":ev("pinvoke_cdecl",B),"native_observations":[nat["u"]]}},
   {"tool":"list_unknowns","args":{}}]},
 {"name":"graph then compare","steps":[
   {"tool":"project_managed_application_graph","args":{"managed_artifact":ev("basic",A),"managed_members":ev("basic",M)}},
   {"tool":"compare_managed_members","args":{"left":ev("basic",M),"right":ev("il_rich",M)}},
   {"tool":"export_evidence_bundle","args":{"path":"/tmp/tracewise-oracle/bundle_tmp.json","overwrite":True}},
   {"tool":"list_unknowns","args":{}}]},
]
json.dump({"scenarios":scen,"sequences":seqs},open(FX+"/workflow_scenarios.json","w"),separators=(",",":"))
def run(calls,tag):
    json.dump(calls,open("/tmp/tracewise-oracle/wf_calls_%s.json"%tag,"w"))
    subprocess.run(["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/wf_raw_%s.json"%tag],stdin=open("/tmp/tracewise-oracle/wf_calls_%s.json"%tag),check=True)
    return json.load(open("/tmp/tracewise-oracle/wf_raw_%s.json"%tag))
def enc(r):
    if r.get("isError"): return {"error":r["content"][0]["text"]}
    return {"structuredContent":r["structuredContent"]}
out={"scenarios":[],"sequences":[]}
from concurrent.futures import ThreadPoolExecutor
def one(i):
    s=scen[i]
    raw=run([[s["tool"],resolve(s["args"])],["list_unknowns",{}]],"s%d"%i)
    return {"name":s["name"],"result":enc(raw[0]),"unknowns":enc(raw[1])}
with ThreadPoolExecutor(3) as pool:
    out["scenarios"]=list(pool.map(one,range(len(scen))))
for j,q in enumerate(seqs):
    raw=run([[st["tool"],resolve(st["args"])] for st in q["steps"]],"q%d"%j)
    out["sequences"].append({"name":q["name"],"results":[enc(r) for r in raw]})
json.dump(out,open(FX+"/oracle_workflows.json","w"),separators=(",",":"))
print(os.path.getsize(FX+"/oracle_workflows.json"), os.path.getsize(FX+"/workflow_scenarios.json"))
for o in out["scenarios"]:
    r=o["result"]; st="ERR" if "error" in r else "ok"
    nun=0 if "error" in o["unknowns"] else len(o["unknowns"]["structuredContent"]["result"]["items"])
    print(st, nun, o["name"], (r.get("error") or "")[:160])
for q in out["sequences"]:
    print(q["name"],[("ERR" if "error" in r else "ok") for r in q["results"]])
