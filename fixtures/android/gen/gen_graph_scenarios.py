import json,subprocess,os
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
from concurrent.futures import ThreadPoolExecutor
FX="/workspace/wt/managed_android/fixtures/android"
inputs=json.load(open("/tmp/tracewise-oracle/graph_inputs.json"))
managed=json.load(open("/workspace/wt/managed_android/fixtures/managed/oracle_inspect.json"))
inputs["managed_artifact_basic"]=managed["basic"]["inspect_managed_artifact"]["structuredContent"]
json.dump(inputs,open(FX+"/graph_inputs.json","w"),separators=(",",":"))
def g(n): return {"$g":n}
scen=[
 ("real apk inventory",{"inventory_evidence":[g("real")]}),
 ("partial inventory",{"inventory_evidence":[g("partial")]}),
 ("duplicate pages",{"inventory_evidence":[g("real"),g("real")]}),
 ("partial plus complete",{"inventory_evidence":[g("partial"),g("real")]}),
 ("conventions",{"inventory_evidence":[g("conventions")]}),
 ("no manifest",{"inventory_evidence":[g("nomanifest")]}),
 ("not an apk",{"inventory_evidence":[g("notapk")]}),
 ("synthetic complete counts",{"inventory_evidence":[g("complete_synthetic")]}),
 ("bridge budget",{"inventory_evidence":[g("big_bridge")]}),
 ("tampered",{"inventory_evidence":[g("tampered")]}),
 ("wrong operation",{"inventory_evidence":[g("managed_artifact_basic")]}),
 ("empty list",{"inventory_evidence":[]}),
 ("missing list",{}),
 ("unknown key",{"inventory_evidence":[g("real")],"limits":{}}),
 ("invalid node format",{"inventory_evidence":[g("badformat")]}),
 ("mixed manifests",{"inventory_evidence":[g("real"),g("conventions")]}),
]
def resolve(x):
    if isinstance(x,dict):
        if "$g" in x: return inputs[x["$g"]]
        return {k:resolve(v) for k,v in x.items()}
    if isinstance(x,list): return [resolve(i) for i in x]
    return x
json.dump([{"name":n,"args":a} for n,a in scen],open(FX+"/graph_scenarios.json","w"),separators=(",",":"))
def run(i):
    n,a=scen[i]
    json.dump([["project_android_application_graph",resolve(a)],["list_unknowns",{}]],open("/tmp/tracewise-oracle/gr_calls_%d.json"%i,"w"))
    subprocess.run(["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/gr_raw_%d.json"%i],stdin=open("/tmp/tracewise-oracle/gr_calls_%d.json"%i),check=True)
    raw=json.load(open("/tmp/tracewise-oracle/gr_raw_%d.json"%i))[0]
    return {"name":n,"result":({"error":raw["content"][0]["text"]} if raw.get("isError") else {"structuredContent":raw["structuredContent"]})}
with ThreadPoolExecutor(3) as pool: res=list(pool.map(run,range(len(scen))))
json.dump(res,open(FX+"/oracle_android_graph.json","w"),separators=(",",":"))
for r in res:
    x=r["result"]
    if "error" in x: print("ERR",r["name"],x["error"][:300])
    else:
        n=x["structuredContent"]["normalized_result"]
        print("ok ",r["name"],n["coverage"],n["runtime_families"],{k:len(v) for k,v in n["components"].items()},n["bridge_candidate_coverage"],len(n["limitations"]))
print({k:os.path.getsize(FX+"/"+k) for k in os.listdir(FX)})
