import json,subprocess,sys,os,glob
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
FX="/workspace/wt/managed_android/fixtures/managed"
names=sorted(os.path.basename(p)[:-4] for p in glob.glob(FX+"/*.dll"))
calls=[]
index=[]
for n in names:
    for tool in ["inspect_managed_artifact","inspect_managed_members","inspect_managed_native_boundaries"]:
        calls.append([tool,{"path":f"{FX}/{n}.dll"}])
        index.append((n,tool))
open("/tmp/tracewise-oracle/calls_managed.json","w").write(json.dumps(calls))
subprocess.run(["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/raw_managed.json"],stdin=open("/tmp/tracewise-oracle/calls_managed.json"),check=True)
raw=json.load(open("/tmp/tracewise-oracle/raw_managed.json"))
out={}
for (n,tool),r in zip(index,raw):
    if r.get("isError"):
        out.setdefault(n,{})[tool]={"error":r["content"][0]["text"]}
    else:
        out.setdefault(n,{})[tool]={"structuredContent":r["structuredContent"]}
json.dump(out,open("/tmp/tracewise-oracle/oracle_managed.json","w"),indent=None,separators=(",",":"))
print(len(out),"files",os.path.getsize("/tmp/tracewise-oracle/oracle_managed.json"),"bytes")
