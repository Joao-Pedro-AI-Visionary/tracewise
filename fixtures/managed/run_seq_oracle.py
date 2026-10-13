import json,subprocess,os,sys
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
FX="/workspace/wt/managed_android/fixtures/managed"
D="$DIR"
seqs={
 "select_and_reuse":[
  ["inspect_managed_artifact",{}],
  ["inspect_managed_artifact",{"path":D+"/nonexistent.dll"}],
  ["inspect_managed_artifact",{"path":D+"/target_notes.txt"}],
  ["inspect_managed_artifact",{"path":D+"/native.dll"}],
  ["inspect_managed_artifact",{"path":"relative.dll"}],
  ["inspect_managed_members",{}],
  ["inspect_managed_artifact",{"path":D+"/basic.dll"}],
  ["inspect_managed_members",{}],
  ["inspect_managed_native_boundaries",{}],
  ["inspect_managed_artifact",{"path":D+"/../managed/pinvoke.dll"}],
  ["inspect_managed_native_boundaries",{}],
 ],
 "target_kinds":[
  ["inspect_managed_artifact",{"path":D+"/target_elf64.bin"}],
  ["inspect_managed_members",{"path":D+"/target_sample.zip"}],
  ["inspect_managed_native_boundaries",{"path":D+"/target_script.js"}],
  ["inspect_managed_artifact",{"path":D}],
  ["inspect_managed_artifact",{"path":""}],
  ["inspect_managed_artifact",{"path":D+"/basic.dll","extra":1}],
  ["inspect_managed_artifact",{"path":7}],
  ["inspect_managed_artifact",{"path":"/tmp/x\u0000y"}],
 ],
}
out={}
for name,steps in seqs.items():
    calls=[[t,json.loads(json.dumps(a).replace("$DIR",FX))] for t,a in steps]
    open("/tmp/tracewise-oracle/seq_calls.json","w").write(json.dumps(calls))
    subprocess.run(["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/seq_raw.json"],stdin=open("/tmp/tracewise-oracle/seq_calls.json"),check=True)
    raw=json.load(open("/tmp/tracewise-oracle/seq_raw.json"))
    res=[]
    for r in raw:
        if r.get("isError"): res.append({"error":r["content"][0]["text"]})
        else: res.append({"structuredContent":r["structuredContent"]})
    out[name]={"steps":[{"tool":t,"args":a} for t,a in steps],"results":res}
json.dump(out,open(FX+"/oracle_sequences.json","w"),indent=1)
print({k:len(v["results"]) for k,v in out.items()})
