import json,subprocess,os
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
from concurrent.futures import ThreadPoolExecutor
FX="/workspace/wt/managed_android/fixtures/android"
APK="/workspace/tools/fixtures-android/ApiDemos-debug.apk"
T="/workspace/tools/fixtures-android"
JDKBIN="/workspace/tools/temurin-21.0.5+11/bin"
HOST_PATH=os.environ["PATH"]
REAL="/workspace/tools/apktool-2.9.3/apktool"
FAKE=lambda n: f"{FX}/fake-apktool-{n}.sh"
PATH_WITH_JAVA=f"{JDKBIN}:{HOST_PATH}"
def d(**a): return ["decode_android_resources",{"path":APK,**a}]
scen=[]
def add(name,env,calls): scen.append({"name":name,"env":env,"calls":calls})
add("real core",{"REA_APKTOOL_COMMAND":REAL,"PATH":PATH_WITH_JAVA},[
 ["inspect_apktool_client",{}],
 d(),
 d(include_strings=False),
 d(locale="de"),
 d(locale="pt-BR"),
 d(locale="b+sr+Latn"),
 d(locale="en-rGB"),
 d(locale="zz"),
 d(locale="zz",include_strings=False),
 d(locale="not a locale"),
 d(locale="d"),
 d(include_strings="yes"),
 ["decode_android_resources",{"path":APK,"extra":True}],
 ["decode_android_resources",{"path":""}],
 ["decode_android_resources",{}],
 ["decode_android_resources",{"path":T+"/nope.apk"}],
 ["decode_android_resources",{"path":T}],
 ["decode_android_resources",{"path":T+"/not-a-zip.apk"}],
 ["decode_android_resources",{"path":T+"/truncated.apk"}],
 ["inspect_apktool_client",{"extra":1}],
])
add("no apktool",{"PATH":HOST_PATH},[["inspect_apktool_client",{}],d()])
add("relative command",{"REA_APKTOOL_COMMAND":"apktool","PATH":PATH_WITH_JAVA},[["inspect_apktool_client",{}],d()])
add("missing command",{"REA_APKTOOL_COMMAND":"/workspace/tools/nope/apktool"},[["inspect_apktool_client",{}],d()])
add("blank command falls back to PATH",{"REA_APKTOOL_COMMAND":"   ","PATH":HOST_PATH},[["inspect_apktool_client",{}]])
add("version fails",{"REA_APKTOOL_COMMAND":"/bin/false"},[["inspect_apktool_client",{}],d()])
add("version blank",{"REA_APKTOOL_COMMAND":"/bin/true"},[["inspect_apktool_client",{}],d()])
add("decode fails",{"REA_APKTOOL_COMMAND":FAKE("fail")},[["inspect_apktool_client",{}],d()])
add("fake big workspace",{"REA_APKTOOL_COMMAND":FAKE("big")},[["inspect_apktool_client",{}],d(),d(locale="de"),d(locale="pt-BR"),d(locale="fr"),d(include_strings=False)])
add("fake oversized files",{"REA_APKTOOL_COMMAND":FAKE("huge")},[d(),d(include_strings=False)])
json.dump(scen,open(FX+"/apktool_scenarios.json","w"),separators=(",",":"))
def run(i):
    s=scen[i]
    json.dump(s["calls"],open("/tmp/tracewise-oracle/pk_calls_%d.json"%i,"w"))
    args=["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/pk_raw_%d.json"%i]+["%s=%s"%(k,v) for k,v in s["env"].items()]
    subprocess.run(args,stdin=open("/tmp/tracewise-oracle/pk_calls_%d.json"%i),check=True)
    raw=json.load(open("/tmp/tracewise-oracle/pk_raw_%d.json"%i))
    return {"name":s["name"],"results":[({"error":r["content"][0]["text"]} if r.get("isError") else {"structuredContent":r["structuredContent"]}) for r in raw]}
with ThreadPoolExecutor(2) as pool: res=list(pool.map(run,range(len(scen))))
json.dump(res,open(FX+"/oracle_apktool.json","w"),separators=(",",":"))
for s,r in zip(scen,res):
    for call,o in zip(s["calls"],r["results"]):
        a=json.dumps({k:v for k,v in call[1].items() if k!="path"})[:60]
        if "error" in o: print(r["name"],"|",call[0],a,"ERR",o["error"][:700])
        else:
            n=o["structuredContent"]["normalized_result"]
            print(r["name"],"|",call[0],a,"ok",o["structuredContent"]["limitations"][1:], (n.get("coverage"),len(n.get("strings",[])),len(n.get("locales",[])),n.get("decoded_file_count")) if "strings" in n else n)
