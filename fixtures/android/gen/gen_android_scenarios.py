import json,subprocess,os,sys
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
from concurrent.futures import ThreadPoolExecutor
FX="/workspace/wt/managed_android/fixtures/android"
os.makedirs(FX,exist_ok=True)
APK="/workspace/tools/fixtures-android/ApiDemos-debug.apk"
JAR="/workspace/tools/jadx-headless-mcp-0.7.1/jadx-headless-mcp-0.7.1-all.jar"
JDK="/workspace/tools/temurin-21.0.5+11"
GOOD={"REA_JADX_MCP_JAR":JAR,"JAVA_HOME":JDK}
MAN="/workspace/wt/managed_android/fixtures/managed"
# derived fixtures (kept out of git: written next to the APK in tools)
os.makedirs("/workspace/tools/fixtures-android",exist_ok=True)
raw=open(APK,"rb").read()
open("/workspace/tools/fixtures-android/truncated.apk","wb").write(raw[:200000])
open("/workspace/tools/fixtures-android/not-a-zip.apk","wb").write(b"this is not an apk\n"*10)
open("/workspace/tools/fixtures-android/ApiDemos-debug.zip","wb").write(raw)
T="/workspace/tools/fixtures-android"
AC="androidx.appcompat.app.AppCompatActivity"
D="io.appium.android.apis.ApiDemos"
def c(tool,**a): return [tool,{"path":APK,**a}]
scen=[]
def add(name,env,calls): scen.append({"name":name,"env":env,"calls":calls})
add("core",GOOD,[
 c("inspect_android_package"),
 c("search_android_classes",query="ApiDemos"),
 c("search_android_classes",query=""),
 c("search_android_classes",query="zzzNoSuchClass"),
 c("search_android_classes",query="apidemos"),
 c("inspect_android_class",class_name=D),
 c("inspect_android_class",class_name=AC),
 c("inspect_android_class",class_name="io.appium.android.apis.DoesNotExist"),
 c("inspect_android_class",class_name="ApiDemos"),
 c("inspect_android_method",class_name=D,method_name="onCreate"),
 c("inspect_android_method",class_name=D,method_name="onCreate",overload_index=0),
 c("inspect_android_method",class_name=D,method_name="onCreate",overload_index=3),
 c("inspect_android_method",class_name=D,method_name="noSuchMethod"),
 c("inspect_android_method",class_name=AC,method_name="setContentView"),
 c("inspect_android_method",class_name=AC,method_name="setContentView",overload_index=0),
 c("inspect_android_method",class_name=AC,method_name="setContentView",overload_index=1),
 c("inspect_android_method",class_name=AC,method_name="setContentView",overload_index=2),
 c("inspect_android_method",class_name=AC,method_name="setContentView",overload_index=9),
 c("inspect_android_method",class_name=AC,method_name="<init>",overload_index=1),
 c("inspect_android_method",class_name=AC,method_name="onCreate"),
 c("inspect_android_method",class_name="io.appium.android.apis.ApiDemos$Missing",method_name="x"),
 c("trace_android_references",class_name=D),
 c("trace_android_references",class_name=D,method_name="onCreate"),
 c("trace_android_references",class_name=AC),
 c("trace_android_references",class_name=AC,method_name="setContentView"),
 c("trace_android_references",class_name=AC,method_name="onCreate"),
 c("trace_android_references",class_name=AC,method_name="noSuch"),
 c("trace_android_references",class_name="no.Such"),
])
add("sdk-validation",GOOD,[
 ["inspect_android_package",{}],
 ["inspect_android_package",{"path":APK,"extra":1}],
 ["inspect_android_class",{"path":APK}],
 ["inspect_android_class",{"path":APK,"class_name":""}],
 ["inspect_android_method",{"path":APK,"class_name":D,"method_name":"onCreate","overload_index":-1}],
 ["inspect_android_method",{"path":APK,"class_name":D,"method_name":"onCreate","overload_index":1.5}],
 ["search_android_classes",{"path":APK}],
 ["inspect_android_package",{"path":""}],
 ["inspect_android_package",{"path":"relative.apk"}],
])
add("no-config",{},[c("inspect_android_package"),c("search_android_classes",query="x")])
add("jar-relative",{"REA_JADX_MCP_JAR":"jadx.jar","JAVA_HOME":JDK},[c("inspect_android_package")])
add("jar-missing",{"REA_JADX_MCP_JAR":"/workspace/tools/nope.jar","JAVA_HOME":JDK},[c("inspect_android_package")])
add("jar-directory",{"REA_JADX_MCP_JAR":"/workspace/tools","JAVA_HOME":JDK},[c("inspect_android_package")])
add("jar-not-zip",{"REA_JADX_MCP_JAR":T+"/not-a-zip.apk","JAVA_HOME":JDK},[c("inspect_android_package")])
add("jar-wrong-classes",{"REA_JADX_MCP_JAR":APK,"JAVA_HOME":JDK},[c("inspect_android_package")])
add("java-missing",{"REA_JADX_MCP_JAR":JAR,"JAVA_HOME":"/workspace/tools/nojdk"},[c("inspect_android_package")])
add("java-no-java-on-path",{"REA_JADX_MCP_JAR":JAR},[c("inspect_android_package")])
add("heap-invalid",{**GOOD,"REA_JADX_HEAP_MIB":"abc"},[c("inspect_android_package")])
add("cpu-invalid",{**GOOD,"REA_JADX_ACTIVE_PROCESSOR_COUNT":"0"},[c("inspect_android_package")])
add("cpu-too-big",{**GOOD,"REA_JADX_ACTIVE_PROCESSOR_COUNT":"3000000000"},[c("inspect_android_package")])
add("heap-1024",{**GOOD,"REA_JADX_HEAP_MIB":"1024","REA_JADX_ACTIVE_PROCESSOR_COUNT":"2"},[c("inspect_android_package"),c("inspect_android_class",class_name=D)])
add("targets",GOOD,[
 ["inspect_android_package",{"path":MAN+"/basic.dll"}],
 ["inspect_android_package",{"path":T+"/nope.apk"}],
 ["inspect_android_package",{"path":T+"/not-a-zip.apk"}],
 ["inspect_android_package",{"path":T+"/ApiDemos-debug.zip"}],
 ["inspect_android_package",{"path":T}],
 ["inspect_android_package",{"path":T+"/truncated.apk"}],
 ["inspect_android_class",{"path":T+"/truncated.apk","class_name":D}],
 ["inspect_android_package",{"path":APK}],
])
json.dump(scen,open(FX+"/android_scenarios.json","w"),indent=0)

def run(i):
    s=scen[i]
    json.dump(s["calls"],open("/tmp/tracewise-oracle/an_calls_%d.json"%i,"w"))
    args=["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/an_raw_%d.json"%i]+["%s=%s"%(k,v) for k,v in s["env"].items()]
    subprocess.run(args,stdin=open("/tmp/tracewise-oracle/an_calls_%d.json"%i),check=True)
    raw=json.load(open("/tmp/tracewise-oracle/an_raw_%d.json"%i))
    out=[]
    for r in raw:
        if r.get("isError"): out.append({"error":r["content"][0]["text"]})
        else: out.append({"structuredContent":r["structuredContent"]})
    return {"name":s["name"],"results":out}
with ThreadPoolExecutor(2) as pool:
    res=list(pool.map(run,range(len(scen))))
json.dump(res,open(FX+"/oracle_android.json","w"),separators=(",",":"))
print(os.path.getsize(FX+"/oracle_android.json"))
for s,r in zip(scen,res):
    for call,o in zip(s["calls"],r["results"]):
        st="ERR" if "error" in o else "ok"
        print(r["name"],call[0],json.dumps({k:v for k,v in call[1].items() if k!="path"})[:80],st,(o.get("error") or "")[:260])
