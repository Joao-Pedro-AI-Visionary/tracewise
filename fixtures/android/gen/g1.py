import json,subprocess
import os as _os; _os.makedirs("/tmp/tracewise-oracle", exist_ok=True)
APK="/workspace/tools/fixtures-android/ApiDemos-debug.apk"
subprocess.run(["python3","/workspace/wt/managed_android/fixtures/android/gen/oracle.py","/tmp/tracewise-oracle/g1_out.json"],input=json.dumps([["open_binary",{"path":APK}],["inspect_artifact",{}]]).encode(),check=True)
o=json.load(open("/tmp/tracewise-oracle/g1_out.json"))
print([("ERR" if x.get("isError") else "ok") for x in o])
ev=o[1]["structuredContent"]
print(ev["operation"], list(ev["normalized_result"].keys()))
inv=ev["normalized_result"]["substeps"][0]["evidence"]["normalized_result"]
print(inv["manifest"], len(inv["nodes"]), len(inv["occurrences"]), len(inv["edges"]))
json.dump(ev,open("/tmp/tracewise-oracle/apk_inspect_artifact.json","w"))
import os; print(os.path.getsize("/tmp/tracewise-oracle/apk_inspect_artifact.json"))
