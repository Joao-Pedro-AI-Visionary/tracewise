use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const DEMO_HAR: &str = "/workspace/tracewise/fixtures/web/demo.har";

fn validate_output_schema(structured: &Value) {
    let tools_val = tracewise_contracts::tracewise_tools_value();
    let tool = tools_val["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "generate_api_client")
        .expect("generate_api_client schema");
    let validator = jsonschema::validator_for(&tool["outputSchema"])
        .unwrap_or_else(|err| panic!("outputSchema failed to compile: {err}"));
    if let Err(first) = validator.validate(structured) {
        let errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|err| format!("path: {}, error: {err}", err.instance_path()))
            .collect();
        panic!(
            "structuredContent failed outputSchema validation:\n{first}\n{}",
            errors.join("\n")
        );
    }
}

fn file_map(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("read dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path
                    .strip_prefix(dir)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.insert(relative, std::fs::read(&path).expect("read file"));
            }
        }
    }
    files
}

async fn generate(session: &BinarySession, spec_path: &Path, output: &Path) -> Value {
    let res = call_tool_local(
        session,
        CallToolRequestParam {
            name: "generate_api_client".into(),
            arguments: Some(
                json!({
                    "spec_path": spec_path,
                    "languages": ["typescript", "python"],
                    "output_directory": output,
                    "replay_capture_path": DEMO_HAR,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("generate_api_client failed");
    let text = serde_json::to_string(&res).expect("serialize");
    assert!(!text.contains("SECRET-"), "tool output leaked a credential");
    res.structured_content.expect("structured content")
}

#[tokio::test]
async fn test_generate_api_client_from_demo_har() {
    let session = BinarySession::new();
    let root = std::env::temp_dir().join(format!("tracewise-api-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("temp root");
    let spec_path = root.join("spec.json");
    let dir_a = root.join("a");
    let dir_b = root.join("b");
    std::fs::create_dir_all(&dir_a).expect("dir a");
    std::fs::create_dir_all(&dir_b).expect("dir b");

    call_tool_local(
        &session,
        CallToolRequestParam {
            name: "infer_api_spec".into(),
            arguments: Some(
                json!({
                    "capture_path": DEMO_HAR,
                    "output_path": &spec_path,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("infer_api_spec failed");

    let first = generate(&session, &spec_path, &dir_a).await;
    let second = generate(&session, &spec_path, &dir_b).await;
    validate_output_schema(&first);
    assert_eq!(first["predicate_type"], "tracewise.api-client");
    assert_eq!(first["operation"], "generate_api_client");
    assert_eq!(first["confidence"], "inferred");
    assert_eq!(first["normalized_result"]["package_name"], "inferred_api");
    let files_a = &first["normalized_result"]["files"];
    let files_b = &second["normalized_result"]["files"];
    assert_eq!(
        files_a, files_b,
        "generation must be deterministic across directories"
    );
    assert!(files_a.as_array().expect("files").len() > 5);

    let replay: Value = serde_json::from_str(
        &std::fs::read_to_string(dir_a.join("typescript/fixtures/replay.json")).expect("replay"),
    )
    .expect("replay json");
    assert_eq!(
        replay.as_array().expect("cases").len(),
        5,
        "demo.har replay cases"
    );
    assert!(!serde_json::to_string(&replay).unwrap().contains("SECRET-"));

    let ts_client =
        std::fs::read_to_string(dir_a.join("typescript/src/client.ts")).expect("ts client");
    assert!(ts_client.contains("getApiTodosById"));
    assert!(ts_client.contains("async getApiMe"));
    let py_client =
        std::fs::read_to_string(dir_a.join("python/inferred_api/client.py")).expect("py client");
    assert!(py_client.contains("def get_api_todos_by_id"));
    assert!(py_client.contains("def get_api_me"));

    let on_disk = file_map(&dir_a);
    let on_disk_b = file_map(&dir_b);
    assert_eq!(on_disk, on_disk_b);
    for file in files_a.as_array().expect("files") {
        let relative = file["path"].as_str().expect("path");
        let bytes = on_disk
            .get(relative)
            .unwrap_or_else(|| panic!("missing {relative}"));
        assert_eq!(bytes.len(), file["bytes"].as_u64().unwrap() as usize);
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        assert_eq!(
            hex::encode(hasher.finalize()),
            file["sha256"].as_str().unwrap()
        );
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("SECRET-"), "{relative} leaked a credential");
    }

    let again = generate(&session, &spec_path, &dir_a).await;
    assert_eq!(first["evidence_id"], again["evidence_id"]);

    let py_dir = dir_a.join("python");
    let python = Command::new("python3")
        .arg("-m")
        .arg("unittest")
        .arg("discover")
        .arg("-s")
        .arg(&py_dir)
        .arg("-p")
        .arg("test_*.py")
        .current_dir(&py_dir)
        .output()
        .expect("python3");
    assert!(
        python.status.success(),
        "python unittest failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&python.stdout),
        String::from_utf8_lossy(&python.stderr)
    );

    let node = Path::new("/tmp/node-v22.20.0-linux-x64/bin/node");
    if node.exists() {
        let bin = node.parent().expect("node bin");
        let path_var = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let ts_dir = dir_a.join("typescript");
        // `npx -y -p typescript tsc` is parsed as a file argument, so the
        // compiler reports TS5112 (tsconfig present, files specified). The
        // `--` separator makes npx invoke the typescript package's tsc.
        let tsc = Command::new(bin.join("npx"))
            .arg("--yes")
            .arg("--package=typescript")
            .arg("--")
            .arg("tsc")
            .arg("--pretty")
            .arg("false")
            .current_dir(&ts_dir)
            .env("PATH", &path_var)
            .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
            .output()
            .expect("npx tsc");
        assert!(
            tsc.status.success(),
            "tsc failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&tsc.stdout),
            String::from_utf8_lossy(&tsc.stderr)
        );
        let node_test = Command::new(node)
            .arg("--test")
            .arg("dist/test/replay.test.js")
            .current_dir(&ts_dir)
            .env("PATH", &path_var)
            .output()
            .expect("node --test");
        assert!(
            node_test.status.success(),
            "node --test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&node_test.stdout),
            String::from_utf8_lossy(&node_test.stderr)
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
