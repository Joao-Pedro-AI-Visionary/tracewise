//! The 24 `*_adb_*` tools against the ORIGINAL REA.
//!
//! Method (live oracle, no recorded goldens): every case runs twice on the same
//! scripted device, once through the original REA MCP server
//! (`fixtures/rea_oracle.py`, node) and once through the Rust server, each time
//! from a freshly seeded sandbox at the SAME absolute paths. The device is
//! `fixtures/adb/fake-adb`, a script that imitates adb 34 (`devices -l`,
//! toybox `ls`/`ps`, `pm`, `dumpsys`, `settings`, `am`, install/uninstall, pull,
//! push, screencap, bugreport) and is selected through `REA_ADB_PATH`, exactly
//! like the real binary. There is no adb binary and no emulator in this
//! environment, so this is the REA test strategy (a fake adb) and not a real
//! device run.
//!
//! What is compared per case, with NO ignored fields:
//! - the complete MCP result: `isError`, `structuredContent` (Evidence,
//!   including `evidence_id`, which hashes the adb path, version, parameters,
//!   result and limitations) and the text content;
//! - the argv of every adb invocation, in order (`state/argv.log`), which proves
//!   the Rust port issues the same commands as REA, quoting included;
//! - the side effects: the sandbox tree (pulled files, bugreport, screenshot,
//!   pushed files on the fake device, the fake package database).
//!
//! Every success is also validated against the catalog `outputSchema`.
//! Each case declares what the oracle must answer (ok / projected error code /
//! plain text) so a broken scenario cannot pass vacuously.
//!
//! Limits (documented, not ported): cancellation mid-run. REA returns the
//! acquired facts as `partial_observation` when a pull/digest is cancelled; the
//! Rust server drops the future (child processes are killed) and reports no
//! partial observation. Not exercised here: it needs a client-side MCP cancel.
//! The 5 second SIGTERM-to-SIGKILL grace and the 30-600 s deadlines are not
//! driven either (unit-level `exec` behaviour is covered by the crate tests).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const E: &str = "emulator-5554";
/// Per-checkout scratch (`target/tmp`): concurrent runs never share a sandbox.
const SANDBOX_ROOT: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/adb-parity");

/// Process-wide environment and the sandbox paths are shared state.
static SERIAL: Mutex<()> = Mutex::const_new(());

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn fake_adb() -> PathBuf {
    let path = repo_root().join("fixtures/adb/fake-adb");
    // The executable bit is part of the fixture contract; restore it if a
    // checkout or an editor dropped it.
    let mut permissions = fs::metadata(&path).expect("fake adb").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod fake adb");
    path
}

fn oracle_available() -> bool {
    tracewise_device::testing::require_or_skip("adb_tools_test", &tracewise_device::testing::rea_oracle_missing())
}

fn outcome_schema(tool: &str) -> Value {
    let tools: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).expect("phase3 json");
    tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("{tool} in phase3"))["outputSchema"]
        .clone()
}

// ------------------------------------------------------------- sandbox ----

struct Dirs {
    base: PathBuf,
}

impl Dirs {
    fn new(group: &str) -> Self {
        Dirs { base: Path::new(SANDBOX_ROOT).join(group) }
    }
    fn device(&self) -> PathBuf {
        self.base.join("device")
    }
    fn state(&self) -> PathBuf {
        self.base.join("state")
    }
    fn out(&self) -> PathBuf {
        self.base.join("out")
    }
    fn local(&self) -> PathBuf {
        self.base.join("local")
    }
}

fn make_writable(path: &Path) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return;
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        let _ = fs::set_permissions(path, permissions);
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    make_writable(&entry.path());
                }
            }
        }
    }
}

/// Fresh sandbox: fake device filesystem, fake package state, output and local dirs.
fn prepare(dirs: &Dirs, setup: Option<fn(&Dirs)>) {
    make_writable(&dirs.base);
    let _ = fs::remove_dir_all(&dirs.base);
    let tmp = dirs.device().join("data/local/tmp");
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("notes.txt"), b"hello adb!").unwrap();
    std::os::unix::fs::symlink("notes.txt", tmp.join("link")).unwrap();
    fs::create_dir_all(tmp.join("sub")).unwrap();
    fs::create_dir_all(tmp.join("dir with space")).unwrap();
    fs::write(tmp.join("dir with space/file one.txt"), b"x").unwrap();
    fs::create_dir_all(dirs.state()).unwrap();
    fs::create_dir_all(dirs.out()).unwrap();
    fs::create_dir_all(dirs.local()).unwrap();
    fs::write(dirs.local().join("payload.bin"), b"PAYLOAD-0123").unwrap();
    fs::write(dirs.local().join("test.apk"), b"apk bytes of a new app").unwrap();
    fs::write(dirs.local().join("com.example.app.apk"), b"apk bytes of an installed app").unwrap();
    if let Some(setup) = setup {
        setup(dirs);
    }
}

fn snapshot(dirs: &Dirs) -> BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if relative == "state/argv.log" {
                continue;
            }
            if metadata.file_type().is_symlink() {
                out.insert(relative, format!("link->{}", fs::read_link(&path).unwrap().display()));
            } else if metadata.is_dir() {
                out.insert(relative.clone(), format!("dir {:o}", metadata.permissions().mode() & 0o777));
                walk(root, &path, out);
            } else {
                let digest = hex::encode(Sha256::digest(fs::read(&path).unwrap()));
                out.insert(relative, format!("file {digest}"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&dirs.base, &dirs.base, &mut out);
    out
}

fn argv_log(dirs: &Dirs) -> Vec<String> {
    fs::read_to_string(dirs.state().join("argv.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

// --------------------------------------------------------------- cases ----

#[derive(Clone, Copy)]
enum Adb {
    Fake,
    Raw(&'static str),
    Unset,
}

/// What the oracle is expected to answer.
#[derive(Clone, Copy)]
enum Expect {
    Ok,
    /// Projected analysis error with this `code`.
    Code(&'static str),
    /// Plain-text error starting with this prefix.
    Text(&'static str),
}

struct Case {
    label: String,
    tool: &'static str,
    args: Value,
    mode: Option<&'static str>,
    adb: Adb,
    version_fail: bool,
    setup: Option<fn(&Dirs)>,
    expect: Expect,
}

fn case(label: &str, tool: &'static str, args: Value, expect: Expect) -> Case {
    Case {
        label: label.to_string(),
        tool,
        args,
        mode: None,
        adb: Adb::Fake,
        version_fail: false,
        setup: None,
        expect,
    }
}

impl Case {
    fn mode(mut self, mode: &'static str) -> Self {
        self.mode = Some(mode);
        self
    }
    fn adb(mut self, adb: Adb) -> Self {
        self.adb = adb;
        self
    }
    fn version_fail(mut self) -> Self {
        self.version_fail = true;
        self
    }
    fn setup(mut self, setup: fn(&Dirs)) -> Self {
        self.setup = Some(setup);
        self
    }
}

fn substitute(args: &Value, dirs: &Dirs) -> Value {
    let text = args
        .to_string()
        .replace("{OUT}", &dirs.out().to_string_lossy())
        .replace("{LOCAL}", &dirs.local().to_string_lossy())
        .replace("{BASE}", &dirs.base.to_string_lossy());
    serde_json::from_str(&text).unwrap()
}

fn apply_env(case: &Case, dirs: &Dirs) {
    match case.adb {
        Adb::Fake => std::env::set_var("REA_ADB_PATH", fake_adb()),
        Adb::Raw(value) => std::env::set_var("REA_ADB_PATH", value),
        Adb::Unset => std::env::remove_var("REA_ADB_PATH"),
    }
    std::env::set_var("FAKE_ADB_STATE", dirs.state());
    std::env::set_var("FAKE_ADB_DEVICE_ROOT", dirs.device());
    match case.mode {
        Some(mode) => std::env::set_var("FAKE_ADB_MODE", mode),
        None => std::env::remove_var("FAKE_ADB_MODE"),
    }
    if case.version_fail {
        std::env::set_var("FAKE_ADB_VERSION_FAIL", "1");
    } else {
        std::env::remove_var("FAKE_ADB_VERSION_FAIL");
    }
}

#[derive(Debug)]
struct Observed {
    is_error: bool,
    structured: Option<Value>,
    text: String,
}

fn run_oracle(group: &str, tool: &str, args: &Value) -> Observed {
    let calls = Path::new(SANDBOX_ROOT).join(format!("{group}-oracle-args.json"));
    let output = Path::new(SANDBOX_ROOT).join(format!("{group}-oracle-out.json"));
    fs::create_dir_all(SANDBOX_ROOT).unwrap();
    fs::write(&calls, args.to_string()).unwrap();
    let _ = fs::remove_file(&output);
    let status = Command::new("python3")
        .arg(repo_root().join("fixtures/rea_oracle.py"))
        .arg(tool)
        .arg(format!("@{}", calls.display()))
        .arg(&output)
        .status()
        .expect("python3");
    assert!(status.success(), "oracle process failed for {tool}");
    let raw: Value = serde_json::from_str(&fs::read_to_string(&output).expect("oracle output")).unwrap();
    observed_from(&raw)
}

fn observed_from(raw: &Value) -> Observed {
    Observed {
        is_error: raw["isError"] == true,
        structured: raw.get("structuredContent").cloned(),
        text: raw["content"][0]["text"].as_str().unwrap_or_default().to_string(),
    }
}

async fn run_rust(tool: &str, args: &Value) -> Observed {
    let session = BinarySession::new();
    let outcome = call_tool_local(
        &session,
        CallToolRequestParam {
            name: tool.to_string().into(),
            arguments: Some(args.as_object().unwrap().clone()),
        },
    )
    .await;
    match outcome {
        Ok(result) => observed_from(&to_json(&result)),
        Err(error) => Observed { is_error: true, structured: None, text: format!("PROTOCOL ERROR: {error}") },
    }
}

fn to_json(result: &CallToolResult) -> Value {
    serde_json::to_value(result).unwrap()
}

fn text_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

fn check_expectation(case: &Case, oracle: &Observed) -> Result<(), String> {
    match case.expect {
        Expect::Ok => {
            if oracle.is_error {
                return Err(format!("oracle answered an error, expected success: {}", oracle.text));
            }
            if oracle.structured.is_none() {
                return Err("oracle success without structuredContent".to_string());
            }
        }
        Expect::Code(code) => {
            let body = text_json(&oracle.text);
            if !oracle.is_error || body["error"]["code"] != code {
                return Err(format!("oracle did not answer error code {code}: {}", oracle.text));
            }
        }
        Expect::Text(prefix) => {
            if !oracle.is_error || !oracle.text.starts_with(prefix) {
                return Err(format!("oracle did not answer text starting {prefix:?}: {}", oracle.text));
            }
        }
    }
    Ok(())
}

fn short(value: &impl std::fmt::Debug) -> String {
    let text = format!("{value:#?}");
    if text.len() > 3500 {
        format!("{}...", &text[..3500])
    } else {
        text
    }
}

/// Run one case against the oracle and the port; Err carries the differences.
async fn compare_case(group: &str, dirs: &Dirs, case: &Case) -> Result<(), String> {
    apply_env(case, dirs);
    let args = |dirs: &Dirs| substitute(&case.args, dirs);

    prepare(dirs, case.setup);
    let oracle = run_oracle(group, case.tool, &args(dirs));
    let oracle_tree = snapshot(dirs);
    let oracle_argv = argv_log(dirs);
    check_expectation(case, &oracle)?;

    prepare(dirs, case.setup);
    let rust = run_rust(case.tool, &args(dirs)).await;
    let rust_tree = snapshot(dirs);
    let rust_argv = argv_log(dirs);

    let mut problems = Vec::new();
    if oracle.is_error != rust.is_error {
        problems.push(format!("isError oracle={} rust={}", oracle.is_error, rust.is_error));
    }
    if oracle.is_error {
        if text_json(&oracle.text) != text_json(&rust.text) {
            problems.push(format!("error body differs\n oracle: {}\n rust:   {}", oracle.text, rust.text));
        }
    } else {
        if oracle.structured != rust.structured {
            problems.push(format!(
                "structuredContent differs\n oracle: {}\n rust:   {}",
                short(&oracle.structured),
                short(&rust.structured)
            ));
        }
        if text_json(&oracle.text) != text_json(&rust.text) {
            problems.push("text content differs".to_string());
        }
        if let Some(structured) = &rust.structured {
            let validator = jsonschema::validator_for(&outcome_schema(case.tool)).expect("schema");
            if let Err(error) = validator.validate(structured) {
                problems.push(format!("outputSchema: {error}"));
            }
        }
    }
    if oracle_argv != rust_argv {
        problems.push(format!("adb argv differs\n oracle: {oracle_argv:#?}\n rust:   {rust_argv:#?}"));
    }
    if oracle_tree != rust_tree {
        problems.push(format!("sandbox side effects differ\n oracle: {oracle_tree:#?}\n rust:   {rust_tree:#?}"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

async fn run_group(group: &str, cases: Vec<Case>) {
    if !oracle_available() {
        return;
    }
    let _guard = SERIAL.lock().await;
    let dirs = Dirs::new(group);
    let mut failures = Vec::new();
    for case in &cases {
        if let Err(problem) = compare_case(group, &dirs, case).await {
            failures.push(format!("[{}] {} {}\n{problem}", case.label, case.tool, case.args));
        }
    }
    let _ = fs::remove_dir_all(Path::new(SANDBOX_ROOT).join(group));
    assert!(failures.is_empty(), "{} of {} cases differ:\n\n{}", failures.len(), cases.len(), failures.join("\n\n"));
    eprintln!("{group}: {} cases identical to the oracle", cases.len());
}

// ------------------------------------------------------------- scenarios ----

fn lock_out_dir(dirs: &Dirs) {
    let locked = dirs.out().join("ro");
    fs::create_dir_all(&locked).unwrap();
    let mut permissions = fs::metadata(&locked).unwrap().permissions();
    permissions.set_mode(0o555);
    fs::set_permissions(&locked, permissions).unwrap();
}

fn existing_package_dir(dirs: &Dirs) {
    fs::create_dir_all(dirs.out().join("com.example.app")).unwrap();
}

fn existing_notes(dirs: &Dirs) {
    fs::write(dirs.out().join("notes.txt"), b"already here").unwrap();
}

fn existing_screen(dirs: &Dirs) {
    fs::write(dirs.out().join("screen.png"), b"old").unwrap();
}

#[tokio::test]
async fn inspection_tools_match_rea() {
    let cases = vec![
        case("client", "inspect_adb_client", json!({}), Expect::Ok),
        case("devices", "list_adb_devices", json!({}), Expect::Ok),
        case("devices garbage", "list_adb_devices", json!({}), Expect::Code("unreadable_output")).mode("garbage_devices"),
        case("device", "inspect_adb_device", json!({"serial": E}), Expect::Ok),
        case("device unknown serial", "inspect_adb_device", json!({"serial": "ghost-1"}), Expect::Code("unsupported_target")),
        case("device offline", "inspect_adb_device", json!({"serial": "OFFLINE"}), Expect::Code("unsupported_target")),
        case("device unauthorized", "inspect_adb_device", json!({"serial": E}), Expect::Code("unsupported_target"))
            .mode("unauthorized_all"),
        case("packages default scope", "list_adb_packages", json!({"serial": E}), Expect::Ok),
        case("packages third_party", "list_adb_packages", json!({"serial": E, "scope": "third_party"}), Expect::Ok),
        case("packages system", "list_adb_packages", json!({"serial": E, "scope": "system"}), Expect::Ok),
        case("packages unparsed line", "list_adb_packages", json!({"serial": E}), Expect::Ok).mode("garbage_ps"),
        case("package details", "inspect_adb_package", json!({"serial": E, "package": "com.example.app"}), Expect::Ok),
        case("package missing", "inspect_adb_package", json!({"serial": E, "package": "com.missing"}), Expect::Code("unsupported_target")),
        case("logcat default", "read_adb_logcat", json!({"serial": E}), Expect::Ok),
        case("logcat count", "read_adb_logcat", json!({"serial": E, "count": 2}), Expect::Ok),
        case("logcat system", "read_adb_logcat", json!({"serial": E, "buffer": "system"}), Expect::Ok),
        case("logcat crash empty", "read_adb_logcat", json!({"serial": E, "buffer": "crash"}), Expect::Ok),
        case("logcat pid", "read_adb_logcat", json!({"serial": E, "pid": 2000}), Expect::Ok),
        case("logcat big", "read_adb_logcat", json!({"serial": E, "count": 5}), Expect::Ok).mode("big_logcat"),
        case("processes", "list_adb_processes", json!({"serial": E}), Expect::Ok),
        case("processes unparsed", "list_adb_processes", json!({"serial": E}), Expect::Ok).mode("garbage_ps"),
        case("directory", "list_adb_directory", json!({"serial": E, "device_path": "/data/local/tmp"}), Expect::Ok),
        case("directory with space", "list_adb_directory", json!({"serial": E, "device_path": "/data/local/tmp/dir with space"}), Expect::Ok),
        case("directory single file", "list_adb_directory", json!({"serial": E, "device_path": "/data/local/tmp/notes.txt"}), Expect::Ok),
        case("directory missing", "list_adb_directory", json!({"serial": E, "device_path": "/data/local/tmp/it's"}), Expect::Code("unsupported_target")),
        case("features", "list_adb_features", json!({"serial": E}), Expect::Ok),
        case("services", "list_adb_services", json!({"serial": E}), Expect::Ok),
        case("display", "inspect_adb_display", json!({"serial": E}), Expect::Ok),
        case("display unsupported format", "inspect_adb_display", json!({"serial": E}), Expect::Code("unreadable_output")).mode("no_wm_size"),
        case("window", "inspect_adb_window", json!({"serial": E}), Expect::Ok),
        case("setting present", "read_adb_setting", json!({"serial": E, "namespace": "secure", "key": "adb_enabled"}), Expect::Ok),
        case("setting absent", "read_adb_setting", json!({"serial": E, "namespace": "system", "key": "no.such-key"}), Expect::Ok),
        case("resolve whatsapp", "resolve_adb_packages", json!({"serial": E, "query": "whatsapp"}), Expect::Ok),
        case("resolve exact", "resolve_adb_packages", json!({"serial": E, "query": "COM.WHATSAPP.W4B"}), Expect::Ok),
        case("resolve none", "resolve_adb_packages", json!({"serial": E, "query": "zzz"}), Expect::Ok),
        case("resolve unparsed", "resolve_adb_packages", json!({"serial": E, "query": "example"}), Expect::Ok).mode("garbage_ps"),
    ];
    run_group("inspection", cases).await;
}

#[tokio::test]
async fn acquisition_tools_match_rea() {
    let cases = vec![
        case("pull package", "pull_adb_package", json!({"serial": E, "package": "com.example.app", "output_directory": "{OUT}"}), Expect::Ok),
        case("pull package relative dir", "pull_adb_package", json!({"serial": E, "package": "com.whatsapp", "output_directory": "{OUT}/./sub/../x"}), Expect::Ok),
        case("pull package missing", "pull_adb_package", json!({"serial": E, "package": "com.missing", "output_directory": "{OUT}"}), Expect::Code("unsupported_target")),
        case("pull package every pull fails", "pull_adb_package", json!({"serial": E, "package": "com.example.app", "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .mode("pull_fail"),
        case("pull package duplicate names", "pull_adb_package", json!({"serial": E, "package": "com.example.app", "output_directory": "{OUT}"}), Expect::Ok)
            .mode("apk_dup_names"),
        case("pull package dir exists", "pull_adb_package", json!({"serial": E, "package": "com.example.app", "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .setup(existing_package_dir),
        case("pull package rollback fails", "pull_adb_package", json!({"serial": E, "package": "com.example.app", "output_directory": "{OUT}/locked"}), Expect::Code("cleanup_incomplete"))
            .mode("pull_fail_lock_parent"),
        case("pull file", "pull_adb_file", json!({"serial": E, "device_path": "/data/local/tmp/notes.txt", "output_directory": "{OUT}"}), Expect::Ok),
        case("pull file through symlink", "pull_adb_file", json!({"serial": E, "device_path": "/data/local/tmp/link", "output_directory": "{OUT}/sub"}), Expect::Ok),
        case("pull file missing", "pull_adb_file", json!({"serial": E, "device_path": "/data/local/tmp/nope", "output_directory": "{OUT}"}), Expect::Code("unsupported_target")),
        case("pull file target exists", "pull_adb_file", json!({"serial": E, "device_path": "/data/local/tmp/notes.txt", "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .setup(existing_notes),
        case("pull file output not writable", "pull_adb_file", json!({"serial": E, "device_path": "/data/local/tmp/notes.txt", "output_directory": "{OUT}/ro"}), Expect::Code("unreadable_output"))
            .setup(lock_out_dir),
        case("screen", "capture_adb_screen", json!({"serial": E, "output_directory": "{OUT}"}), Expect::Ok),
        case("screen not a png", "capture_adb_screen", json!({"serial": E, "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .mode("screencap_garbage"),
        case("screen target exists", "capture_adb_screen", json!({"serial": E, "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .setup(existing_screen),
        case("screen unknown serial", "capture_adb_screen", json!({"serial": "ghost-1", "output_directory": "{OUT}"}), Expect::Code("unreadable_output")),
        case("bugreport", "collect_adb_bugreport", json!({"serial": E, "output_directory": "{OUT}"}), Expect::Ok),
        case("bugreport without path", "collect_adb_bugreport", json!({"serial": E, "output_directory": "{OUT}"}), Expect::Code("unreadable_output"))
            .mode("bugreport_no_path"),
    ];
    run_group("acquisition", cases).await;
}

#[tokio::test]
async fn mutating_tools_match_rea() {
    let cases = vec![
        case("push new file", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/payload.bin"}), Expect::Ok),
        case("push refuses existing file", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/notes.txt"}), Expect::Code("unreadable_output")),
        case("push overwrite", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/notes.txt", "overwrite": true}), Expect::Ok),
        case("push without device sha256sum", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/payload.bin"}), Expect::Ok)
            .mode("no_sha256sum"),
        case("push digest mismatch", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/payload.bin"}), Expect::Code("artifact_changed"))
            .mode("wrong_sha256sum"),
        case("push local missing", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/missing.bin", "device_path": "/data/local/tmp/payload.bin"}), Expect::Code("invalid_request")),
        case("push local is a directory", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}", "device_path": "/data/local/tmp/payload.bin"}), Expect::Code("invalid_request")),
        case("push into missing device dir", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/nodir/payload.bin"}), Expect::Code("unsupported_target")),
        case("push path with space", "push_adb_file", json!({"serial": E, "local_path": "{LOCAL}/payload.bin", "device_path": "/data/local/tmp/dir with space/new file.bin"}), Expect::Ok),
        case("install new apk", "install_adb_package", json!({"serial": E, "apk_path": "{LOCAL}/test.apk"}), Expect::Ok),
        case("install existing without replace", "install_adb_package", json!({"serial": E, "apk_path": "{LOCAL}/com.example.app.apk"}), Expect::Code("unreadable_output")),
        case("install existing with replace", "install_adb_package", json!({"serial": E, "apk_path": "{LOCAL}/com.example.app.apk", "replace": true}), Expect::Ok),
        case("install failure printed with exit 0", "install_adb_package", json!({"serial": E, "apk_path": "{LOCAL}/com.example.app.apk"}), Expect::Code("unsupported_target"))
            .mode("install_failure_exit0"),
        case("install apk missing", "install_adb_package", json!({"serial": E, "apk_path": "{LOCAL}/missing.apk"}), Expect::Code("invalid_request")),
        case("uninstall", "uninstall_adb_package", json!({"serial": E, "package": "com.whatsapp"}), Expect::Ok),
        case("uninstall missing", "uninstall_adb_package", json!({"serial": E, "package": "com.missing"}), Expect::Code("unreadable_output")),
        case("uninstall failure printed with exit 0", "uninstall_adb_package", json!({"serial": E, "package": "com.missing"}), Expect::Code("unsupported_target"))
            .mode("uninstall_failure_exit0"),
        case("start app", "start_adb_app", json!({"serial": E, "package": "com.example.app"}), Expect::Ok),
        case("start app without launcher", "start_adb_app", json!({"serial": E, "package": "com.example.app"}), Expect::Code("unsupported_target"))
            .mode("no_launcher"),
        case("start app unknown package", "start_adb_app", json!({"serial": E, "package": "com.missing"}), Expect::Code("unsupported_target")),
        case("start app refused", "start_adb_app", json!({"serial": E, "package": "com.example.app"}), Expect::Code("unsupported_target"))
            .mode("am_refused"),
        case("start activity minimal", "start_adb_activity", json!({"serial": E, "action": "android.intent.action.VIEW"}), Expect::Ok),
        case(
            "start activity with data, component and every extra type",
            "start_adb_activity",
            json!({
                "serial": E,
                "action": "android.intent.action.VIEW",
                "data_uri": "https://example.com/?a=1&b=2",
                "component": "com.example.app/.Main",
                "extras": [
                    {"key": "s", "type": "string", "value": "hello world 'quoted' $HOME"},
                    {"key": "b", "type": "boolean", "value": "true"},
                    {"key": "i", "type": "int", "value": "-42"},
                    {"key": "l", "type": "long", "value": "9000000000"},
                    {"key": "f", "type": "float", "value": "3.5"}
                ]
            }),
            Expect::Ok,
        ),
        case("start activity bad boolean", "start_adb_activity", json!({"serial": E, "action": "a.b", "extras": [{"key": "b", "type": "boolean", "value": "yes"}]}), Expect::Code("invalid_request")),
        case("start activity bad int", "start_adb_activity", json!({"serial": E, "action": "a.b", "extras": [{"key": "i", "type": "int", "value": "1.5"}]}), Expect::Code("invalid_request")),
        case("start activity bad long", "start_adb_activity", json!({"serial": E, "action": "a.b", "extras": [{"key": "i", "type": "long", "value": "x"}]}), Expect::Code("invalid_request")),
        case("start activity bad float", "start_adb_activity", json!({"serial": E, "action": "a.b", "extras": [{"key": "f", "type": "float", "value": "1."}]}), Expect::Code("invalid_request")),
        case("start activity refused", "start_adb_activity", json!({"serial": E, "action": "a.b"}), Expect::Code("unsupported_target"))
            .mode("am_refused"),
        case("stop app", "stop_adb_app", json!({"serial": E, "package": "com.example.app"}), Expect::Ok),
        case("stop app unknown serial", "stop_adb_app", json!({"serial": "ghost-1", "package": "com.example.app"}), Expect::Code("unsupported_target")),
    ];
    run_group("mutation", cases).await;
}

#[tokio::test]
async fn adb_selection_and_client_errors_match_rea() {
    let cases = vec![
        case("missing binary", "inspect_adb_client", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Raw("/nonexistent/adb")),
        case("missing binary, device tool", "list_adb_devices", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Raw("/nonexistent/adb")),
        case("relative path", "inspect_adb_client", json!({}), Expect::Text("REA_ADB_PATH must be")).adb(Adb::Raw("adb")),
        case("blank path falls back to PATH", "inspect_adb_client", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Raw("   ")),
        case("unset falls back to PATH", "list_adb_devices", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Unset),
        case("version probe fails", "inspect_adb_client", json!({}), Expect::Code("capability_unavailable")).version_fail(),
        case("directory instead of binary", "inspect_adb_client", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Raw("/tmp")),
        case("not executable", "inspect_adb_client", json!({}), Expect::Code("capability_unavailable")).adb(Adb::Raw("/etc/hostname")),
    ];
    run_group("selection", cases).await;
}

/// Argument admission errors, batched through one oracle session. The calls
/// have no device effect: they are rejected before any adb process starts.
#[tokio::test]
async fn admission_errors_match_rea() {
    if !oracle_available() {
        return;
    }
    let _guard = SERIAL.lock().await;
    let long_serial = "a".repeat(257);
    let cases: Vec<(&str, Value)> = vec![
        ("inspect_adb_device", json!({})),
        ("inspect_adb_device", json!({"serial": "bad serial"})),
        ("inspect_adb_device", json!({"serial": "it's"})),
        ("inspect_adb_device", json!({"serial": ""})),
        ("inspect_adb_device", json!({"serial": 5})),
        ("inspect_adb_device", json!({"serial": null})),
        ("inspect_adb_device", json!({"serial": ["a"]})),
        ("inspect_adb_device", json!({"serial": {}})),
        ("inspect_adb_device", json!({"serial": true})),
        ("inspect_adb_device", json!({"serial": "a\u{00a0}b"})),
        ("inspect_adb_device", json!({"serial": long_serial})),
        ("inspect_adb_device", json!({"serial": "ok", "extra": 1})),
        ("inspect_adb_device", json!({"serial": "ok", "x": 1, "y": 2})),
        ("inspect_adb_client", json!({"a": 1})),
        ("list_adb_devices", json!({"a": 1, "b": 2})),
        ("list_adb_packages", json!({"serial": "a", "scope": "bad"})),
        ("list_adb_packages", json!({"serial": "a", "scope": null})),
        ("list_adb_packages", json!({"serial": "a", "scope": 3, "zz": 1})),
        ("pull_adb_package", json!({"serial": "a", "package": "1bad", "output_directory": "/tmp/x"})),
        ("pull_adb_package", json!({"serial": "a", "package": "com..x", "output_directory": ""})),
        ("pull_adb_package", json!({"serial": "a", "package": "com.x", "output_directory": "a\u{0}b"})),
        ("pull_adb_package", json!({"serial": "a"})),
        ("read_adb_logcat", json!({"serial": "a", "count": 0, "pid": -1, "buffer": "x"})),
        ("read_adb_logcat", json!({"serial": "a", "count": 1.5})),
        ("read_adb_logcat", json!({"serial": "a", "pid": 0.5, "count": -0.5})),
        ("read_adb_logcat", json!({"serial": "a", "count": 10001, "pid": 2.5})),
        ("read_adb_logcat", json!({"serial": "a", "count": "5"})),
        ("read_adb_logcat", json!({"serial": "a", "pid": 0, "buffer": 5})),
        ("read_adb_logcat", json!({"serial": "a", "pid": "7"})),
        ("inspect_adb_package", json!({"serial": "a", "package": "com.example."})),
        ("pull_adb_file", json!({"serial": "a", "device_path": "rel", "output_directory": "/tmp/o"})),
        ("pull_adb_file", json!({"serial": "a", "device_path": "", "output_directory": "/tmp/o"})),
        ("push_adb_file", json!({"serial": "a", "local_path": "/tmp/x", "device_path": "/d", "overwrite": "yes"})),
        ("push_adb_file", json!({"serial": "a", "local_path": "/tmp/x"})),
        ("capture_adb_screen", json!({"serial": "a"})),
        ("list_adb_directory", json!({"serial": "a", "device_path": "no-slash"})),
        ("read_adb_setting", json!({"serial": "a", "namespace": "x", "key": "a b"})),
        ("read_adb_setting", json!({"serial": "a", "namespace": "secure", "key": ""})),
        ("resolve_adb_packages", json!({"serial": "a", "query": "a"})),
        ("resolve_adb_packages", json!({"serial": "a", "query": 7})),
        ("install_adb_package", json!({"serial": "a", "apk_path": "/x", "replace": 1})),
        ("uninstall_adb_package", json!({"serial": "a", "package": ""})),
        ("start_adb_app", json!({"serial": "a", "package": "a-b"})),
        ("stop_adb_app", json!({"serial": "a", "package": "1a"})),
        ("start_adb_activity", json!({"serial": "a", "action": "x y"})),
        ("start_adb_activity", json!({"serial": "a", "action": ""})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "data_uri": "a b", "component": "a b"})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "component": "/Act"})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "extras": "s"})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "extras": [1, null, [], {}]})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "extras": [{"key": "", "type": "bad", "value": "", "q": 1}]})),
        ("start_adb_activity", json!({"serial": "a", "action": "a.b", "extras": [{"key": "a b", "type": "int", "value": "x\u{0}"}]})),
        (
            "start_adb_activity",
            json!({"serial": "a", "action": "a.b", "extras": (0..17).map(|_| json!({"key": "k", "type": "int", "value": "1"})).collect::<Vec<_>>()}),
        ),
    ];
    let batch = Path::new(SANDBOX_ROOT).join("admission-calls.json");
    let answers = Path::new(SANDBOX_ROOT).join("admission-answers.json");
    fs::create_dir_all(SANDBOX_ROOT).unwrap();
    let calls: Vec<Value> = cases.iter().map(|(tool, args)| json!({"tool": tool, "args": args})).collect();
    fs::write(&batch, serde_json::to_string(&calls).unwrap()).unwrap();
    let status = Command::new("python3")
        .arg(repo_root().join("fixtures/adb/oracle_batch.py"))
        .arg(&batch)
        .arg(&answers)
        .status()
        .expect("python3");
    assert!(status.success(), "oracle batch failed");
    let oracle: Vec<Value> = serde_json::from_str(&fs::read_to_string(&answers).unwrap()).unwrap();
    assert_eq!(oracle.len(), cases.len());
    // No adb process must start for a rejected call: point the binary at a
    // path that would answer differently if it were reached.
    std::env::set_var("REA_ADB_PATH", "/nonexistent/adb-must-not-run");
    let mut failures = Vec::new();
    for ((tool, args), expected) in cases.iter().zip(&oracle) {
        let expected = observed_from(expected);
        assert!(
            expected.is_error && expected.text.starts_with("Input validation error: Invalid arguments for tool"),
            "oracle must reject {tool} {args}: {}",
            expected.text
        );
        let actual = run_rust(tool, args).await;
        if !actual.is_error || actual.text != expected.text {
            failures.push(format!("{tool} {args}\n oracle: {}\n rust:   {}", expected.text, actual.text));
        }
    }
    std::env::remove_var("REA_ADB_PATH");
    assert!(failures.is_empty(), "{} admission cases differ:\n{}", failures.len(), failures.join("\n"));
}

/// Every catalog name is routed to a real handler (no `pending port`).
#[tokio::test]
async fn catalog_tools_no_longer_answer_pending_port() {
    let _guard = SERIAL.lock().await;
    std::env::set_var("REA_ADB_PATH", "/nonexistent/adb-must-not-run");
    for tool in tracewise_device::ADB_TOOLS {
        let outcome = run_rust(tool, &json!({})).await;
        assert!(!outcome.text.contains("pending port"), "{tool} still pending: {}", outcome.text);
        assert!(!outcome.text.contains("Unknown tool"), "{tool} is not routed: {}", outcome.text);
        assert!(outcome.is_error, "{tool} with no arguments must be an error result");
    }
    std::env::remove_var("REA_ADB_PATH");
}

/// MCP cancellation drops the handler future. The adb child must die with it, and
/// the half-pulled package directory must be registered for removal so the next
/// adb call cleans it up.
#[tokio::test]
async fn cancelled_pull_package_leaves_no_process_and_cleans_up_on_next_call() {
    let _guard = SERIAL.lock().await;
    let dirs = Dirs::new("cancel");
    prepare(&dirs, None);
    let adb = case("cancel", "pull_adb_package", json!({}), Expect::Ok).mode("slow_pull");
    apply_env(&adb, &dirs);
    let args = json!({"serial": E, "package": "com.example.app", "output_directory": dirs.out().to_string_lossy()});
    let session = BinarySession::new();
    let request = CallToolRequestParam { name: "pull_adb_package".to_string().into(), arguments: Some(args.as_object().unwrap().clone()) };
    let outcome = tokio::time::timeout(std::time::Duration::from_millis(2500), call_tool_local(&session, request)).await;
    assert!(outcome.is_err(), "the slow pull must still be running when the future is dropped");
    let package_dir = dirs.out().join("com.example.app");
    assert!(package_dir.exists(), "the partial package directory is expected right after cancellation");
    let pulled = package_dir.to_string_lossy().into_owned();
    let alive = |pattern: &str| {
        let out = std::process::Command::new("pgrep").arg("-f").arg(pattern).output().unwrap();
        String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.trim().is_empty()).count()
    };
    let mut running = alive(&pulled);
    for _ in 0..40 {
        if running == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        running = alive(&pulled);
    }
    assert_eq!(running, 0, "the adb child outlived the cancellation");
    // Any later adb call retries the registered removal.
    std::env::remove_var("FAKE_ADB_MODE");
    let next = run_rust("inspect_adb_client", &json!({})).await;
    assert!(!next.is_error, "{}", next.text);
    assert!(!package_dir.exists(), "the registered partial directory was not removed by the next call");
    let _ = fs::remove_dir_all(&dirs.base);
}

/// Server shutdown (transport closed, SIGTERM, SIGINT) removes the half-pulled package directory a
/// cancelled `pull_adb_package` left registered, without waiting for a next adb call.
#[tokio::test]
async fn shutdown_removes_the_package_directory_of_a_cancelled_pull() {
    let _guard = SERIAL.lock().await;
    let dirs = Dirs::new("shutdown");
    prepare(&dirs, None);
    let adb = case("shutdown", "pull_adb_package", json!({}), Expect::Ok).mode("slow_pull");
    apply_env(&adb, &dirs);
    let args = json!({"serial": E, "package": "com.example.app", "output_directory": dirs.out().to_string_lossy()});
    let session = BinarySession::new();
    let request = CallToolRequestParam { name: "pull_adb_package".to_string().into(), arguments: Some(args.as_object().unwrap().clone()) };
    let outcome = tokio::time::timeout(std::time::Duration::from_millis(2500), call_tool_local(&session, request)).await;
    assert!(outcome.is_err(), "the slow pull must still be running when the future is dropped");
    let package_dir = dirs.out().join("com.example.app");
    assert!(package_dir.exists(), "the partial package directory is expected right after cancellation");
    std::env::remove_var("FAKE_ADB_MODE");

    tracewise_server::tracks::shutdown().await;
    assert!(!package_dir.exists(), "shutdown must remove the registered partial package directory");
    // Nothing stays registered: a later adb call has no cleanup left to do.
    assert!(tracewise_device::provider::shutdown().is_empty(), "the registry must be empty after shutdown");
    let _ = fs::remove_dir_all(&dirs.base);
}
