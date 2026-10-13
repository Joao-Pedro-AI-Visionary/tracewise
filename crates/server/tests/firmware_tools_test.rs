//! `inspect_firmware_regions` and `extract_firmware` against the ORIGINAL REA,
//! with the real tools.
//!
//! Binwalk 3.1.0 (built from the crates.io release with `cargo install
//! --locked --no-default-features`-equivalent plus `RUST_FONTCONFIG_DLOPEN`) and
//! Unblob 26.6.4 (`pip install unblob==26.6.4` in a venv) live under
//! `/workspace/tools/` and are selected through `REA_BINWALK_COMMAND` /
//! `REA_UNBLOB_COMMAND`, exactly as a user would. `fixtures/firmware/`
//! holds deterministic samples (`make_fixtures.py`) and two fake tools
//! (`fake-binwalk`, `fake-unblob`) that provoke every report/process failure
//! the real tools cannot be made to produce on demand.
//!
//! Each case runs the oracle first (a fresh `rea.mjs` process) and then the Rust
//! port, with the same environment, arguments and absolute paths. The complete
//! MCP result is compared after normalizing only what is random per run:
//! - the private runtime directory `/tmp/rea-firmware-XXXXXX` (6 random chars),
//! - UUID-shaped ids (Binwalk's signature ids),
//! - Unblob's `<pid>:<n>` blob ids (the pid part),
//! - `evidence_id` (it hashes the values above).
//!
//! Every other field is compared as-is: `normalized_result`, `raw_result` (the
//! tool reports, command lines, captured stdout/stderr and byte counts),
//! `subject`, `provider`, `parameters`, `limitations`, `locations`, and the
//! error bodies. The published output tree (names, modes, digests, links) and
//! the absence of leftover `/tmp/rea-firmware-*` roots and stray processes are
//! compared too. Every success is validated against the catalog `outputSchema`.
//!
//! Limits (documented, not ported): the cleanup-retry registry REA keeps across
//! calls (`#pendingCleanup`) and cooperative cancellation. Timeouts (120 s) are
//! covered by a unit test of the runner with a short deadline, not end to end.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const BINWALK: &str = "/workspace/tools/binwalk-3.1.0/bin/binwalk";
const UNBLOB: &str = "/workspace/tools/unblob-26.6.4/bin/unblob";
/// Per-checkout scratch (`target/tmp`), so concurrent runs from other worktrees
/// never share sandboxes, private roots or marker processes.
const WORK: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/fw-parity");

static SERIAL: Mutex<()> = Mutex::const_new(());

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn fixture(name: &str) -> String {
    repo_root().join("fixtures/firmware").join(name).to_string_lossy().into_owned()
}

fn executable(name: &str) -> String {
    let path = fixture(name);
    let mut permissions = fs::metadata(&path).expect("fake tool").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod fake tool");
    path
}

fn prerequisites() -> bool {
    let mut missing = tracewise_device::testing::rea_oracle_missing();
    missing.extend(tracewise_device::testing::missing_paths(&[BINWALK, UNBLOB, "/usr/bin/prlimit"]));
    tracewise_device::testing::require_or_skip("firmware_tools_test", &missing)
}

fn tool_schema(tool: &str) -> Value {
    let tools: Value = serde_json::from_str(tracewise_contracts::PHASE6_TOOLS_JSON).expect("phase6 json");
    tools["tools"].as_array().unwrap().iter().find(|t| t["name"] == tool).expect("tool")["outputSchema"].clone()
}

// ------------------------------------------------------------ normalization --

struct Normalizer {
    root: Regex,
    uuid: Regex,
    blob: Regex,
}

impl Normalizer {
    fn new() -> Self {
        Normalizer {
            root: Regex::new(r"/rea-firmware-[A-Za-z0-9]{6}").unwrap(),
            uuid: Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            blob: Regex::new(r"^[0-9]+:([0-9]+)$").unwrap(),
        }
    }

    fn string(&self, text: &str) -> String {
        let text = self.root.replace_all(text, "/rea-firmware-ROOT");
        let text = self.uuid.replace_all(&text, "UUID");
        self.blob.replace(&text, "PID:$1").into_owned()
    }

    fn value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.string(text)),
            Value::Array(items) => Value::Array(items.iter().map(|v| self.value(v)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(key, _)| key.as_str() != "evidence_id")
                    .map(|(key, v)| (key.clone(), self.value(v)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

// ------------------------------------------------------------------ cases ----

struct Case {
    label: String,
    tool: &'static str,
    args: Value,
    env: Vec<(&'static str, String)>,
    /// Expected oracle answer: None = success, Some(code) = projected error code,
    /// Some("text") = plain text.
    expect: Option<&'static str>,
}

fn case(label: &str, tool: &'static str, args: Value, expect: Option<&'static str>) -> Case {
    Case { label: label.to_string(), tool, args, env: Vec::new(), expect }
}

impl Case {
    fn env(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.env.push((key, value.into()));
        self
    }
}

fn real_tools(case: Case) -> Case {
    case.env("REA_BINWALK_COMMAND", BINWALK).env("REA_UNBLOB_COMMAND", UNBLOB)
}

fn fake_binwalk(case: Case, mode: &str) -> Case {
    case.env("REA_BINWALK_COMMAND", executable("fake-binwalk")).env("FAKE_FW_MODE", mode)
}

fn fake_unblob(case: Case, mutation: &str) -> Case {
    case.env("REA_UNBLOB_COMMAND", executable("fake-unblob")).env("FAKE_FW_MUTATION", mutation)
}

const ENV_KEYS: [&str; 11] = [
    "REA_BINWALK_COMMAND",
    "REA_UNBLOB_COMMAND",
    "REA_FIRMWARE_PRLIMIT_COMMAND",
    "FAKE_FW_MODE",
    "FAKE_FW_MUTATION",
    "FAKE_FW_VERSION",
    "FAKE_FW_BANNER_BYTES",
    "FAKE_FW_STDERR",
    "FAKE_FW_EXIT",
    "FAKE_FW_VERSION_EXIT",
    "FAKE_FW_SLOW",
];

fn apply_env(case: &Case) {
    for key in ENV_KEYS {
        std::env::remove_var(key);
    }
    for (key, value) in &case.env {
        std::env::set_var(key, value);
    }
    // Private roots (REA's `os.tmpdir()` and the port's) land in this run's own directory.
    fs::create_dir_all(format!("{WORK}/tmp")).unwrap();
    std::env::set_var("TMPDIR", format!("{WORK}/tmp"));
    std::env::set_var("FAKE_FW_MARKER", stray_marker());
}

fn substitute(args: &Value, out: &str) -> Value {
    serde_json::from_str(
        &args
            .to_string()
            .replace("{OUT}", out)
            .replace("{SAMPLE}", &fixture("sample.bin"))
            .replace("{LINKS}", &fixture("links.bin"))
            .replace("{RANDOM}", &fixture("random.bin"))
            .replace("{WORK}", WORK),
    )
    .unwrap()
}

fn run_oracle(tool: &str, args: &Value) -> Value {
    let calls = format!("{WORK}/oracle-args.json");
    let out = format!("{WORK}/oracle-out.json");
    fs::write(&calls, args.to_string()).unwrap();
    let _ = fs::remove_file(&out);
    let status = Command::new("python3")
        .arg(repo_root().join("fixtures/rea_oracle.py"))
        .arg(tool)
        .arg(format!("@{calls}"))
        .arg(&out)
        .status()
        .expect("python3");
    assert!(status.success(), "oracle failed for {tool}");
    serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap()
}

async fn run_rust(tool: &str, args: &Value) -> Value {
    let session = BinarySession::new();
    let result = call_tool_local(
        &session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: Some(args.as_object().unwrap().clone()) },
    )
    .await;
    match result {
        Ok(result) => serde_json::to_value(&result).unwrap(),
        Err(error) => json!({"isError": true, "content": [{"type": "text", "text": format!("PROTOCOL ERROR: {error}")}]}),
    }
}

fn tree(root: &str) -> BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut entries: Vec<_> = match fs::read_dir(dir) {
            Ok(listing) => listing.flatten().collect(),
            Err(_) => return,
        };
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let meta = fs::symlink_metadata(&path).unwrap();
            let mode = meta.permissions().mode() & 0o7777;
            if meta.file_type().is_symlink() {
                out.insert(rel, format!("link {mode:o} -> {}", fs::read_link(&path).unwrap().display()));
            } else if meta.is_dir() {
                out.insert(rel.clone(), format!("dir {mode:o}"));
                walk(base, &path, out);
            } else {
                out.insert(rel, format!("file {mode:o} {}", hex::encode(Sha256::digest(fs::read(&path).unwrap()))));
            }
        }
    }
    let mut out = BTreeMap::new();
    if Path::new(root).exists() {
        walk(Path::new(root), Path::new(root), &mut out);
    }
    out
}

/// The private runtime roots under this run's own `TMPDIR` (see `apply_env`).
fn leftover_roots() -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(format!("{WORK}/tmp"))
        .map(|listing| {
            listing
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("rea-firmware-"))
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// Marker the fake tools put on the command line of their stray descendants.
fn stray_marker() -> String {
    format!("tw-fw-stray-{}", std::process::id())
}

fn stray_processes() -> usize {
    let output = Command::new("pgrep").arg("-f").arg(stray_marker()).output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.trim().is_empty()).count(),
        Err(_) => 0,
    }
}

fn text_of(result: &Value) -> String {
    result["content"][0]["text"].as_str().unwrap_or_default().to_string()
}

fn body_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

fn short(value: &Value) -> String {
    let text = serde_json::to_string_pretty(value).unwrap();
    if text.len() > 6000 {
        format!("{}...", &text[..6000])
    } else {
        text
    }
}

async fn compare_case(normalizer: &Normalizer, case: &Case) -> Result<(), String> {
    apply_env(case);
    let out = format!("{WORK}/out");
    let reset = || {
        let _ = fs::remove_dir_all(&out);
    };
    let args = substitute(&case.args, &out);

    reset();
    let before = leftover_roots();
    let oracle = run_oracle(case.tool, &args);
    let oracle_tree = tree(&out);
    let oracle_leftover = leftover_roots();
    let oracle_stray = stray_processes();

    reset();
    let rust = run_rust(case.tool, &args).await;
    let rust_tree = tree(&out);
    let rust_leftover = leftover_roots();
    let rust_stray = stray_processes();
    reset();

    let oracle_error = oracle["isError"] == true;
    match case.expect {
        None => {
            if oracle_error {
                return Err(format!("oracle answered an error, expected success: {}", text_of(&oracle)));
            }
        }
        Some("text") => {
            if !oracle_error || body_of(&text_of(&oracle)).is_object() {
                return Err(format!("oracle did not answer plain text: {}", text_of(&oracle)));
            }
        }
        Some(code) => {
            let body = body_of(&text_of(&oracle));
            if !oracle_error || body["error"]["code"] != code {
                return Err(format!("oracle did not answer error code {code}: {}", text_of(&oracle)));
            }
        }
    }

    let mut problems = Vec::new();
    if oracle_error != (rust["isError"] == true) {
        problems.push(format!("isError oracle={oracle_error} rust={}", rust["isError"]));
    }
    if oracle_error {
        let (o, r) = (normalizer.value(&body_of(&text_of(&oracle))), normalizer.value(&body_of(&text_of(&rust))));
        if o != r {
            problems.push(format!("error body differs\n oracle: {}\n rust:   {}", short(&o), short(&r)));
        }
    } else {
        let (o, r) = (normalizer.value(&oracle["structuredContent"]), normalizer.value(&rust["structuredContent"]));
        if o != r {
            problems.push(format!("structuredContent differs\n oracle: {}\n rust:   {}", short(&o), short(&r)));
        }
        if let Some(structured) = rust.get("structuredContent") {
            let validator = jsonschema::validator_for(&tool_schema(case.tool)).expect("schema");
            if let Err(error) = validator.validate(structured) {
                problems.push(format!("outputSchema: {error}"));
            }
        }
    }
    if oracle_tree != rust_tree {
        problems.push(format!("published tree differs\n oracle: {oracle_tree:#?}\n rust:   {rust_tree:#?}"));
    }
    if oracle_leftover != before {
        problems.push(format!("oracle left private roots behind: {oracle_leftover:?}"));
    }
    if rust_leftover != before {
        problems.push(format!("rust left private roots behind: {rust_leftover:?}"));
    }
    if oracle_stray != 0 || rust_stray != 0 {
        problems.push(format!("stray processes: oracle={oracle_stray} rust={rust_stray}"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

async fn run_group(group: &str, cases: Vec<Case>) {
    if !prerequisites() {
        return;
    }
    let _guard = SERIAL.lock().await;
    fs::create_dir_all(WORK).unwrap();
    for path in [fixture("random.bin"), fixture("sample.bin"), fixture("links.bin")] {
        assert!(Path::new(&path).exists(), "missing fixture {path}");
    }
    let normalizer = Normalizer::new();
    let mut failures = Vec::new();
    for case in &cases {
        if let Err(problem) = compare_case(&normalizer, case).await {
            failures.push(format!("[{}] {} {}\n{problem}", case.label, case.tool, case.args));
        }
    }
    assert!(failures.is_empty(), "{group}: {} of {} cases differ:\n\n{}", failures.len(), cases.len(), failures.join("\n\n"));
    eprintln!("{group}: {} cases identical to the oracle", cases.len());
}

// --------------------------------------------------------------- scenarios ----

#[tokio::test]
async fn real_tools_inspect_and_extract_match_rea() {
    let cases = vec![
        real_tools(case("inspect sample", "inspect_firmware_regions", json!({"path": "{SAMPLE}"}), None)),
        real_tools(case("inspect links", "inspect_firmware_regions", json!({"path": "{LINKS}"}), None)),
        real_tools(case("inspect random", "inspect_firmware_regions", json!({"path": "{RANDOM}"}), None)),
        real_tools(case("extract sample", "extract_firmware", json!({"path": "{SAMPLE}", "output_directory": "{OUT}"}), None)),
        real_tools(case(
            "extract selected range",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "range": {"offset": 128, "length": 3299}}),
            None,
        )),
        real_tools(case(
            "extract depth limit 1",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "max_depth": 1}),
            None,
        )),
        real_tools(case("extract with symlink kept as metadata", "extract_firmware", json!({"path": "{LINKS}", "output_directory": "{OUT}"}), None)),
        real_tools(case("extract nothing recognisable", "extract_firmware", json!({"path": "{RANDOM}", "output_directory": "{OUT}"}), None)),
        real_tools(case(
            "extract staging bytes budget",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "max_output_bytes": 1000}),
            Some("unreadable_output"),
        )),
        real_tools(case(
            "extract staging files budget",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "max_output_files": 2}),
            Some("unreadable_output"),
        )),
        real_tools(case(
            "extract output directory exists",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{WORK}"}),
            Some("execution_failure"),
        )),
        real_tools(case(
            "extract output parent missing",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{WORK}/nodir/out"}),
            Some("execution_failure"),
        )),
        real_tools(case(
            "extract range beyond file",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "range": {"offset": 3000, "length": 9999}}),
            Some("invalid_request"),
        )),
        real_tools(case(
            "extract range starts at end of file",
            "extract_firmware",
            json!({"path": "{SAMPLE}", "output_directory": "{OUT}", "range": {"offset": 3745, "length": 1}}),
            Some("invalid_request"),
        )),
        real_tools(case("inspect missing file", "inspect_firmware_regions", json!({"path": "{WORK}/missing.bin"}), Some("execution_failure"))),
        real_tools(case("inspect a directory", "inspect_firmware_regions", json!({"path": "{WORK}"}), Some("invalid_request"))),
    ];
    run_group("real tools", cases).await;
}

#[tokio::test]
async fn tool_selection_errors_match_rea() {
    let sample = json!({"path": "{SAMPLE}"});
    let extract = json!({"path": "{SAMPLE}", "output_directory": "{OUT}"});
    let cases = vec![
        case("no tool configured (binwalk)", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")),
        case("no tool configured (unblob)", "extract_firmware", extract.clone(), Some("capability_unavailable")),
        case("relative tool path", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable"))
            .env("REA_BINWALK_COMMAND", "binwalk"),
        case("missing tool", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable"))
            .env("REA_BINWALK_COMMAND", "/nonexistent/binwalk"),
        case("tool is a directory", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable"))
            .env("REA_BINWALK_COMMAND", "/tmp"),
        case("tool not executable", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable"))
            .env("REA_BINWALK_COMMAND", "/etc/hostname"),
        case("tool path with dot segments is resolved", "inspect_firmware_regions", sample.clone(), None)
            .env("REA_BINWALK_COMMAND", "/workspace/tools/binwalk-3.1.0/bin/../bin/binwalk"),
        real_tools(case("limiter relative", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")))
            .env("REA_FIRMWARE_PRLIMIT_COMMAND", "prlimit"),
        real_tools(case("limiter missing", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")))
            .env("REA_FIRMWARE_PRLIMIT_COMMAND", "/nonexistent/prlimit"),
        real_tools(case("limiter is a directory", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")))
            .env("REA_FIRMWARE_PRLIMIT_COMMAND", "/tmp"),
        real_tools(case("limiter blank", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")))
            .env("REA_FIRMWARE_PRLIMIT_COMMAND", ""),
        real_tools(case("empty firmware", "inspect_firmware_regions", json!({"path": "/dev/null"}), Some("invalid_request"))),
        fake_binwalk(case("version too new", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")), "ok")
            .env("FAKE_FW_VERSION", "binwalk 3.2.0"),
        fake_binwalk(case("version unparsable", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")), "ok")
            .env("FAKE_FW_VERSION", "hello"),
        fake_binwalk(case("version missing", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")), "ok")
            .env("FAKE_FW_VERSION", ""),
        fake_binwalk(case("compatible patch release", "inspect_firmware_regions", sample.clone(), None), "ok")
            .env("FAKE_FW_VERSION", "binwalk 3.1.7"),
        fake_binwalk(case("prerelease suffix", "inspect_firmware_regions", sample.clone(), None), "ok")
            .env("FAKE_FW_VERSION", "binwalk 3.1.0-rc1"),
        fake_binwalk(case("banner too long", "inspect_firmware_regions", sample.clone(), Some("capability_unavailable")), "ok")
            .env("FAKE_FW_BANNER_BYTES", "2000"),
        fake_unblob(case("unblob version too old", "extract_firmware", extract.clone(), Some("capability_unavailable")), "none")
            .env("FAKE_FW_VERSION", "25.1.0"),
        fake_unblob(case("unblob compatible patch", "extract_firmware", extract.clone(), None), "none")
            .env("FAKE_FW_VERSION", "26.6.9"),
    ];
    run_group("tool selection", cases).await;
}

#[tokio::test]
async fn binwalk_report_and_process_failures_match_rea() {
    let sample = json!({"path": "{SAMPLE}"});
    let modes: [(&str, &'static str); 18] = [
        ("ok", ""),
        ("no_report", "unreadable_output"),
        ("no_report_exit1", "execution_failure"),
        ("exit3", "execution_failure"),
        ("invalid_json", "unreadable_output"),
        ("bom", "unreadable_output"),
        ("non_utf8", "unreadable_output"),
        ("wrong_shape", "unreadable_output"),
        ("not_array", "unreadable_output"),
        ("two_records", "unreadable_output"),
        ("other_path", "unreadable_output"),
        ("extractions", "unreadable_output"),
        ("oob", "unreadable_output"),
        ("big_stdout", "unreadable_output"),
        ("xfsz", "execution_failure"),
        ("killed", "execution_failure"),
        ("stray", ""),
        ("ok", ""),
    ];
    let mut cases: Vec<Case> = Vec::new();
    for (mode, code) in modes {
        let expect = if code.is_empty() { None } else { Some(code) };
        cases.push(fake_binwalk(case(&format!("binwalk mode {mode}"), "inspect_firmware_regions", sample.clone(), expect), mode));
    }
    cases.push(
        fake_binwalk(case("stderr is captured", "inspect_firmware_regions", sample.clone(), Some("execution_failure")), "exit3")
            .env("FAKE_FW_STDERR", "fake binwalk: unsupported architecture\n"),
    );
    cases.push(
        fake_binwalk(case("no report with diagnostics", "inspect_firmware_regions", sample.clone(), Some("unreadable_output")), "no_report")
            .env("FAKE_FW_STDERR", "warning: nothing written\n"),
    );
    run_group("binwalk failures", cases).await;
}

#[tokio::test]
async fn unblob_report_failures_match_rea() {
    let extract = json!({"path": "{SAMPLE}", "output_directory": "{OUT}"});
    let mutations: [(&str, &'static str); 36] = [
        ("none", ""),
        ("hash_mismatch", "unreadable_output"),
        ("no_root_hash", "unreadable_output"),
        ("size_mismatch", "unreadable_output"),
        ("root_not_file", "unreadable_output"),
        ("duplicate_task", "unreadable_output"),
        ("missing_stat", "unreadable_output"),
        ("stat_path_mismatch", "unreadable_output"),
        ("no_root", "unreadable_output"),
        ("two_roots", "unreadable_output"),
        ("chunk_bounds", "unreadable_output"),
        ("chunk_bounds_beyond", "unreadable_output"),
        ("chunk_duplicate", "unreadable_output"),
        ("chunk_encrypted", ""),
        ("chunk_unknown_handler", ""),
        ("chunk_diagnostic", ""),
        ("unknown_report", ""),
        ("multifile", ""),
        ("multifile_clean", ""),
        ("multifile_bad", "unreadable_output"),
        ("child_missing", "unreadable_output"),
        ("child_identity", "unreadable_output"),
        ("disconnected", "unreadable_output"),
        ("outside_path", "unreadable_output"),
        ("depth_limited", ""),
        ("absent_file", "unreadable_output"),
        ("reported_size_mismatch", "unreadable_output"),
        ("bytes_disagree", "unreadable_output"),
        ("bad_shape", "unreadable_output"),
        ("not_array", "unreadable_output"),
        ("symlink", ""),
        ("special", ""),
        ("many_files", "unreadable_output"),
        ("huge", "unreadable_output"),
        ("unsafe_name", "execution_failure"),
        ("decomposed_name", ""),
    ];
    let mut cases: Vec<Case> = Vec::new();
    for (mutation, code) in mutations {
        let expect = if code.is_empty() { None } else { Some(code) };
        let mut args = extract.clone();
        if mutation == "many_files" {
            args["max_output_files"] = json!(10);
        }
        if mutation == "huge" {
            args["max_output_bytes"] = json!(2000);
        }
        if mutation == "depth_limited" {
            args["max_depth"] = json!(2);
        }
        cases.push(fake_unblob(case(&format!("unblob mutation {mutation}"), "extract_firmware", args, expect), mutation));
    }
    cases.push(
        fake_unblob(case("unblob exits 1 with a diagnostic", "extract_firmware", extract.clone(), None), "chunk_diagnostic")
            .env("FAKE_FW_EXIT", "1"),
    );
    cases.push(
        fake_unblob(case("unblob exits 1 without a diagnostic", "extract_firmware", extract.clone(), Some("unreadable_output")), "none")
            .env("FAKE_FW_EXIT", "1"),
    );
    cases.push(
        fake_unblob(case("unblob exits 2", "extract_firmware", extract.clone(), Some("execution_failure")), "none")
            .env("FAKE_FW_EXIT", "2"),
    );
    run_group("unblob failures", cases).await;
}

#[tokio::test]
async fn firmware_admission_errors_match_rea() {
    if !prerequisites() {
        return;
    }
    let _guard = SERIAL.lock().await;
    fs::create_dir_all(WORK).unwrap();
    let cases: Vec<(&str, Value)> = vec![
        ("inspect_firmware_regions", json!({})),
        ("inspect_firmware_regions", json!({"path": ""})),
        ("inspect_firmware_regions", json!({"path": "rel/x.bin"})),
        ("inspect_firmware_regions", json!({"path": "a\u{0}b"})),
        ("inspect_firmware_regions", json!({"path": "/abs\u{0}"})),
        ("inspect_firmware_regions", json!({"path": "/abs", "x": 1})),
        ("inspect_firmware_regions", json!({"path": 5})),
        ("extract_firmware", json!({})),
        ("extract_firmware", json!({"path": "x", "output_directory": "y"})),
        ("extract_firmware", json!({"path": "/x", "output_directory": ""})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "range": {}})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "range": {"offset": -1, "length": 0}})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "range": {"offset": 1.5, "length": 9007199254740992u64}})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "range": 5})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "range": {"offset": 0, "length": 1, "z": 1}})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "max_depth": 0, "max_output_bytes": 0, "max_output_files": 0})),
        ("extract_firmware", json!({"path": "/x", "output_directory": "/y", "max_depth": 11, "max_output_bytes": 536870913, "max_output_files": 100001})),
    ];
    let calls: Vec<Value> = cases.iter().map(|(tool, args)| json!({"tool": tool, "args": args})).collect();
    let calls_file = format!("{WORK}/admission-calls.json");
    let answers_file = format!("{WORK}/admission-answers.json");
    fs::write(&calls_file, serde_json::to_string(&calls).unwrap()).unwrap();
    let status = Command::new("python3")
        .arg(repo_root().join("fixtures/adb/oracle_batch.py"))
        .arg(&calls_file)
        .arg(&answers_file)
        .status()
        .expect("python3");
    assert!(status.success());
    let oracle: Vec<Value> = serde_json::from_str(&fs::read_to_string(&answers_file).unwrap()).unwrap();
    for key in ENV_KEYS {
        std::env::remove_var(key);
    }
    let mut failures = Vec::new();
    for ((tool, args), expected) in cases.iter().zip(&oracle) {
        let expected_text = text_of(expected);
        assert!(expected_text.starts_with("Input validation error"), "{tool} {args}: {expected_text}");
        let actual = run_rust(tool, args).await;
        if text_of(&actual) != expected_text || actual["isError"] != true {
            failures.push(format!("{tool} {args}\n oracle: {expected_text}\n rust:   {}", text_of(&actual)));
        }
    }
    assert!(failures.is_empty(), "{} admission cases differ:\n{}", failures.len(), failures.join("\n"));
}

/// MCP cancellation drops the handler future (`tokio::select!` in `handlers.rs`).
/// A tool that is mid-run must leave nothing behind: no process of its group, no
/// private `/tmp/rea-firmware-*` root, no output directory, and the provider
/// queue must be free for the next request.
#[tokio::test]
async fn cancelled_requests_leave_no_process_or_private_root() {
    if !prerequisites() {
        return;
    }
    let _guard = SERIAL.lock().await;
    fs::create_dir_all(WORK).unwrap();
    let out = format!("{WORK}/out");
    let cancelled = vec![
        fake_binwalk(case("inspect", "inspect_firmware_regions", json!({"path": "{SAMPLE}"}), None), "slow"),
        fake_unblob(case("extract", "extract_firmware", json!({"path": "{SAMPLE}", "output_directory": "{OUT}"}), None), "none")
            .env("FAKE_FW_SLOW", "1"),
    ];
    for case in &cancelled {
        apply_env(case);
        let _ = fs::remove_dir_all(&out);
        let before = leftover_roots();
        let args = substitute(&case.args, &out);
        let session = BinarySession::new();
        let request = CallToolRequestParam { name: case.tool.to_string().into(), arguments: Some(args.as_object().unwrap().clone()) };
        let outcome = tokio::time::timeout(std::time::Duration::from_millis(2500), call_tool_local(&session, request)).await;
        assert!(outcome.is_err(), "[{}] the slow tool must still be running when the future is dropped", case.label);
        assert_eq!(leftover_roots(), before, "[{}] a private runtime root survived the cancellation", case.label);
        assert!(!Path::new(&out).exists(), "[{}] a partial output directory survived", case.label);
        let mut alive = stray_processes();
        for _ in 0..40 {
            if alive == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            alive = stray_processes();
        }
        assert_eq!(alive, 0, "[{}] a process of the owned group outlived the cancellation", case.label);
    }
    // The queue is free again: a normal request completes.
    let follow_up = real_tools(case("follow-up", "inspect_firmware_regions", json!({"path": "{SAMPLE}"}), None));
    apply_env(&follow_up);
    let args = substitute(&follow_up.args, &out);
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), run_rust(follow_up.tool, &args))
        .await
        .expect("the provider queue was not released after cancellation");
    assert_ne!(result["isError"], true, "{result}");
}
