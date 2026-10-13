//! Conformance tests of the IDA provider at the MCP connection seam (ports of REA's
//! `IdaSessionClient.test.ts`, `IdaOperationFailures.test.ts`, `IdaConfiguration.test.ts`,
//! `idaProvider.test.ts` and `providerContracts.test.ts`). The upstream server is an
//! in-process recording fake; the stdio transport is covered separately by the parity
//! tests against the fake in `fixtures/engines/ida`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::error::AnalysisError;
use crate::provider::tokio_util_lite::CancelToken;
use crate::provider::{AnalysisClient, AnalysisProvider, CachePolicy, ExecContext};
use crate::session::{EngineSession, Registry};
use crate::target::BinaryTarget;

use super::capabilities::IDA_OPERATIONS;
use super::config::{parse_registration, read_registration, IdaConfig, IdaMode, IdaRegistration};
use super::connection::{IdaConnection, IdaFault};
use super::protocol::{decode_tool_result, DecodeFailure};
use super::provider::IdaProvider;
use super::IdaSessionClient;

type Hook = Arc<dyn Fn(&str, &Value) -> Option<Value> + Send + Sync>;
type BeforeCall = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

struct Gate {
    tool: String,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

/// Stateful producer fixture at the connection seam (REA's `RecordingIdaMcp`).
struct RecordingIdaMcp {
    mode: IdaMode,
    calls: Mutex<Vec<(String, Value)>>,
    connects: AtomicUsize,
    closes: AtomicUsize,
    input_sha256: Mutex<String>,
    input_path: Mutex<String>,
    image_base: Mutex<String>,
    pseudocode: Mutex<String>,
    owned: AtomicBool,
    database: Mutex<Option<String>>,
    fail_close: AtomicBool,
    fail_tool: Mutex<Option<(String, String)>>,
    gate: Mutex<Option<Gate>>,
    hook: Mutex<Option<Hook>>,
    /// Runs before each call; may change fixture state and may fail the call.
    before_call: Mutex<Option<BeforeCall>>,
}

impl RecordingIdaMcp {
    fn new(target: &BinaryTarget, mode: IdaMode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            calls: Mutex::new(Vec::new()),
            connects: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            input_sha256: Mutex::new(target.sha256.clone()),
            input_path: Mutex::new(target.path.clone()),
            image_base: Mutex::new("0x1000".to_string()),
            pseudocode: Mutex::new("int main(void) { return 42; }".to_string()),
            owned: AtomicBool::new(true),
            database: Mutex::new(None),
            fail_close: AtomicBool::new(false),
            fail_tool: Mutex::new(None),
            gate: Mutex::new(None),
            hook: Mutex::new(None),
            before_call: Mutex::new(None),
        })
    }

    fn names(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn count(&self, tool: &str) -> usize {
        self.names().iter().filter(|n| *n == tool).count()
    }

    fn args_of(&self, tool: &str) -> Vec<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == tool)
            .map(|(_, a)| a.clone())
            .collect()
    }

    fn set_hook(&self, hook: impl Fn(&str, &Value) -> Option<Value> + Send + Sync + 'static) {
        *self.hook.lock().unwrap() = Some(Arc::new(hook));
    }

    fn function() -> Value {
        json!({ "address": "0x1000", "name": "main", "size": "0x20" })
    }

    fn modern_function() -> Value {
        json!({ "addr": "0x1000", "name": "main", "size": "0x20" })
    }

    fn assembly() -> Value {
        json!({
            "name": "main",
            "start_ea": "0x1000",
            "lines": [{ "address": "0x1000", "instruction": "ret", "comments": ["observed comment"] }],
            "return_type": "int",
            "arguments": [],
        })
    }

    fn read(&self, name: &str) -> Value {
        match name {
            "get_metadata" => json!({
                "path": *self.input_path.lock().unwrap(),
                "module": "target.elf",
                "sha256": *self.input_sha256.lock().unwrap(),
                "base": *self.image_base.lock().unwrap(),
            }),
            "list_functions" => json!({ "data": [Self::function()], "next_offset": null }),
            "list_funcs" => json!([{ "data": [Self::modern_function()], "next_offset": null }]),
            "get_function_by_address" => {
                let mut function = Self::function();
                function["address"] = json!("0x1004");
                function
            }
            "get_function_by_name" => Self::function(),
            "lookup_funcs" => {
                json!([{ "query": "main", "fn": Self::modern_function(), "error": null }])
            }
            "decompile_function" => json!(*self.pseudocode.lock().unwrap()),
            "decompile" => {
                json!({ "code": *self.pseudocode.lock().unwrap(), "cursor": { "done": true } })
            }
            "disassemble_function" => Self::assembly(),
            "disasm" => json!({ "asm": Self::assembly(), "cursor": { "done": true } }),
            "get_callers" => json!([
                { "address": "0x1004", "name": "main", "size": "0x20" },
                { "address": "0x1008", "name": "main", "size": "0x20" },
            ]),
            "get_callees" => json!([{ "address": "0x2000", "name": "puts", "type": "external" }]),
            "callees" => {
                json!([{ "callees": [{ "addr": "0x2000", "name": "puts", "type": "external" }], "more": false }])
            }
            "get_xrefs_to" => {
                json!([{ "address": "0x1004", "type": "code", "function": Self::function() }])
            }
            "xrefs_to" => json!([{
                "xrefs": [{ "addr": "0x1004", "type": "code", "fn": Self::modern_function() }],
                "more": false,
            }]),
            "list_strings" => {
                json!({ "data": [{ "address": "0x3000", "length": 5, "string": "a.b\nC" }], "next_offset": null })
            }
            "find_regex" => {
                json!({ "matches": [{ "addr": "0x3000", "string": "a.b\nC" }], "cursor": { "done": true } })
            }
            other => panic!("unimplemented producer tool {other}"),
        }
    }

    fn lifecycle(&self, name: &str, args: &Value) -> Result<Value, IdaFault> {
        let input_path = self.input_path.lock().unwrap().clone();
        match name {
            "idb_open" => {
                let id = args["preferred_session_id"]
                    .as_str()
                    .expect("lifecycle identity")
                    .to_string();
                *self.input_path.lock().unwrap() =
                    args["input_path"].as_str().expect("input path").to_string();
                *self.database.lock().unwrap() = Some(id.clone());
                Ok(json!({
                    "success": true,
                    "session": { "session_id": id, "input_path": *self.input_path.lock().unwrap() },
                }))
            }
            "idb_list" => {
                let database = self.database.lock().unwrap().clone();
                Ok(json!({
                    "sessions": database.map(|id| json!({
                        "session_id": id,
                        "input_path": input_path,
                        "owned": self.owned.load(Ordering::SeqCst),
                        "backend": "worker",
                        "is_active": true,
                    })).into_iter().collect::<Vec<_>>(),
                }))
            }
            "server_health" => Ok(json!({
                "status": "ok",
                "input_path": input_path,
                "idb_path": format!("{input_path}.i64"),
                "module": "target.elf",
                "imagebase": *self.image_base.lock().unwrap(),
                "auto_analysis_ready": true,
            })),
            "idb_close" => {
                if self.fail_close.load(Ordering::SeqCst) {
                    return Err(IdaFault::Other("Worker release failed".to_string()));
                }
                let id = self.database.lock().unwrap().take();
                Ok(json!({
                    "success": true,
                    "session_id": id.unwrap_or_else(|| "missing".to_string()),
                    "saved": null,
                    "owned": self.owned.load(Ordering::SeqCst),
                    "backend": "worker",
                }))
            }
            other => panic!("unimplemented producer tool {other}"),
        }
    }
}

#[async_trait]
impl IdaConnection for RecordingIdaMcp {
    async fn connect(&self) -> Result<Vec<String>, IdaFault> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let legacy = [
            "get_metadata",
            "list_functions",
            "list_strings",
            "get_function_by_name",
            "get_function_by_address",
            "decompile_function",
            "disassemble_function",
            "get_callers",
            "get_callees",
            "get_xrefs_to",
        ];
        let modern = [
            "idb_open",
            "idb_list",
            "idb_close",
            "server_health",
            "list_funcs",
            "lookup_funcs",
            "find_regex",
            "decompile",
            "disasm",
            "callees",
            "xrefs_to",
        ];
        let names: &[&str] = if self.mode == IdaMode::Attached {
            &legacy
        } else {
            &modern
        };
        Ok(names.iter().map(|n| (*n).to_string()).collect())
    }

    async fn call(&self, name: &str, args: &Value) -> Result<Value, IdaFault> {
        self.calls
            .lock()
            .unwrap()
            .push((name.to_string(), args.clone()));
        let gate = self
            .gate
            .lock()
            .unwrap()
            .as_ref()
            .filter(|g| g.tool == name)
            .map(|g| (g.started.clone(), g.release.clone()));
        if let Some((started, release)) = gate {
            started.notify_one();
            release.notified().await;
        }
        let before_call = self.before_call.lock().unwrap().clone();
        if let Some(before_call) = before_call {
            if let Some(message) = before_call(name) {
                return Err(IdaFault::Other(message));
            }
        }
        let failing = self.fail_tool.lock().unwrap().clone();
        if let Some((tool, message)) = failing {
            if tool == name {
                return Err(IdaFault::Other(message));
            }
        }
        let hook = self.hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            if let Some(overridden) = hook(name, args) {
                return Ok(overridden);
            }
        }
        if matches!(
            name,
            "idb_open" | "idb_list" | "idb_close" | "server_health"
        ) {
            return self.lifecycle(name, args);
        }
        Ok(self.read(name))
    }

    fn server_info(&self) -> Value {
        json!({ "name": "upstream-fixture", "version": "sdk-version-is-not-ida" })
    }

    async fn close(&self) -> Result<(), IdaFault> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    target: BinaryTarget,
    producer: Arc<RecordingIdaMcp>,
    client: IdaSessionClient,
}

fn target_in(root: &Path) -> BinaryTarget {
    let path = root.join("target.elf");
    let bytes = b"\x7fELF\x02\x01\x01\x00fixture-bytes";
    std::fs::write(&path, bytes).unwrap();
    BinaryTarget {
        path: path.to_string_lossy().to_string(),
        kind: "executable".to_string(),
        format: "elf".to_string(),
        architecture: Some("x86_64".to_string()),
        available_architectures: vec!["x86_64".to_string()],
        sha256: hex::encode(Sha256::digest(bytes)),
        executable_role: None,
        managed: None,
        mips_elf: None,
    }
}

fn registration(mode: &str, root: Option<&Path>) -> IdaRegistration {
    let mut value = json!({ "command": "fixture", "mode": mode, "timeoutMs": 1000 });
    if let Some(root) = root {
        value["workspaceRoot"] = json!(root);
    }
    parse_registration(&value).expect("valid registration")
}

fn fixture(mode: IdaMode) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let target = target_in(root.path());
    let producer = RecordingIdaMcp::new(&target, mode);
    let registration = registration(mode.as_str(), Some(root.path()));
    let client = IdaSessionClient::new(registration, target.clone(), producer.clone(), None);
    Fixture {
        root,
        target,
        producer,
        client,
    }
}

async fn run(
    client: &IdaSessionClient,
    operation: &str,
    parameters: Value,
) -> Result<crate::provider::AnalysisExecution, AnalysisError> {
    client
        .execute(operation, &parameters, &ExecContext::default())
        .await
}

fn entries(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    names
}

fn has_private_workspace(root: &Path) -> bool {
    entries(root)
        .iter()
        .any(|name| name.starts_with("rea-ida-"))
}

fn is_cleanup_incomplete(error: &AnalysisError) -> bool {
    matches!(
        error,
        AnalysisError::ProviderAdapter {
            cleanup_incomplete: true,
            ..
        }
    )
}

// ---------------------------------------------------------------- pagination (headless)

#[tokio::test(flavor = "multi_thread")]
async fn headless_pagination_follows_reported_cursors_and_bare_hex_assembly() {
    let f = fixture(IdaMode::Headless);
    f.producer.set_hook(|name, args| {
        let first = args["offset"] == json!(0);
        let cursor = if first { json!({ "next": 1 }) } else { json!({ "done": true }) };
        match name {
            "decompile" => Some(json!({ "code": if first { "first line" } else { "second line" }, "cursor": cursor })),
            "disasm" => Some(json!({
                "asm": {
                    "name": "main",
                    "start_ea": "0x1000",
                    "lines": [{ "addr": if first { "1000" } else { "1001" }, "instruction": if first { "push rbp" } else { "ret" } }],
                },
                "cursor": cursor,
            })),
            "find_regex" => Some(json!({
                "matches": [{ "addr": if first { "0x3000" } else { "0x3002" }, "string": if first { "a.b" } else { "a+b" } }],
                "cursor": cursor,
            })),
            "list_funcs" => {
                let page = args["queries"]["offset"].as_u64().unwrap();
                Some(json!([{
                    "data": [{
                        "addr": if page == 0 { "0x1000" } else { "0x2000" },
                        "name": if page == 0 { "main" } else { "other" },
                        "size": "0x20",
                    }],
                    "next_offset": if page == 0 { json!(1) } else { Value::Null },
                }]))
            }
            _ => None,
        }
    });
    assert_eq!(
        run(&f.client, "list_procedures", json!({}))
            .await
            .unwrap()
            .result
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        run(&f.client, "list_strings", json!({}))
            .await
            .unwrap()
            .result
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let dossier = run(
        &f.client,
        "analyze_function",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap()
    .result;
    assert_eq!(dossier["pseudocode"], "first line\nsecond line");
    assert_eq!(
        dossier["assembly"],
        json!(["0x1000: push rbp", "0x1001: ret"])
    );
    assert_eq!(dossier["procedure"]["classification"], Value::Null);
    assert_eq!(
        dossier["procedure"]["body"],
        json!({ "available": false, "reason": "IDA MCP does not report complete function body ranges." })
    );
    assert_eq!(dossier["native_api"], Value::Null);
    assert_eq!(dossier["native_value_flow"], Value::Null);
    assert!(f.client.close(false).await.is_ok());
}

// ---------------------------------------------------------------- attached semantics

#[tokio::test(flavor = "multi_thread")]
async fn attached_accepts_a_normalized_spelling_of_the_bound_document() {
    let f = fixture(IdaMode::Attached);
    let spelled = f.target.path.replace("/target.elf", "/./target.elf");
    assert!(
        run(&f.client, "list_procedures", json!({ "document": spelled }))
            .await
            .is_ok()
    );
    assert!(f.producer.count("list_functions") > 0);
    assert!(f.client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_rejects_an_unrelated_document_before_connecting() {
    let f = fixture(IdaMode::Attached);
    let error = run(
        &f.client,
        "list_procedures",
        json!({ "document": "/unrelated/input" }),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&error, AnalysisError::Input { operation, .. } if operation == "list_procedures")
    );
    assert_eq!(f.producer.connects.load(Ordering::SeqCst), 0);
    assert!(f.producer.names().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn hexadecimal_looking_names_stay_names_unless_the_caller_writes_0x() {
    let f = fixture(IdaMode::Attached);
    f.producer.set_hook(|name, args| {
        (name == "get_function_by_name" && args["name"] == "f")
            .then(|| json!({ "address": "0x1000", "name": "f", "size": "0x20" }))
    });
    let found = run(&f.client, "procedure_address", json!({ "procedure": "f" }))
        .await
        .unwrap();
    assert_eq!(found.result, "0x1000");
    assert_eq!(f.producer.count("get_function_by_address"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_null_arguments_are_rejected_before_connecting() {
    let f = fixture(IdaMode::Attached);
    for (operation, parameters, key) in [
        ("list_procedures", json!({ "document": null }), "document"),
        ("list_strings", json!({ "address": null }), "address"),
        (
            "procedure_pseudo_code",
            json!({ "procedure": null }),
            "procedure",
        ),
    ] {
        match run(&f.client, operation, parameters).await.unwrap_err() {
            AnalysisError::Input { issues, .. } => {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].path, vec![json!(key)]);
                assert_eq!(issues[0].reason, "invalid_type");
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(f.producer.connects.load(Ordering::SeqCst), 0);
    assert!(f.producer.names().is_empty());
    assert!(run(&f.client, "list_procedures", json!({})).await.is_ok());
    assert!(run(&f.client, "list_strings", json!({})).await.is_ok());
    assert!(run(
        &f.client,
        "procedure_pseudo_code",
        json!({ "procedure": "main" })
    )
    .await
    .is_ok());
    assert_eq!(f.producer.count("decompile_function"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_function_observations_resolve_entries_and_report_unknown_body_evidence() {
    let f = fixture(IdaMode::Attached);
    let execution = run(
        &f.client,
        "analyze_function",
        json!({ "procedure": "0x1004" }),
    )
    .await
    .unwrap();
    let dossier = &execution.result;
    assert_eq!(dossier["procedure"]["address"], "0x1000");
    let addresses = |key: &str| -> Vec<Value> {
        dossier[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["address"].clone())
            .collect()
    };
    assert_eq!(addresses("callers"), vec![json!("0x1000")]);
    assert_eq!(addresses("callees"), vec![json!("0x2000")]);
    assert_eq!(dossier["procedure"]["body"]["available"], false);
    assert_eq!(dossier["comments"], json!([]));
    assert_eq!(dossier["procedure"]["signature"], "int main()");
    let raw = execution.raw_result.as_ref().unwrap();
    assert!(raw["observations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["tool"] == "get_callers"));
    assert_eq!(raw["upstream"]["version"], "sdk-version-is-not-ida");
    assert_eq!(execution.provider.version.as_deref(), Some("1"));
    assert!(f.client.close(false).await.is_ok());
    assert!(
        f.producer.names().iter().all(|n| !n.starts_with("idb_")),
        "attached mode must not touch the database lifecycle"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn complete_paged_inventory_and_literal_versus_regex_search() {
    let f = fixture(IdaMode::Attached);
    f.producer.set_hook(|name, args| {
        (name == "list_functions").then(|| {
            let first = args["offset"] == json!(0);
            json!({
                "data": [{ "address": if first { "0x1000" } else { "0x2000" }, "name": "main", "size": "0x10" }],
                "next_offset": if first { json!(100) } else { Value::Null },
            })
        })
    });
    assert_eq!(
        run(&f.client, "list_procedures", json!({}))
            .await
            .unwrap()
            .result
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for (pattern, mode, count) in [
        ("a.b", "literal", 1),
        ("a+b", "literal", 0),
        ("a.b", "regex", 1),
    ] {
        let found = run(
            &f.client,
            "search_strings",
            json!({ "pattern": pattern, "mode": mode }),
        )
        .await
        .unwrap();
        assert_eq!(
            found.result.as_array().unwrap().len(),
            count,
            "{pattern} {mode}"
        );
    }
    assert!(run(
        &f.client,
        "search_strings",
        json!({ "pattern": "[", "mode": "regex" })
    )
    .await
    .is_err());
    assert!(f.client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn mismatched_identities_and_target_switches_are_never_successful_observations() {
    let f = fixture(IdaMode::Attached);
    *f.producer.input_sha256.lock().unwrap() = "a".repeat(64);
    let mismatch = run(
        &f.client,
        "procedure_address",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap_err();
    // The generic projection hides the cause; the diagnostic message keeps it.
    assert!(
        mismatch.message().contains("SHA-256"),
        "{}",
        mismatch.message()
    );
    *f.producer.input_sha256.lock().unwrap() = f.target.sha256.clone();
    let producer = f.producer.clone();
    *f.producer.before_call.lock().unwrap() = Some(Arc::new(move |name| {
        if name == "decompile_function" {
            *producer.image_base.lock().unwrap() = "0x2000".to_string();
        }
        None
    }));
    let changed = run(
        &f.client,
        "procedure_pseudo_code",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap_err();
    assert!(
        changed.message().contains("changed"),
        "{}",
        changed.message()
    );
    assert!(f.client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_producer_data_and_non_advancing_cursors_fail_closed() {
    let f = fixture(IdaMode::Attached);
    // A mutating operation is not part of the adapter; nothing is even connected.
    let mutation = run(
        &f.client,
        "set_address_name",
        json!({ "address": "0x1000", "name": "changed" }),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        mutation,
        AnalysisError::CapabilityUnavailable { .. }
    ));
    assert_eq!(f.producer.connects.load(Ordering::SeqCst), 0);
    assert!(run(&f.client, "xrefs", json!({})).await.is_err());
    let invalid = run(&f.client, "xrefs", json!({ "address": "not-an-address" }))
        .await
        .unwrap_err();
    assert_eq!(invalid.tag(), "AnalysisInputError");
    assert_eq!(f.producer.connects.load(Ordering::SeqCst), 0);
    f.producer.set_hook(|name, _| {
        (name == "list_functions").then(|| json!({ "data": [], "next_offset": 0 }))
    });
    assert!(run(&f.client, "list_procedures", json!({})).await.is_err());
    f.producer
        .set_hook(|name, _| (name == "decompile_function").then(|| json!({ "unexpected": true })));
    let malformed = run(
        &f.client,
        "procedure_pseudo_code",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap_err();
    assert_eq!(malformed.tag(), "AnalysisOutputError");
    match malformed {
        AnalysisError::Output { reason, .. } => assert_eq!(
            reason,
            "IDA MCP returned malformed or unsupported producer data: $: Invalid input: expected string, received object"
        ),
        other => panic!("unexpected {other:?}"),
    }
    assert!(f.client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_drains_in_flight_read_only_work_before_closing_the_proxy() {
    let f = fixture(IdaMode::Attached);
    assert!(run(
        &f.client,
        "procedure_address",
        json!({ "procedure": "main" })
    )
    .await
    .is_ok());
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *f.producer.gate.lock().unwrap() = Some(Gate {
        tool: "decompile_function".to_string(),
        started: started.clone(),
        release: release.clone(),
    });
    let client = Arc::new(f.client);
    let cancel = CancelToken::new();
    let call = {
        let client = client.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            client
                .execute(
                    "procedure_pseudo_code",
                    &json!({ "procedure": "main" }),
                    &ExecContext { cancel },
                )
                .await
        })
    };
    started.notified().await;
    cancel.cancel();
    let closing = {
        let client = client.clone();
        tokio::spawn(async move { client.close(false).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        f.producer.closes.load(Ordering::SeqCst),
        0,
        "the proxy must outlive the in-flight request"
    );
    release.notify_one();
    let result = call.await.unwrap();
    assert!(
        matches!(result, Err(AnalysisError::Cancelled { .. })),
        "{result:?}"
    );
    assert!(closing.await.unwrap().is_ok());
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_caller_does_not_abandon_the_request_or_break_serialization() {
    let f = fixture(IdaMode::Attached);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *f.producer.gate.lock().unwrap() = Some(Gate {
        tool: "decompile_function".to_string(),
        started: started.clone(),
        release: release.clone(),
    });
    let client = Arc::new(f.client);
    let abandoned = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .execute(
                    "procedure_pseudo_code",
                    &json!({ "procedure": "main" }),
                    &ExecContext::default(),
                )
                .await
        })
    };
    started.notified().await;
    abandoned.abort();
    // The next request queues behind the drained one instead of interleaving with it.
    let next = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .execute(
                    "procedure_address",
                    &json!({ "procedure": "main" }),
                    &ExecContext::default(),
                )
                .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // The abandoned request already resolved `main` (two lookups); the queued one has not started.
    assert_eq!(
        f.producer.count("get_function_by_name"),
        2,
        "the second request must wait"
    );
    release.notify_one();
    assert!(next.await.unwrap().is_ok());
    assert_eq!(f.producer.count("get_function_by_name"), 4);
    assert!(client.close(false).await.is_ok());
}

// ---------------------------------------------------------------- headless lifecycle

#[tokio::test(flavor = "multi_thread")]
async fn headless_never_closes_an_unowned_worker() {
    let f = fixture(IdaMode::Headless);
    f.producer.owned.store(false, Ordering::SeqCst);
    assert!(run(&f.client, "health", json!({})).await.is_err());
    let closed = f.client.close(false).await.unwrap_err();
    assert!(is_cleanup_incomplete(&closed));
    assert_eq!(f.producer.count("idb_close"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_close_callers_share_one_in_flight_close() {
    let f = fixture(IdaMode::Headless);
    assert!(run(&f.client, "health", json!({})).await.is_ok());
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *f.producer.gate.lock().unwrap() = Some(Gate {
        tool: "idb_close".to_string(),
        started: started.clone(),
        release: release.clone(),
    });
    let client = Arc::new(f.client);
    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.close(false).await })
    };
    started.notified().await;
    let second = {
        let client = client.clone();
        tokio::spawn(async move { client.close(false).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    release.notify_one();
    assert!(first.await.unwrap().is_ok());
    assert!(second.await.unwrap().is_ok());
    assert_eq!(f.producer.count("idb_close"), 1);
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfirmed_open_retains_the_workspace_and_is_never_retried() {
    let f = fixture(IdaMode::Headless);
    *f.producer.fail_tool.lock().unwrap() = Some((
        "idb_open".to_string(),
        "Timed out while the worker may still be opening".to_string(),
    ));
    assert!(run(&f.client, "health", json!({})).await.is_err());
    assert!(run(&f.client, "health", json!({})).await.is_err());
    assert_eq!(f.producer.count("idb_open"), 1);
    let closed = f.client.close(false).await.unwrap_err();
    assert!(is_cleanup_incomplete(&closed));
    assert!(has_private_workspace(f.root.path()));
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_opens_a_private_copy_scopes_requests_and_closes_without_saving() {
    let f = fixture(IdaMode::Headless);
    let original = std::fs::read(&f.target.path).unwrap();
    let execution = run(
        &f.client,
        "analyze_function",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap();
    let input = f.producer.input_path.lock().unwrap().clone();
    assert_ne!(input, f.target.path);
    assert_eq!(std::fs::read(&input).unwrap(), original);
    let limitations = execution.result["limitations"].as_array().unwrap();
    assert!(limitations
        .iter()
        .any(|v| v.as_str().unwrap().contains("Direct callers")));
    let open = &f.producer.args_of("idb_open")[0];
    assert_eq!(open["mode"], "force_headless");
    assert_eq!(open["run_auto_analysis"], true);
    let database = f.producer.database.lock().unwrap().clone().unwrap();
    for (name, args) in f.producer.calls.lock().unwrap().iter() {
        if !matches!(name.as_str(), "idb_open" | "idb_list") {
            assert_eq!(args["database"], json!(database), "{name} must be scoped");
        }
    }
    assert!(f.client.close(false).await.is_ok());
    assert_eq!(f.producer.args_of("idb_close")[0]["save"], json!(false));
    assert_eq!(entries(f.root.path()), vec!["target.elf".to_string()]);
    assert_eq!(std::fs::read(&f.target.path).unwrap(), original);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_worker_release_retains_the_workspace_and_a_later_close_retries_it() {
    let f = fixture(IdaMode::Headless);
    assert!(run(&f.client, "health", json!({})).await.is_ok());
    f.producer.fail_close.store(true, Ordering::SeqCst);
    let failed = f.client.close(false).await.unwrap_err();
    assert!(is_cleanup_incomplete(&failed));
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 0);
    assert!(has_private_workspace(f.root.path()));
    f.producer.fail_close.store(false, Ordering::SeqCst);
    assert!(f.client.close(false).await.is_ok());
    assert_eq!(f.producer.count("idb_close"), 2);
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 1);
    assert_eq!(entries(f.root.path()), vec!["target.elf".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn inventory_verification_after_an_acknowledged_close_is_retried_without_closing_again() {
    let f = fixture(IdaMode::Headless);
    assert!(run(&f.client, "health", json!({})).await.is_ok());
    let inventory_fails = Arc::new(AtomicBool::new(true));
    let producer = f.producer.clone();
    let flag = inventory_fails.clone();
    // After the worker is released, the post-close inventory is unavailable until the flag drops.
    *f.producer.before_call.lock().unwrap() = Some(Arc::new(move |name| {
        (name == "idb_list"
            && producer.database.lock().unwrap().is_none()
            && flag.load(Ordering::SeqCst))
        .then(|| "Worker inventory unavailable after acknowledged close".to_string())
    }));
    assert!(f.client.close(false).await.is_err());
    assert_eq!(f.producer.closes.load(Ordering::SeqCst), 0);
    assert!(has_private_workspace(f.root.path()));
    inventory_fails.store(false, Ordering::SeqCst);
    assert!(f.client.close(false).await.is_ok());
    assert_eq!(f.producer.count("idb_close"), 1);
    assert_eq!(entries(f.root.path()), vec!["target.elf".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_input_identity_at_startup_never_closes_an_unrelated_database() {
    let f = fixture(IdaMode::Headless);
    f.producer.set_hook(|name, _| {
        (name == "idb_open").then(|| {
            json!({ "success": true, "session": { "session_id": "user-database", "input_path": "/unrelated/input" } })
        })
    });
    assert!(run(&f.client, "health", json!({})).await.is_err());
    assert!(f.client.close(false).await.is_ok());
    assert_eq!(f.producer.count("idb_close"), 0);
    assert_eq!(entries(f.root.path()), vec!["target.elf".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_privately_owned_worker_is_released_after_malformed_open_output() {
    let f = fixture(IdaMode::Headless);
    let producer = f.producer.clone();
    // Register the worker the way a real upstream would, then answer with garbage.
    f.producer.set_hook(move |name, args| {
        if name == "idb_open" {
            *producer.database.lock().unwrap() =
                args["preferred_session_id"].as_str().map(str::to_string);
            *producer.input_path.lock().unwrap() = args["input_path"].as_str().unwrap().to_string();
            let id = producer.database.lock().unwrap().clone().unwrap();
            return Some(json!({ "success": true, "session": { "session_id": id } }));
        }
        None
    });
    assert!(run(&f.client, "health", json!({})).await.is_err());
    assert!(f.client.close(false).await.is_ok());
    let closes = f.producer.args_of("idb_close");
    assert_eq!(closes.len(), 1);
    assert!(closes[0]["database"].as_str().unwrap().starts_with("rea-"));
    assert_eq!(entries(f.root.path()), vec!["target.elf".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_failures_survive_alongside_preview_data() {
    for (tool, operation, parameters, response) in [
        (
            "decompile",
            "procedure_pseudo_code",
            json!({ "procedure": "main" }),
            json!({ "code": "partial pseudocode", "cursor": { "done": true } }),
        ),
        (
            "xrefs_to",
            "xrefs",
            json!({ "address": "0x1000" }),
            json!([{ "xrefs": [], "more": false }]),
        ),
        (
            "callees",
            "procedure_callees",
            json!({ "procedure": "main" }),
            json!([{ "callees": [], "more": false }]),
        ),
        (
            "decompile",
            "analyze_function",
            json!({ "procedure": "main" }),
            json!({ "code": "partial pseudocode", "cursor": { "done": true } }),
        ),
        (
            "callees",
            "analyze_function",
            json!({ "procedure": "main" }),
            json!([{ "callees": [], "more": false }]),
        ),
    ] {
        let f = fixture(IdaMode::Headless);
        let failure = "Database analysis interrupted while reading observations";
        let tool_name = tool.to_string();
        f.producer.set_hook(move |name, _| {
            if name != tool_name {
                return None;
            }
            let with_error = |value: &Value| {
                let mut object = value.as_object().unwrap().clone();
                object.insert("error".to_string(), json!(failure));
                Value::Object(object)
            };
            Some(match &response {
                Value::Array(items) => Value::Array(items.iter().map(with_error).collect()),
                other => with_error(other),
            })
        });
        let error = run(&f.client, operation, parameters).await.unwrap_err();
        assert!(
            error.message().contains(failure),
            "{tool}/{operation}: {}",
            error.message()
        );
        assert!(f.client.close(false).await.is_ok());
    }
}

// ---------------------------------------------------------------- provider composition

fn provider_with(
    mode: &str,
    producer: Option<Arc<RecordingIdaMcp>>,
    registration_json: Value,
) -> (IdaProvider, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registration.json");
    let mut value = registration_json;
    value["mode"] = json!(mode);
    std::fs::write(&path, value.to_string()).unwrap();
    let mut environment = BTreeMap::new();
    environment.insert(
        "REA_IDA_MCP_CONFIG".to_string(),
        path.to_string_lossy().to_string(),
    );
    let config = IdaConfig::from_environment(&environment);
    let provider = match producer {
        Some(producer) => IdaProvider::with_connection_factory(
            config,
            Arc::new(move |_, _| producer.clone() as Arc<dyn IdaConnection>),
        ),
        None => IdaProvider::new(config),
    };
    (provider, directory)
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_commits_adapter_semantics_without_launching_or_persisting_credentials() {
    let root = tempfile::tempdir().unwrap();
    let target = target_in(root.path());
    let producer = RecordingIdaMcp::new(&target, IdaMode::Headless);
    let (provider, _registration) = provider_with(
        "headless",
        Some(producer.clone()),
        json!({ "url": "http://127.0.0.1:8745/mcp", "headers": { "Authorization": "Bearer private-fixture-credential" } }),
    );
    let availability = provider.inspect_availability();
    assert!(availability.available);
    assert_eq!(availability.diagnostics["live_connection_probed"], false);
    assert_eq!(availability.diagnostics["transport"], "http");
    let profile = provider
        .resolve_analysis_profile(&target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.provider.version, "1");
    assert_eq!(profile.parameters["engine_version"], Value::Null);
    assert_eq!(
        profile.parameters["upstream_distribution_version"],
        Value::Null
    );
    assert_eq!(profile.parameters["cache_policy"], "live");
    assert_eq!(profile.parameters["version_scope"], "rea-ida-adapter");
    assert_eq!(
        profile.parameters["compatibility_profile"],
        "database-supervisor"
    );
    assert!(!serde_json::to_string(&profile)
        .unwrap()
        .contains("private-fixture-credential"));
    profile.verify().expect("the profile digest is consistent");
    assert_eq!(producer.connects.load(Ordering::SeqCst), 0);
    let callers = provider
        .capabilities()
        .into_iter()
        .find(|c| c.operation == "procedure_callers")
        .unwrap();
    assert!(!callers.available);
    assert_eq!(
        callers.reason.as_deref(),
        Some("The modern upstream profile reports code references without proving direct call edges.")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_are_live_read_only_and_truthful_about_effects() {
    let (stdio, _a) = provider_with("attached", None, json!({ "command": "ida-mcp" }));
    let capabilities = stdio.capabilities();
    assert_eq!(capabilities.len(), 12);
    assert_eq!(
        capabilities
            .iter()
            .map(|c| c.operation.as_str())
            .collect::<Vec<_>>(),
        IDA_OPERATIONS
    );
    for capability in &capabilities {
        assert!(capability.available, "{}", capability.operation);
        assert_eq!(capability.cache_policy, CachePolicy::Live);
        assert!(!capability.effects.mutates_artifact);
        assert!(capability.effects.may_access_network);
        assert!(capability.effects.launches_process && capability.effects.may_write_filesystem);
        assert_eq!(capability.limitations.len(), 6);
    }
    let (http, _b) = provider_with("attached", None, json!({ "url": "http://localhost:9/mcp" }));
    assert!(http
        .capabilities()
        .iter()
        .all(|c| !c.effects.launches_process && !c.effects.may_write_filesystem));
    let (headless_http, _c) =
        provider_with("headless", None, json!({ "url": "http://localhost:9/mcp" }));
    assert!(headless_http
        .capabilities()
        .iter()
        .all(|c| c.effects.launches_process));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejects_unsupported_targets_and_reports_incomplete_profiles_on_first_analysis() {
    let root = tempfile::tempdir().unwrap();
    let target = target_in(root.path());
    let producer = RecordingIdaMcp::new(&target, IdaMode::Attached);
    let (provider, _registration) = provider_with(
        "headless",
        Some(producer.clone()),
        json!({ "command": "fixture" }),
    );
    let mut database = target.clone();
    database.kind = "database".to_string();
    database.format = "analysis-database".to_string();
    let support = provider.inspect_target_support(&database);
    assert!(!support.supported);
    assert_eq!(support.code.as_deref(), Some("target_kind_unsupported"));
    let mut mips = target.clone();
    mips.architecture = Some("mips".to_string());
    assert_eq!(
        provider.inspect_target_support(&mips).code.as_deref(),
        Some("architecture_unsupported")
    );
    assert!(provider.inspect_target_support(&target).supported);
    let client = provider.create_client(
        &target,
        provider.resolve_analysis_profile(&target).await.unwrap(),
    );
    assert_eq!(producer.connects.load(Ordering::SeqCst), 0);
    let error = client
        .execute(
            "procedure_pseudo_code",
            &json!({ "procedure": "main" }),
            &ExecContext::default(),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .message()
            .contains("headless compatibility profile is missing tools: idb_open"),
        "{}",
        error.message()
    );
    assert_eq!(producer.connects.load(Ordering::SeqCst), 1);
    assert!(client.close(false).await.is_ok());
    assert_eq!(producer.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn live_results_are_re_observed_every_time_never_replayed_from_the_session_cache() {
    let root = tempfile::tempdir().unwrap();
    let target = target_in(root.path());
    let producer = RecordingIdaMcp::new(&target, IdaMode::Attached);
    let (provider, _registration) = provider_with(
        "attached",
        Some(producer.clone()),
        json!({ "command": "fixture" }),
    );
    let session = EngineSession::new(Registry::new(vec![Arc::new(provider)], "auto"));
    let route = session.route_for(&target, None, &|| true).await.unwrap();
    assert_eq!(route.provider_id(), "ida");
    let query = json!({ "procedure": "main", "document": target.path });
    let ctx = ExecContext::default();
    let first = route
        .execute("procedure_pseudo_code", &query, &ctx)
        .await
        .unwrap();
    assert_eq!(first.result, "int main(void) { return 42; }");
    *producer.pseudocode.lock().unwrap() = "int main(void) { return 99; }".to_string();
    let second = route
        .execute("procedure_pseudo_code", &query, &ctx)
        .await
        .unwrap();
    assert_eq!(second.result, "int main(void) { return 99; }");
    assert_eq!(producer.count("decompile_function"), 2);
    assert!(!second
        .limitations
        .iter()
        .any(|l| l.contains("local REA analysis snapshot")));
    // Headless mode declares procedure_callers unavailable; the route reports it as such.
    session.release().await.unwrap();
    assert_eq!(producer.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_callers_are_unavailable_through_the_route_and_the_client() {
    let f = fixture(IdaMode::Headless);
    let error = run(
        &f.client,
        "procedure_callers",
        json!({ "procedure": "main" }),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, AnalysisError::CapabilityUnavailable { .. }));
    assert_eq!(f.producer.connects.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn operation_contracts_cover_every_declared_operation_in_both_modes() {
    for mode in [IdaMode::Attached, IdaMode::Headless] {
        for operation in IDA_OPERATIONS {
            let f = fixture(mode);
            let parameters = if operation.starts_with("search_") {
                json!({ "pattern": "a.b" })
            } else if operation == "xrefs" {
                json!({ "address": "0x1000" })
            } else if operation.starts_with("list_") {
                json!({})
            } else {
                json!({ "procedure": "main" })
            };
            let outcome = run(&f.client, operation, parameters).await;
            if mode == IdaMode::Headless && operation == "procedure_callers" {
                assert!(matches!(
                    outcome,
                    Err(AnalysisError::CapabilityUnavailable { .. })
                ));
            } else {
                let execution = outcome.unwrap_or_else(|e| panic!("{mode:?} {operation}: {e:?}"));
                assert_eq!(execution.provider.id, "ida");
                assert!(execution.raw_result.is_some());
                assert_eq!(
                    execution.locations.first(),
                    Some(
                        &tracewise_domain::evidence::EvidenceLocation::ArtifactPath {
                            path: f.target.path.clone()
                        }
                    )
                );
            }
            assert!(f.client.close(false).await.is_ok());
        }
    }
}

// ---------------------------------------------------------------- registration + decoding

fn write_json(dir: &Path, name: &str, value: &Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path
}

#[test]
fn registrations_accept_direct_and_upstream_mcp_servers_documents() {
    let dir = tempfile::tempdir().unwrap();
    for input in [
        json!({ "command": "python", "args": ["server.py"] }),
        json!({ "mcpServers": { "ida-pro-mcp": { "command": "python", "args": ["server.py"] }, "unrelated": { "command": "untouched" } } }),
    ] {
        let path = write_json(dir.path(), "mcp.json", &input);
        let registration = read_registration(path.to_str().unwrap()).unwrap();
        assert_eq!(registration.mode, IdaMode::Attached);
        assert_eq!(registration.timeout_ms, 300_000);
        assert!(registration.is_stdio());
        assert_eq!(registration.canonical()["args"], json!(["server.py"]));
    }
}

#[test]
fn registrations_validate_local_transports_and_lifecycle_inputs() {
    let dir = tempfile::tempdir().unwrap();
    for input in [
        json!({ "url": "https://example.com/mcp" }),
        json!({ "url": "http://token@127.0.0.1/mcp" }),
        json!({ "command": "python", "mode": "force_gui" }),
        json!({ "command": "python", "workspaceRoot": "relative" }),
        json!({ "command": "python", "args": "server.py" }),
        json!({ "command": "" }),
        json!({ "command": "python", "url": "http://127.0.0.1/mcp" }),
        json!({ "command": "python", "timeoutMs": 0 }),
        json!({ "command": "python", "timeoutMs": 1.5 }),
        json!({ "command": "python", "unknown": true }),
        json!({ "command": "python", "type": "http" }),
        json!({ "command": "python", "env": { "A": 1 } }),
    ] {
        let path = write_json(dir.path(), "mcp.json", &input);
        assert!(
            read_registration(path.to_str().unwrap()).is_err(),
            "{input}"
        );
    }
    let accepted = write_json(
        dir.path(),
        "ok.json",
        &json!({ "url": "http://127.0.0.1:8745/mcp", "mode": "headless", "headers": { "Authorization": "Bearer fixture-credential" } }),
    );
    let registration = read_registration(accepted.to_str().unwrap()).unwrap();
    assert!(!registration.is_stdio());
    assert_eq!(registration.mode, IdaMode::Headless);
    let local_v6 = write_json(
        dir.path(),
        "v6.json",
        &json!({ "url": "http://[::1]:9/mcp" }),
    );
    assert!(read_registration(local_v6.to_str().unwrap()).is_ok());
    let malformed = dir.path().join("malformed.json");
    std::fs::write(&malformed, "malformed").unwrap();
    assert!(read_registration(malformed.to_str().unwrap()).is_err());
    assert!(read_registration(dir.path().join("absent").to_str().unwrap()).is_err());
    let oversized = dir.path().join("big.json");
    std::fs::write(&oversized, " ".repeat(70_000)).unwrap();
    assert_eq!(
        read_registration(oversized.to_str().unwrap()).unwrap_err(),
        "REA_IDA_MCP_CONFIG exceeds the 64 KiB registration size."
    );
}

#[test]
fn registration_digests_commit_to_the_parsed_object_with_defaults() {
    let a = parse_registration(&json!({ "command": "x" })).unwrap();
    let b = parse_registration(
        &json!({ "command": "x", "args": [], "env": {}, "mode": "attached", "timeoutMs": 300000 }),
    )
    .unwrap();
    assert_eq!(a.digest(), b.digest());
    let c = parse_registration(&json!({ "command": "x", "type": "stdio" })).unwrap();
    assert_ne!(
        a.digest(),
        c.digest(),
        "an explicit `type` is part of the parsed registration"
    );
}

#[test]
fn tool_results_decode_wrappers_dictionaries_text_arrays_and_errors() {
    assert_eq!(
        decode_tool_result(
            &json!({ "content": [], "structuredContent": { "result": [{ "address": "0x1" }] } })
        )
        .unwrap(),
        json!([{ "address": "0x1" }])
    );
    assert_eq!(
        decode_tool_result(
            &json!({ "content": [], "structuredContent": { "address": "0x1", "name": "f" } })
        )
        .unwrap(),
        json!({ "address": "0x1", "name": "f" })
    );
    assert_eq!(
        decode_tool_result(&json!({ "content": [{ "type": "text", "text": "int f() {}" }] }))
            .unwrap(),
        json!("int f() {}")
    );
    assert_eq!(
        decode_tool_result(&json!({ "content": [{ "type": "text", "text": "{\"data\":[]}" }] }))
            .unwrap(),
        json!({ "data": [] })
    );
    match decode_tool_result(
        &json!({ "content": [{ "type": "text", "text": "No function at 0x1" }], "isError": true }),
    ) {
        Err(DecodeFailure::Protocol(message)) => assert!(message.contains("No function at 0x1")),
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(
        decode_tool_result(&json!({ "content": "invalid" })),
        Err(DecodeFailure::Malformed(m)) if m == "content: Invalid input: expected array, received string"
    ));
    assert!(matches!(
        decode_tool_result(&json!({ "content": [] })),
        Err(DecodeFailure::Protocol(_))
    ));
    match decode_tool_result(&json!({
        "content": [{ "type": "text", "text": "partial" }],
        "_meta": { "ida_mcp": { "output_truncated": true, "download_hint": "Fetch it with the download tool." } },
    })) {
        Err(DecodeFailure::Protocol(message)) => assert!(
            message.ends_with("Fetch it with the download tool."),
            "{message}"
        ),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn zod_issue_wording_matches_the_reference_implementation() {
    // Expected strings were produced by zod 4.4.3, the version REA ships.
    use super::protocol as p;
    let render = |parse: &dyn Fn(&mut p::Issues)| {
        let mut issues = Vec::new();
        parse(&mut issues);
        p::render(&issues)
    };
    assert_eq!(
        render(&|i| {
            p::function(
                Some(&json!({ "address": "0x1", "name": "", "size": "0x1" })),
                &[],
                i,
            );
        }),
        "name: Too small: expected string to have >=1 characters"
    );
    assert_eq!(
        render(&|i| {
            p::function(Some(&json!({ "name": "x" })), &[], i);
        }),
        "$: Invalid input"
    );
    assert_eq!(
        render(&|i| {
            p::function(Some(&json!(5)), &[], i);
        }),
        "$: Invalid input"
    );
    assert_eq!(
        render(&|i| {
            p::address(Some(&json!("zz")), &[], i);
        }),
        "$: Invalid string: must match pattern /^(?:0x)?[0-9a-f]+$/iu"
    );
    assert_eq!(
        render(&|i| {
            p::page(Some(&json!({ "data": [], "next_offset": -1 })), &[], i);
        }),
        "next_offset: Too small: expected number to be >=0"
    );
    assert_eq!(
        render(&|i| {
            p::page(Some(&json!({ "data": [] })), &[], i);
        }),
        "next_offset: Invalid input: expected number, received undefined"
    );
    assert_eq!(
        render(&|i| {
            p::page(Some(&json!({ "data": [], "next_offset": 1.5 })), &[], i);
        }),
        "next_offset: Invalid input: expected int, received number"
    );
    assert_eq!(
        render(&|i| {
            p::cursor(Some(&json!({ "done": false })), &[], i);
        }),
        "$: Invalid input"
    );
    assert_eq!(
        render(&|i| {
            p::modern_page(Some(&json!([])), &[], i);
        }),
        "$: Too small: expected array to have >=1 items"
    );
    assert_eq!(
        render(&|i| {
            p::modern_page(
                Some(&json!([{ "data": [], "next_offset": null }, {}])),
                &[],
                i,
            );
        }),
        "$: Too big: expected array to have <=1 items"
    );
    assert_eq!(
        render(&|i| {
            p::legacy_string(
                Some(&json!({ "address": "0x1", "string": 5, "length": 1 })),
                &[],
                i,
            );
        }),
        "string: Invalid input: expected string, received number"
    );
    assert_eq!(
        render(&|i| {
            p::modern_callees(
                Some(&json!([{ "callees": [{ "addr": "0x1", "name": "a", "type": "weird" }] }])),
                &[],
                i,
            );
        }),
        "0.callees.0.type: Invalid option: expected one of \"internal\"|\"external\""
    );
    assert_eq!(
        render(&|i| {
            p::disassembly(
                Some(
                    &json!({ "name": "a", "start_ea": "0x1", "lines": [], "arguments": [{ "name": "a" }] }),
                ),
                &[],
                i,
            );
        }),
        "arguments.0.type: Invalid input: expected string, received undefined"
    );
}

#[test]
fn transport_failures_are_redacted_without_touching_caller_evidence() {
    let registration = parse_registration(&json!({
        "url": "http://127.0.0.1:12345/mcp",
        "headers": { "Authorization": "Bearer fixture-secret" },
    }))
    .unwrap();
    let message = super::connection::redact_transport_failure(
        "Invalid Authorization value Bearer fixture-secret at /caller/input",
        &registration,
    );
    assert!(!message.contains("fixture-secret"));
    assert!(message.contains("/caller/input"));
    // Decoded results are caller evidence and are never redacted.
    assert_eq!(
        decode_tool_result(&json!({ "content": [{ "type": "text", "text": "Caller-selected fixture-secret evidence" }] })).unwrap(),
        json!("Caller-selected fixture-secret evidence")
    );
    // Only authentication-bearing headers are credentials.
    let plain = parse_registration(
        &json!({ "url": "http://127.0.0.1:1/mcp", "headers": { "X-Trace": "abc" } }),
    )
    .unwrap();
    assert_eq!(
        super::connection::redact_transport_failure("abc stays", &plain),
        "abc stays"
    );
}

#[test]
fn scalar_wrappers_do_not_swallow_structured_dictionaries() {
    assert_eq!(
        decode_tool_result(&json!({ "content": [], "structuredContent": { "result": "code" } }))
            .unwrap(),
        json!("code")
    );
    assert_eq!(
        decode_tool_result(
            &json!({ "content": [], "structuredContent": { "path": "input", "result": "field" } })
        )
        .unwrap(),
        json!({ "path": "input", "result": "field" })
    );
    assert_eq!(
        decode_tool_result(
            &json!({ "content": [{ "type": "text", "text": "[{\"address\":\"0x1000\"}]" }] })
        )
        .unwrap(),
        json!([{ "address": "0x1000" }])
    );
    // A truncated preview that still satisfies the item schema is not an observation.
    match decode_tool_result(&json!({
        "isError": false,
        "structuredContent": { "result": [{ "addr": "0x1000", "name": "main", "size": "0x20" }] },
        "content": [{ "type": "text", "text": "preview" }],
        "_meta": { "ida_mcp": { "output_truncated": true, "total_chars": 70000, "download_hint": "Download the full upstream output" } },
    })) {
        Err(DecodeFailure::Protocol(message)) => {
            assert!(message.contains("Download the full upstream output"))
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn the_doctor_check_validates_without_launching_or_copying_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_json(
        dir.path(),
        "registration.json",
        &json!({ "url": "http://127.0.0.1:12345/mcp", "headers": { "Authorization": "Bearer fixture-secret" }, "mode": "headless" }),
    );
    let path = path.to_string_lossy().to_string();
    let valid = super::config::inspect_registration(Some(&path));
    assert_eq!(valid["configured"], true);
    assert_eq!(valid["available"], true);
    assert_eq!(valid["providerVersion"], Value::Null);
    assert!(valid["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("no IDA process was launched"));
    assert_eq!(
        valid["registrationEnvironment"],
        json!({ "REA_IDA_MCP_CONFIG": path })
    );
    assert!(!valid.to_string().contains("fixture-secret"));
    let invalid_path = write_json(
        dir.path(),
        "bad.json",
        &json!({ "url": "https://example.com/mcp" }),
    );
    let invalid = super::config::inspect_registration(invalid_path.to_str());
    assert_eq!(invalid["available"], false);
    assert_eq!(invalid["registrationEnvironment"], json!({}));
    assert_eq!(invalid["checks"][0]["code"], "invalid_configuration");
    let missing = super::config::inspect_registration(None);
    assert_eq!(missing["configured"], false);
    assert_eq!(missing["available"], false);
    assert_eq!(missing["checks"][0]["code"], "not_configured");
}

#[tokio::test(flavor = "multi_thread")]
async fn non_ascii_procedure_names_are_names_and_never_slice_inside_a_character() {
    for name in ["日本語の関数", "é", "x", "0"] {
        let f = fixture(IdaMode::Attached);
        let found = run(&f.client, "procedure_address", json!({ "procedure": name })).await;
        assert!(found.is_ok(), "{name}: {found:?}");
        assert_eq!(
            f.producer.args_of("get_function_by_name")[0]["name"],
            json!(name)
        );
        assert_eq!(f.producer.count("get_function_by_address"), 0);
        assert!(f.client.close(false).await.is_ok());
    }
}

// ---------------------------------------------------------------- workspace ownership
// (port of `IdaWorkspaceOwnership.test.ts`)

fn headless_client_for(
    root: &Path,
    workspace_root: &Path,
    target: &BinaryTarget,
) -> (IdaSessionClient, Arc<RecordingIdaMcp>) {
    let producer = RecordingIdaMcp::new(target, IdaMode::Headless);
    let client = IdaSessionClient::new(
        registration("headless", Some(workspace_root)),
        target.clone(),
        producer.clone(),
        None,
    );
    let _ = root;
    (client, producer)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_private_input_is_opened_through_a_canonical_path_when_the_root_is_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    let target = target_in(root.path());
    let links = tempfile::tempdir().unwrap();
    let linked = links.path().join("root");
    std::os::unix::fs::symlink(root.path(), &linked).unwrap();
    let (client, producer) = headless_client_for(root.path(), &linked, &target);
    assert!(run(&client, "health", json!({})).await.is_ok());
    let canonical = std::fs::canonicalize(root.path()).unwrap();
    let opened = producer.args_of("idb_open")[0]["input_path"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        opened.starts_with(&format!("{}/", canonical.display())),
        "{opened}"
    );
    assert!(client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn cleanup_ownership_is_retained_when_copying_the_admitted_input_fails() {
    let f = fixture(IdaMode::Headless);
    std::fs::remove_file(&f.target.path).unwrap();
    let failed = run(&f.client, "health", json!({})).await.unwrap_err();
    assert!(
        matches!(failed, AnalysisError::ProviderAdapter { .. }),
        "{failed:?}"
    );
    assert_eq!(
        entries(f.root.path()).len(),
        1,
        "the private workspace exists and is owned"
    );
    assert_eq!(f.producer.count("idb_open"), 0);
    assert!(f.client.close(false).await.is_ok());
    assert!(entries(f.root.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_input_identity_failure_is_preserved_and_workspace_removal_is_retried() {
    use std::os::unix::fs::PermissionsExt;
    // Permission bits do not restrain root.
    if std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(0)
        == 0
    {
        if std::env::var("TRACEWISE_REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false) {
            panic!("TRACEWISE_REQUIRE_ORACLE=1 but this test cannot run as root (permission bits do not restrain root)");
        }
        eprintln!("SKIP: running as root; permission bits do not restrain root");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut target = target_in(root.path());
    target.sha256 = "a".repeat(64);
    let (client, producer) = headless_client_for(root.path(), root.path(), &target);
    let failed = run(&client, "health", json!({})).await.unwrap_err();
    assert!(
        failed.message().contains("target changed"),
        "{}",
        failed.message()
    );
    let workspace = entries(root.path())
        .into_iter()
        .find(|n| n.starts_with("rea-ida-"))
        .expect("workspace retained");
    assert_eq!(producer.count("idb_open"), 0);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let closed = client.close(false).await;
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    match closed.unwrap_err() {
        AnalysisError::ProviderAdapter {
            cleanup_incomplete,
            cleanup_resources,
            ..
        } => {
            assert!(cleanup_incomplete);
            assert_eq!(cleanup_resources.len(), 1);
            assert!(
                cleanup_resources[0].contains(&workspace),
                "{cleanup_resources:?}"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(client.close(false).await.is_ok());
    assert_eq!(entries(root.path()), vec!["target.elf".to_string()]);
}
