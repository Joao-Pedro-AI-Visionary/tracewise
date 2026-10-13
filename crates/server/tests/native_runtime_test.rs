//! Native runtime tools against the ORIGINAL REA on Linux:
//! `observe_native_ui`, `capture_native_ui_scenario`, `observe_native_calls`
//! (macOS-only providers) and the admission rules of `trace_native_ui_action`.
//!
//! One oracle session and one Rust session replay the same ordered call list:
//! first with no target open, then after `open_binary` on a minimal arm64
//! Mach-O header (`/tmp/tw-native-parity/mini.macho`), the way an analyst would
//! reach these tools. Every tool answer is compared in full (`isError` plus the
//! complete text body), with no ignored field:
//! - rejected arguments: REA's MCP-layer text (`Input validation error: ...`),
//!   reproduced issue by issue (order, paths, zod messages, defaults);
//! - no open target: `target_unavailable` (NoBinaryOpenError);
//! - `trace_native_ui_action`: admission, the target check and, with the Mach-O
//!   open, REA's `provider_unavailable` for `list_names` (no engine is
//!   configured on this host). The answer now comes from the engines track
//!   itself, reached through the sibling-tool dispatch; there is no stand-in for
//!   an unported sibling any more. Its workflow proper is proven against REA's
//!   compiled code in `crates/device/tests/ui_trace_parity.rs`;
//! - open Mach-O target on Linux: `capability_unavailable` /
//!   `unsupported_host` with the session's composite provider identity
//!   `composite:native-macos+rea-artifact-graph+rea-dotnet-static`.
//!
//! Not verifiable here (no macOS host): the real observation paths. Accessibility
//! trees, screenshots, scenario steps and LLDB call traces are not ported and
//! remain [Não verificável] in this environment; on macOS the tools answer a
//! capability error that says so.

use std::fs;
use std::path::Path;
use std::process::Command;

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

/// Per-checkout scratch (`target/tmp`): concurrent runs never share files.
const WORK: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/native-parity");

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn oracle_available() -> bool {
    tracewise_device::testing::require_or_skip("native_runtime_test", &tracewise_device::testing::rea_oracle_missing())
}

fn mini_macho() -> String {
    fs::create_dir_all(WORK).unwrap();
    let path = format!("{WORK}/mini.macho");
    // arm64 MH_MAGIC_64 header, no load commands.
    let mut bytes = Vec::new();
    for word in [0xfeed_facf_u32, 0x0100_000c, 0, 2, 0, 0, 0, 0] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&[0u8; 64]);
    fs::write(&path, bytes).unwrap();
    path
}

/// The ordered plan and the index of the first call issued after `open_binary`.
fn calls() -> (Vec<(&'static str, Value)>, usize) {
    let valid_ui = json!({"pid": 1, "window_id": 2});
    let valid_scenario = json!({"pid": 1, "window_id": 2, "steps": [{"kind": "wait", "milliseconds": 1}]});
    let valid_calls = json!({"breakpoints": [{"kind": "function", "name": "open"}]});
    let invalid: Vec<(&'static str, Value)> = vec![
        ("observe_native_ui", json!({})),
        ("observe_native_ui", json!({"pid": 0, "window_id": -1, "screenshot": "y", "max_nodes": 0})),
        ("observe_native_ui", json!({"pid": 1.5, "window_id": 9007199254740992u64, "max_nodes": 9007199254740992u64})),
        ("observe_native_ui", json!({"pid": 1, "window_id": 2, "x": 1})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": []})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "zoom"}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [1, "a", null, []]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "click"}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "click", "path": [-1, 1.5, "x"], "extra": 1}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "scroll", "path": [], "direction": "up"}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "key-entry", "path": [0]}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "wait", "milliseconds": 180001}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": [{"kind": "click", "path": (0..33).collect::<Vec<_>>()}]})),
        ("capture_native_ui_scenario", json!({"pid": 1, "window_id": 2, "steps": "s"})),
        ("observe_native_calls", json!({})),
        ("observe_native_calls", json!({"breakpoints": []})),
        ("observe_native_calls", json!({"breakpoints": [{}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "zzz"}]})),
        ("observe_native_calls", json!({"breakpoints": [1, null]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function"}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function", "name": "", "module": ""}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function", "name": "a\u{0}b", "module": "a\u{0}"}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "objc-method", "selector": "a b"}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "objc-method", "selector": "[x]", "class_name": "", "method_type": "z"}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "objc-method", "selector": "a\u{0}", "class_name": "a\u{0}"}]})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function", "name": "open", "extra": 1}]})),
        (
            "observe_native_calls",
            json!({"breakpoints": [{"kind": "function", "name": "open"}], "arguments": [1, "a\u{0}"],
                "environment": {"": "x", "A=B": "1", "C": "v\u{0}", "D": 1}, "working_directory": "",
                "duration_ms": 99, "max_events": 0, "argument_registers": 9, "backtrace_frames": 65}),
        ),
        (
            "observe_native_calls",
            json!({"breakpoints": [{"kind": "function", "name": "open"}], "arguments": "x", "environment": [],
                "duration_ms": 600001, "max_events": 100001, "argument_registers": -1, "backtrace_frames": -1,
                "working_directory": "a\u{0}"}),
        ),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function", "name": "open"}], "environment": {"A": "b", "A\u{0}": "c"}})),
        ("observe_native_calls", json!({"breakpoints": [{"kind": "function", "name": "open"}], "environment": "x", "arguments": null})),
        ("trace_native_ui_action", json!({})),
        ("trace_native_ui_action", json!({"action": ""})),
        ("trace_native_ui_action", json!({"action": "a", "max_depth": 33, "max_nodes": 0, "max_edges": 5001})),
        ("trace_native_ui_action", json!({"action": 5, "max_depth": -1, "max_nodes": 2001, "max_edges": 0, "z": 1})),
    ];
    let mut all: Vec<(&'static str, Value)> = Vec::new();
    // Phase 1: no target open.
    all.push(("observe_native_ui", valid_ui.clone()));
    all.push(("capture_native_ui_scenario", valid_scenario.clone()));
    all.push(("observe_native_calls", valid_calls.clone()));
    all.push(("trace_native_ui_action", json!({"action": "buildTapped:"})));
    all.extend(invalid.iter().cloned());
    let split = all.len();
    // Phase 2 (after open_binary): valid calls hit the host gate.
    all.push(("observe_native_ui", valid_ui));
    all.push(("observe_native_ui", json!({"pid": 4242, "window_id": 7, "screenshot": false, "accessibility": false, "max_nodes": 3})));
    all.push(("capture_native_ui_scenario", valid_scenario));
    all.push((
        "capture_native_ui_scenario",
        json!({"pid": 1, "window_id": 2, "steps": [
            {"kind": "click", "path": [0, 1]},
            {"kind": "scroll", "path": [], "direction": "decrement"},
            {"kind": "key-entry", "path": [2], "text": "hello"}
        ]}),
    ));
    all.push(("observe_native_calls", valid_calls));
    all.push((
        "observe_native_calls",
        json!({"breakpoints": [
                {"kind": "objc-method", "class_name": "NSURLSession", "selector": "dataTaskWithRequest:completionHandler:"},
                {"kind": "function", "name": "open", "module": "libsystem_kernel.dylib"}],
            "arguments": ["--help"], "environment": {"A": "b"}, "working_directory": "/tmp",
            "duration_ms": 5000, "backtrace_frames": 4}),
    ));
    // With a target open the workflow reaches the sibling tools: REA (no engine
    // configured on this host) fails it with `provider_unavailable` for `list_names`.
    all.push(("trace_native_ui_action", json!({"action": "buildTapped:"})));
    all.push(("trace_native_ui_action", json!({"action": "0x1000", "max_depth": 2})));
    // Rejected arguments are reported before the target is consulted.
    all.extend(invalid);
    (all, split)
}

#[tokio::test]
async fn native_runtime_tools_match_rea_on_linux() {
    if !oracle_available() {
        return;
    }
    let macho = mini_macho();
    let (plan, split) = calls();
    // Oracle: one session, open_binary between the two phases.
    let mut oracle_calls: Vec<Value> = Vec::new();
    for (index, (tool, args)) in plan.iter().enumerate() {
        if index == split {
            oracle_calls.push(json!({"tool": "open_binary", "args": {"path": macho}}));
        }
        oracle_calls.push(json!({"tool": tool, "args": args}));
    }
    let calls_file = format!("{WORK}/calls.json");
    let out_file = format!("{WORK}/answers.json");
    fs::write(&calls_file, serde_json::to_string(&oracle_calls).unwrap()).unwrap();
    let status = Command::new("python3")
        .arg(repo_root().join("fixtures/adb/oracle_batch.py"))
        .arg(&calls_file)
        .arg(&out_file)
        .status()
        .expect("python3");
    assert!(status.success(), "oracle batch failed");
    let oracle: Vec<Value> = serde_json::from_str(&fs::read_to_string(&out_file).unwrap()).unwrap();
    assert_eq!(oracle.len(), oracle_calls.len());

    let session = BinarySession::new();
    let mut oracle_index = 0;
    let mut failures = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, (tool, args)) in plan.iter().enumerate() {
        if index == split {
            oracle_index += 1; // the oracle's open_binary answer
            let opened = call_tool_local(
                &session,
                CallToolRequestParam {
                    name: "open_binary".to_string().into(),
                    arguments: Some(json!({"path": macho}).as_object().unwrap().clone()),
                },
            )
            .await
            .expect("open_binary");
            assert_ne!(opened.is_error, Some(true));
        }
        let expected = &oracle[oracle_index];
        oracle_index += 1;
        let actual = call_tool_local(
            &session,
            CallToolRequestParam {
                name: tool.to_string().into(),
                arguments: Some(args.as_object().unwrap().clone()),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{tool}: protocol error {error}"));
        let actual = serde_json::to_value(&actual).unwrap();
        let expected_text = expected["content"][0]["text"].as_str().unwrap_or_default();
        let actual_text = actual["content"][0]["text"].as_str().unwrap_or_default();
        let same_flag = (expected["isError"] == true) == (actual["isError"] == true);
        let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.to_string()));
        if !same_flag || parse(expected_text) != parse(actual_text) {
            failures.push(format!("[{index}] {tool} {args}\n oracle: {expected_text}\n rust:   {actual_text}"));
        }
        assert_eq!(expected["isError"], true, "[{index}] {tool}: every call in this plan is an error on Linux");
        seen.insert(parse(expected_text)["error"]["code"].as_str().unwrap_or("input-validation").to_string());
    }
    assert!(failures.is_empty(), "{} of {} calls differ:\n{}", failures.len(), plan.len(), failures.join("\n"));
    // The plan must exercise all three kinds of answer.
    for code in ["input-validation", "target_unavailable", "capability_unavailable", "provider_unavailable"] {
        assert!(seen.contains(code), "plan never produced {code}: {seen:?}");
    }
    eprintln!("native runtime: {} calls identical to the oracle ({seen:?})", plan.len());
}
