//! Shared driver for the jsgraph MCP parity tests: a long-lived original-REA MCP stdio session,
//! the port's in-process dispatcher, and the normalization/diff used to compare whole results.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

pub fn rea_src() -> PathBuf {
    PathBuf::from(std::env::var("REA_SRC").unwrap_or_else(|_| "/workspace/rea-map/src".to_string()))
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

pub fn oracle_available() -> bool {
    if rea_src().join("scripts/rea.mjs").is_file() {
        return true;
    }
    assert!(
        std::env::var("TRACEWISE_REQUIRE_ORACLE").is_err(),
        "REA oracle missing at {}",
        rea_src().display()
    );
    eprintln!("skipping: REA oracle not found");
    false
}

/// One long-lived REA MCP stdio session.
pub struct Rea {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Rea {
    pub fn start() -> Self {
        let mut child = Command::new("node")
            .arg(rea_src().join("scripts/rea.mjs"))
            .arg("mcp")
            .current_dir(rea_src())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if std::env::var("TRACEWISE_REA_STDERR").is_ok() { Stdio::inherit() } else { Stdio::null() })
            .spawn()
            .expect("spawn REA");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut rea = Rea { child, stdin, stdout, next_id: 0 };
        rea.request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"jsgraph-parity","version":"0"}}),
        );
        rea.notify("notifications/initialized");
        rea
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").expect("write REA");
        self.stdin.flush().expect("flush REA");
    }

    fn notify(&mut self, method: &str) {
        self.send(json!({"jsonrpc":"2.0","method":method}));
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read REA");
            assert!(read > 0, "REA closed stdout");
            let message: Value = match serde_json::from_str(line.trim()) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if message.get("id") == Some(&json!(id)) {
                return message.get("result").cloned().unwrap_or(message);
            }
        }
    }

    pub fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":tool,"arguments":arguments}))
    }
}

impl Drop for Rea {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub async fn ours(session: &BinarySession, tool: &str, arguments: Value) -> Value {
    let result = call_tool_local(
        session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: arguments.as_object().cloned() },
    )
    .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => return json!({"isError": true, "text": error.message}),
    };
    // Same shape as the oracle result: structuredContent plus the text content.
    let mut out = serde_json::Map::new();
    if let Some(structured) = result.structured_content {
        out.insert("structuredContent".into(), structured);
    }
    out.insert("isError".into(), json!(result.is_error.unwrap_or(false)));
    if let Some(first) = result.content.first() {
        if let Ok(value) = serde_json::to_value(first) {
            if let Some(text) = value.get("text") {
                out.insert("text".into(), text.clone());
            }
        }
    }
    Value::Object(out)
}

pub fn rea_normalized(mut result: Value) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(structured) = result.get_mut("structuredContent") {
        out.insert("structuredContent".into(), structured.take());
    }
    out.insert("isError".into(), json!(result.get("isError").and_then(Value::as_bool).unwrap_or(false)));
    if let Some(text) = result["content"].get(0).and_then(|c| c.get("text")) {
        out.insert("text".into(), text.clone());
    }
    Value::Object(out)
}

/// Replace the host-path fields and the ids derived from them by placeholders, consistently on
/// both sides (an id maps to `#<n>` in order of first appearance).
pub fn canon(value: &Value, ids: &mut Vec<String>) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, inner) in map {
                let replaced = match key.as_str() {
                    "local_path" | "input_path" if inner.is_string() => json!("<path>"),
                    "evidence_id" | "application_evidence_id" | "left_evidence_id" | "right_evidence_id"
                        if inner.is_string() =>
                    {
                        json!(placeholder(ids, inner.as_str().unwrap()))
                    }
                    _ => canon(inner, ids),
                };
                out.insert(key.clone(), replaced);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(|item| canon(item, ids)).collect()),
        Value::String(text) if text.starts_with("ev_") => json!(placeholder(ids, text)),
        // The text content item of a tool result is the JSON body (or a plain error message).
        Value::String(text) if text.starts_with('{') => match serde_json::from_str::<Value>(text) {
            Ok(parsed) => canon(&parsed, ids),
            Err(_) => json!(text),
        },
        other => other.clone(),
    }
}

pub fn placeholder(ids: &mut Vec<String>, id: &str) -> String {
    let index = match ids.iter().position(|known| known == id) {
        Some(index) => index,
        None => {
            ids.push(id.to_string());
            ids.len() - 1
        }
    };
    format!("<id#{index}>")
}

pub fn diff(path: &str, want: &Value, got: &Value, out: &mut Vec<String>) {
    if out.len() >= 8 {
        return;
    }
    match (want, got) {
        (Value::Object(a), Value::Object(b)) => {
            for key in a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))) {
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => diff(&format!("{path}.{key}"), x, y, out),
                    (Some(_), None) => out.push(format!("{path}.{key}: missing in port")),
                    (None, Some(_)) => out.push(format!("{path}.{key}: extra in port")),
                    _ => {}
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                out.push(format!("{path}: length {} vs {}", a.len(), b.len()));
            }
            for (index, (x, y)) in a.iter().zip(b).enumerate() {
                diff(&format!("{path}[{index}]"), x, y, out);
            }
        }
        _ => {
            if want != got {
                let short = |v: &Value| v.to_string().chars().take(140).collect::<String>();
                out.push(format!("{path}: rea {} vs port {}", short(want), short(got)));
            }
        }
    }
}

pub struct Counter {
    pub compared: usize,
    pub failures: Vec<String>,
}

impl Counter {
    pub fn check(&mut self, label: &str, rea: Value, port: Value) {
        let mut a = Vec::new();
        let mut b = Vec::new();
        let rea = rea_normalized(rea);
        // Byte-for-byte text, key order included: the response budget accounting depends on it.
        let mut diffs = Vec::new();
        if let (Some(want_text), Some(got_text)) = (rea["text"].as_str(), port["text"].as_str()) {
            if want_text != got_text && want_text.starts_with('{') {
                let at = want_text.bytes().zip(got_text.bytes()).position(|(x, y)| x != y).unwrap_or(0);
                let around = |text: &str| {
                    let start = at.saturating_sub(60);
                    text.get(start..(at + 60).min(text.len())).unwrap_or("").to_string()
                };
                diffs.push(format!("text differs at byte {at} (rea {} bytes, port {}): rea ..{}.. port ..{}..", want_text.len(), got_text.len(), around(want_text), around(got_text)));
            }
        }
        let want = canon(&rea, &mut a);
        let got = canon(&port, &mut b);
        self.compared += 1;
        diff("$", &want, &got, &mut diffs);
        if !diffs.is_empty() {
            self.failures.push(format!("{label}: {}", diffs.join(" | ")));
        }
    }
}

