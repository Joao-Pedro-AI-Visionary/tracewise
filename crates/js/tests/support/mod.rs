//! Shared helpers for the jsgraph layer-parity tests (`mod support;` from each test file).
//!
//! Oracle = the compiled REA checkout (`REA_SRC`, default `/workspace/rea-map/src`) driven by
//! the node scripts in `fixtures/jsgraph/oracle/`. Layer tests compare the Rust output with the
//! REA output **exactly** (same keys, same order inside arrays, same values).
//!
//! Corpus selection (all layers use [`corpus`]):
//! - the test's own inline snippets,
//! - every JS/TS file under the repo `fixtures/` and the REA `tests/fixtures`,
//! - the REA source tree itself (real-world TypeScript), every `TRACEWISE_JSGRAPH_STRIDE`-th file
//!   (default 9; `TRACEWISE_JSGRAPH_STRIDE=1` for all of them),
//! - extra directories from `TRACEWISE_JSGRAPH_CORPUS=dir1,dir2` (every file).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

pub fn rea_src() -> PathBuf {
    PathBuf::from(std::env::var("REA_SRC").unwrap_or_else(|_| "/workspace/rea-map/src".into()))
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn oracle_script(name: &str) -> PathBuf {
    repo_root().join("fixtures/jsgraph/oracle").join(name)
}

/// True when the REA checkout is usable. With `TRACEWISE_REQUIRE_ORACLE=1` a missing oracle
/// fails the test instead of skipping it.
pub fn oracle_available() -> bool {
    let src = rea_src();
    if src.join("dist/domain/javascript/javascriptSourceParser.js").exists() {
        return true;
    }
    if std::env::var("TRACEWISE_REQUIRE_ORACLE").as_deref() == Ok("1") {
        panic!("REA checkout not found at {} (set REA_SRC)", src.display());
    }
    eprintln!("skipping: REA checkout not found at {}", src.display());
    false
}

pub fn is_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts")
    )
}

pub fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    collect_filtered(dir, out, true);
}

/// Like [`collect`] but descends into `node_modules` (application fixtures vendor packages).
pub fn collect_with_node_modules(dir: &Path, out: &mut Vec<PathBuf>) {
    collect_filtered(dir, out, false);
}

fn collect_filtered(dir: &Path, out: &mut Vec<PathBuf>, skip_node_modules: bool) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if (skip_node_modules && name == "node_modules") || name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_filtered(&path, out, skip_node_modules);
        } else if is_source(&path) {
            if let Ok(meta) = path.metadata() {
                if meta.len() < 2_000_000 {
                    out.push(path);
                }
            }
        }
    }
}

pub struct Corpus {
    pub files: Vec<PathBuf>,
    /// Keeps the temp dir holding the inline snippets alive.
    pub _dir: tempfile::TempDir,
}

/// Build the corpus; `snippets` are `(file name, source)` pairs (the extension picks the dialect).
pub fn corpus(snippets: &[(&str, &str)]) -> Corpus {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut files = Vec::new();
    for (name, text) in snippets {
        let path = dir.path().join(name);
        std::fs::write(&path, text).expect("write snippet");
        files.push(path);
    }
    collect(&repo_root().join("fixtures"), &mut files);
    collect(&rea_src().join("tests/fixtures"), &mut files);
    let stride: usize = std::env::var("TRACEWISE_JSGRAPH_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9)
        .max(1);
    let mut rea_sources = Vec::new();
    collect(&rea_src().join("src"), &mut rea_sources);
    files.extend(rea_sources.into_iter().step_by(stride));
    if let Ok(extra) = std::env::var("TRACEWISE_JSGRAPH_CORPUS") {
        for dir in extra.split(',').filter(|d| !d.is_empty()) {
            collect(Path::new(dir), &mut files);
        }
    }
    // Paths that legitimately differ between the two parsers (broken tails): see the AST test.
    files.retain(|p| !p.to_string_lossy().contains("Heavy.app/Scripts"));
    Corpus { files, _dir: dir }
}

/// Files per oracle process. REA's `layers.mjs` prints one multi-megabyte JSON line per bundle; when
/// a single node process answers thousands of files over a pipe its stdout can silently stop after
/// a few lines (exit status 0), so a comparison fed by one process could cover only a prefix of the
/// corpus. Chunking plus an exact line count per chunk keeps every layer test honest.
pub const ORACLE_CHUNK: usize = 100;

/// Run a node oracle script over `files` (in chunks of [`ORACLE_CHUNK`]) and hand each JSON line to
/// `each`. Fails the test unless every chunk answers exactly one readable line per file, in order,
/// so no layer test can pass on a truncated or partly discarded oracle answer. Returns the number
/// of lines handed to `each` (always `files.len()`).
pub fn stream_oracle(script: &str, files: &[PathBuf], mut each: impl FnMut(Value)) -> usize {
    let mut answered = 0usize;
    for chunk in files.chunks(ORACLE_CHUNK) {
        let dir = tempfile::tempdir().expect("tempdir");
        let list = dir.path().join("files.txt");
        std::fs::write(
            &list,
            chunk.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("
"),
        )
        .expect("write list");
        let mut child = Command::new("node")
            .arg(oracle_script(script))
            .arg(&list)
            .env("REA_SRC", rea_src())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn node");
        let stdout = child.stdout.take().expect("stdout");
        let mut lines = 0usize;
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("oracle line");
            let value = serde_json::from_str::<Value>(&line).unwrap_or_else(|error| {
                panic!(
                    "{script}: unreadable oracle line {} of the chunk starting at {} ({error}): {}",
                    lines + 1,
                    chunk[0].display(),
                    &line[..line.char_indices().nth(100).map_or(line.len(), |(i, _)| i)]
                )
            });
            if let (Some(path), Some(expected)) = (value["path"].as_str(), chunk.get(lines)) {
                assert_eq!(
                    path,
                    expected.display().to_string(),
                    "{script}: the oracle answered out of order at line {} of the chunk starting at {}",
                    lines + 1,
                    chunk[0].display()
                );
            }
            lines += 1;
            each(value);
        }
        let status = child.wait().expect("wait node");
        assert!(status.success(), "oracle script {script} failed");
        assert_eq!(
            lines,
            chunk.len(),
            "{script}: the oracle dropped output for the chunk starting at {}",
            chunk[0].display()
        );
        answered += lines;
    }
    assert_eq!(answered, files.len(), "{script}: oracle answers do not cover the corpus");
    eprintln!("oracle {script}: {answered} readable lines for {} corpus files", files.len());
    answered
}

/// Exact structural diff (keys, array order, values). Paths use `$.a[0].b`.
pub fn diff(expected: &Value, actual: &Value, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    walk("$", expected, actual, &mut out, limit);
    out
}

fn brief(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 110 {
        format!("{}...", &text[..text.char_indices().nth(110).map_or(text.len(), |(i, _)| i)])
    } else {
        text
    }
}

fn walk(path: &str, expected: &Value, actual: &Value, out: &mut Vec<String>, limit: usize) {
    if out.len() >= limit {
        return;
    }
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (key, value) in e {
                match a.get(key) {
                    Some(other) => walk(&format!("{path}.{key}"), value, other, out, limit),
                    None => out.push(format!("{path}.{key}: missing (expected {})", brief(value))),
                }
            }
            for (key, value) in a {
                if !e.contains_key(key) {
                    out.push(format!("{path}.{key}: unexpected (actual {})", brief(value)));
                }
            }
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                out.push(format!("{path}: length {} expected, {} actual", e.len(), a.len()));
            }
            for (index, (left, right)) in e.iter().zip(a).enumerate() {
                walk(&format!("{path}[{index}]"), left, right, out, limit);
            }
        }
        (left, right) => {
            if left != right {
                out.push(format!("{path}: expected {} actual {}", brief(left), brief(right)));
            }
        }
    }
}

/// Collects differences across many files; prints a per-shape ranking and panics on any.
#[derive(Default)]
pub struct Report {
    shapes: BTreeMap<String, usize>,
    files_with_diffs: usize,
    pub checked: usize,
    shown: usize,
}

impl Report {
    pub fn record(&mut self, file: &str, diffs: &[String]) {
        self.checked += 1;
        if diffs.is_empty() {
            return;
        }
        self.files_with_diffs += 1;
        for entry in diffs {
            // Shape = diff text with array indexes and numbers collapsed.
            let mut shape = String::new();
            let mut in_index = false;
            for ch in entry.chars().take(140) {
                match ch {
                    '[' => {
                        in_index = true;
                        shape.push('[');
                    }
                    ']' => {
                        in_index = false;
                        shape.push(']');
                    }
                    c if in_index && c.is_ascii_digit() => {}
                    c => shape.push(c),
                }
            }
            *self.shapes.entry(shape).or_default() += 1;
        }
        if self.shown < 10 {
            self.shown += 1;
            eprintln!("--- {file}: {} differences, first:", diffs.len());
            for entry in diffs.iter().take(5) {
                eprintln!("    {entry}");
            }
        }
    }

    pub fn finish(self, what: &str) {
        eprintln!("{what}: checked {} files, {} with differences", self.checked, self.files_with_diffs);
        if self.files_with_diffs == 0 {
            return;
        }
        let mut ranked: Vec<_> = self.shapes.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1));
        for (shape, count) in ranked.iter().take(60) {
            eprintln!("{count:6}  {shape}");
        }
        panic!("{what}: {} files differ from the REA oracle", self.files_with_diffs);
    }
}

/// Call one tool of the ORIGINAL REA MCP server (stdio JSON-RPC) and return the tool result
/// (`structuredContent`, `content`, ...). The server is started per call, like `rea_oracle.py`.
pub fn rea_mcp_call(tool: &str, arguments: Value) -> Value {
    use std::io::Write;
    let mut child = Command::new("node")
        .arg(rea_src().join("scripts/rea.mjs"))
        .arg("mcp")
        .current_dir(rea_src())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn REA MCP server");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut next_id = 0u64;
    let mut send = |method: &str, params: Option<Value>, notify: bool| -> Option<Value> {
        let mut message = serde_json::json!({ "jsonrpc": "2.0", "method": method });
        if let Some(params) = params {
            message["params"] = params;
        }
        let id = if notify {
            None
        } else {
            next_id += 1;
            message["id"] = serde_json::json!(next_id);
            Some(next_id)
        };
        writeln!(stdin, "{message}").expect("write request");
        stdin.flush().expect("flush");
        let id = id?;
        loop {
            let line = lines.next().expect("REA MCP closed").expect("read response");
            let response: Value = serde_json::from_str(&line).expect("response json");
            if response.get("id") == Some(&serde_json::json!(id)) {
                return Some(response);
            }
        }
    };
    send(
        "initialize",
        Some(serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "oracle", "version": "1" }
        })),
        false,
    );
    send("notifications/initialized", None, true);
    let response = send(
        "tools/call",
        Some(serde_json::json!({ "name": tool, "arguments": arguments })),
        false,
    )
    .expect("tool response");
    let _ = child.kill();
    let _ = child.wait();
    response.get("result").cloned().unwrap_or(response)
}
