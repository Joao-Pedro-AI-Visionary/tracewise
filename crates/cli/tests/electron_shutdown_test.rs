//! `tracewise mcp` must not leave an Electron application or its profile directory behind however the
//! client or the operator ends the session while `capture_electron_scenario` is running:
//! `notifications/cancelled`, a closed stdin, SIGTERM, and (best effort) SIGKILL of the server.
//!
//! The server is the real binary configured like an operator would
//! (`TRACEWISE_ELECTRON_EXECUTABLE`, `TRACEWISE_ELECTRON_RUNTIME_DIR`, a private Xvfb display) and runs
//! the real Electron 44.7.0 against REA's readiness app with a click that never resolves, so the
//! request is still pending when the session ends.
//!
//! - cancelled: the process group is killed when the request's future is dropped, the server keeps
//!   serving, and the directory is gone;
//! - stdin closed / SIGTERM: `run_stdio_server` leaves through `tracks::shutdown` and then `exit`, so
//!   no future is dropped on the SIGTERM path; the `atexit` hook of the provider does the cleanup;
//! - SIGKILL: nothing runs in the server. The leader carries `PR_SET_PDEATHSIG`, so Electron still
//!   dies; only the (small) run directory stays until the next run's sweep, which the provider tests cover.
//!
//! Skips, printing why, without Electron or Xvfb; fails instead when `TRACEWISE_REQUIRE_ORACLE=1`.

#[path = "../../server/tests/electron_support/basic.rs"]
mod electron_basic;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use electron_basic::*;
use serde_json::{json, Value};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    next_id: u64,
    runtime: ScratchDir,
    _xvfb: Xvfb,
}

impl Server {
    fn start() -> Option<Server> {
        let electron = electron_executable()?;
        let xvfb = Xvfb::start()?;
        let runtime = ScratchDir::new("shutdown-runtime");
        let mut child = Command::new(env!("CARGO_BIN_EXE_tracewise"))
            .arg("mcp")
            .env("TRACEWISE_ELECTRON_EXECUTABLE", &electron)
            .env("TRACEWISE_ELECTRON_RUNTIME_DIR", &runtime.0)
            .env("DISPLAY", &xvfb.display)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tracewise mcp");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Server {
            child,
            stdin,
            lines,
            next_id: 0,
            runtime,
            _xvfb: xvfb,
        };
        let id = server.send_request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "electron-shutdown-test", "version": "1" } }),
        );
        server.wait_response(id);
        server.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        Some(server)
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn send_request(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        id
    }

    fn wait_response(&mut self, id: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).expect("a response before the deadline");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }

    /// Start the never-resolving capture and wait until Electron is up and the click is polling.
    fn start_pending_capture(&mut self) -> u64 {
        let electron = electron_executable().unwrap();
        let app = readiness_app();
        let id = self.send_request(
            "tools/call",
            json!({
                "name": "capture_electron_scenario",
                "arguments": {
                    "executable_path": electron,
                    "application_path": app.join("main.js"),
                    "application_root": app,
                    "args": base_args(),
                    "actions": [{ "step_id": "missing", "kind": "click", "selector": "#does-not-exist" }],
                },
            }),
        );
        let needle = self.runtime.0.to_string_lossy().to_string();
        assert!(
            wait_until(Duration::from_secs(60), || processes_with_cmdline(&needle).len() >= 4),
            "Electron never started"
        );
        std::thread::sleep(Duration::from_secs(8));
        assert!(!run_directories(&self.runtime.0).is_empty(), "the run directory exists while the capture runs");
        id
    }

    fn electron_processes(&self) -> Vec<i32> {
        processes_with_cmdline(&self.runtime.0.to_string_lossy())
    }

    fn wait_exit(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    fn assert_nothing_left(&self, what: &str) {
        assert!(
            wait_until(Duration::from_secs(15), || self.electron_processes().is_empty()),
            "{what}: Electron processes left: {:?}",
            self.electron_processes()
        );
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn signal(pid: u32, name: &str) {
    let status = Command::new("kill").arg(format!("-{name}")).arg(pid.to_string()).status().expect("kill");
    assert!(status.success());
}

#[test]
fn cancelling_the_request_cleans_up_and_the_server_keeps_serving() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut server) = Server::start() else { return };
    let id = server.start_pending_capture();
    server.send(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": id, "reason": "test" } }));
    server.assert_nothing_left("cancelled");
    // The processes turn into zombies (empty cmdline) at SIGKILL, a few milliseconds before the
    // dropped future finishes removing the profile directory, and the client gets no response to a
    // cancellation to synchronise on. A short deadline, not an immediate check: a directory that
    // is still there after it is a real leak.
    assert!(
        wait_until(Duration::from_secs(5), || run_directories(&server.runtime.0).is_empty()),
        "run directory left behind: {:?}",
        run_directories(&server.runtime.0)
    );
    // Still alive and answering.
    let listed = server.send_request("tools/list", json!({}));
    let response = server.wait_response(listed);
    assert!(response["result"]["tools"].as_array().is_some_and(|tools| !tools.is_empty()), "{response}");
    assert!(matches!(server.child.try_wait(), Ok(None)), "the server survived the cancellation");
}

#[test]
fn closing_stdin_cleans_up() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut server) = Server::start() else { return };
    server.start_pending_capture();
    drop(server.stdin.take());
    let status = server.wait_exit(Duration::from_secs(30)).expect("the server exits when stdin closes");
    assert!(status.success() || status.code().is_some(), "{status:?}");
    server.assert_nothing_left("stdin closed");
    assert!(run_directories(&server.runtime.0).is_empty(), "{:?}", run_directories(&server.runtime.0));
}

#[test]
fn sigterm_cleans_up_through_the_exit_hook() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut server) = Server::start() else { return };
    server.start_pending_capture();
    signal(server.child.id(), "TERM");
    let status = server.wait_exit(Duration::from_secs(30)).expect("the server exits on SIGTERM");
    assert_eq!(status.code(), Some(143), "{status:?}");
    server.assert_nothing_left("SIGTERM");
    assert!(run_directories(&server.runtime.0).is_empty(), "{:?}", run_directories(&server.runtime.0));
}

#[test]
fn sigkill_of_the_server_still_ends_electron() {
    let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let Some(mut server) = Server::start() else { return };
    server.start_pending_capture();
    signal(server.child.id(), "KILL");
    server.wait_exit(Duration::from_secs(10)).expect("SIGKILL ends the server");
    // Nothing in the server ran, so this is `PR_SET_PDEATHSIG` on the Electron leader plus Chromium's
    // helpers exiting with their browser process.
    server.assert_nothing_left("SIGKILL of the server");
}
