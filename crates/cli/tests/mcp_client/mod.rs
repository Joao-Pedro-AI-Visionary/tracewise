//! Minimal blocking MCP client around the real `tracewise mcp` binary, shared by the shutdown
//! tests. Responses are read on a helper thread so that a test can send a request and not wait.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub struct Client {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Client {
    /// Start `tracewise mcp` with the given environment (the rest is inherited).
    pub fn start(envs: &[(&str, &str)]) -> Client {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tracewise"));
        command.arg("mcp").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command.spawn().expect("spawn tracewise mcp");
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
        let mut client = Client { child, stdin, lines, next_id: 0 };
        client.request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "shutdown-test", "version": "1" } }),
        );
        client.notify("notifications/initialized");
        client
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    pub fn notify(&mut self, method: &str) {
        self.send(json!({ "jsonrpc": "2.0", "method": method }));
    }

    pub fn notify_with(&mut self, method: &str, params: Value) {
        self.send(json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    /// Send a request and return its id without waiting for the answer.
    pub fn send_request(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        id
    }

    pub fn wait_for(&mut self, id: u64, limit: Duration) -> Value {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).expect("response before the deadline");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send_request(method, params);
        self.wait_for(id, Duration::from_secs(120))
    }

    pub fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    /// Wait for the server to exit; returns its status and how long that took after `since`.
    pub fn wait_exit(&mut self, since: Instant, limit: Duration) -> (std::process::ExitStatus, Duration) {
        let deadline = since + limit;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status, since.elapsed());
            }
            assert!(Instant::now() < deadline, "tracewise mcp did not exit within {limit:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn signal(&self, signal: &str) {
        let status = Command::new("kill").arg(format!("-{signal}")).arg(self.child.id().to_string()).status().unwrap();
        assert!(status.success());
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // A failed assertion must not leave the server (and its JVM) behind.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
