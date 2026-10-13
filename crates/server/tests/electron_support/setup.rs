//! Scenario setup shared by the server-side Electron tests (needs the tracewise crates;
//! the process-level helpers in `basic.rs` do not).
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use tracewise_web::electron_active::ElectronActiveConfig;
use tracewise_web::electron_scenario::parse_capture_electron_scenario_input;

use super::basic::*;

/// One real Electron at a time: concurrent ones would starve the shared machine.
pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());


pub fn validate_schema(structured: &Value) {
    let tools = tracewise_contracts::phase2_tools_value();
    let tool = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "capture_electron_scenario")
        .expect("tool in phase2");
    let validator = jsonschema::validator_for(&tool["outputSchema"]).expect("schema");
    validator
        .validate(structured)
        .unwrap_or_else(|error| panic!("capture_electron_scenario schema: {error}"));
}


pub struct Setup {
    pub electron: PathBuf,
    pub xvfb: Xvfb,
    pub scratch: ScratchDir,
}

impl Setup {
    pub fn new(label: &str) -> Option<Self> {
        let electron = electron_executable()?;
        let xvfb = Xvfb::start()?;
        Some(Self {
            electron,
            xvfb,
            scratch: ScratchDir::new(label),
        })
    }

    pub fn config(&self) -> ElectronActiveConfig {
        ElectronActiveConfig::from_values(self.electron.to_str().unwrap(), self.scratch.0.to_str()).unwrap()
    }

    pub fn environment(&self) -> HashMap<String, String> {
        launch_environment(&self.xvfb.display)
    }

    pub fn scenario(&self, actions: Value) -> Map<String, Value> {
        let app = readiness_app();
        parse_capture_electron_scenario_input(&json!({
            "executable_path": self.electron,
            "application_path": app.join("main.js"),
            "application_root": app,
            "args": base_args(),
            "actions": actions,
        }))
        .unwrap()
    }

    pub fn assert_clean(&self) {
        assert!(
            run_directories(&self.scratch.0).is_empty(),
            "run directories left behind: {:?}",
            run_directories(&self.scratch.0)
        );
        let needle = self.scratch.0.to_string_lossy().to_string();
        assert!(
            processes_with_cmdline(&needle).is_empty(),
            "processes left behind: {:?}",
            processes_with_cmdline(&needle)
        );
    }
}

pub fn readiness_actions() -> Value {
    read_json(&repo_root().join("fixtures/electron/scenario_readiness.json"))["actions"].clone()
}

pub fn read_json(path: &std::path::Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

use std::sync::OnceLock;

pub struct Configured {
    pub electron: PathBuf,
    pub runtime: PathBuf,
}

static CONFIGURED: OnceLock<Option<Configured>> = OnceLock::new();
static RUNTIME_DIR: OnceLock<PathBuf> = OnceLock::new();

extern "C" {
    fn atexit(callback: extern "C" fn()) -> i32;
}

/// The test process has no teardown hook for statics: remove the runtime directory (it is empty
/// when every test passed; a leftover run directory would make `remove_dir` fail and stay visible).
extern "C" fn remove_runtime_dir() {
    if let Some(dir) = RUNTIME_DIR.get() {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Start Xvfb from a thread that never exits (`PR_SET_PDEATHSIG` follows the creating thread),
/// export the operator configuration and return it; `None` when Electron or Xvfb is missing.
pub fn configured() -> Option<&'static Configured> {
    CONFIGURED
        .get_or_init(|| {
            let electron = electron_executable()?;
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let xvfb = Xvfb::start();
                let display = xvfb.as_ref().map(|x| x.display.clone());
                let _ = sender.send(display);
                loop {
                    std::thread::park();
                }
            });
            let display = receiver.recv().ok()??;
            let runtime = std::env::temp_dir().join(format!("tw-mcp-runtime-{}", std::process::id()));
            std::fs::create_dir_all(&runtime).ok()?;
            RUNTIME_DIR.set(runtime.clone()).ok();
            // SAFETY: registers a plain `extern "C" fn()` that only removes the (empty) directory.
            unsafe {
                atexit(remove_runtime_dir);
            }
            std::env::set_var("TRACEWISE_ELECTRON_EXECUTABLE", &electron);
            std::env::set_var("TRACEWISE_ELECTRON_RUNTIME_DIR", &runtime);
            std::env::set_var("DISPLAY", display);
            Some(Configured { electron, runtime })
        })
        .as_ref()
}
