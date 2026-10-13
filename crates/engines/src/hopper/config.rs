//! Hopper settings read from the REA environment (port of `parseConfig.ts`).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const MAC_LAUNCHER: &str = "/Applications/Hopper Disassembler.app/Contents/MacOS/hopper";
const SYSTEM_LINUX_HOPPER: &str = "/opt/hopper/bin/Hopper";

#[derive(Debug, Clone)]
pub struct HopperConfig {
    pub launcher_path: String,
    /// `HOPPER_TARGET_PATH` / `HOPPER_TARGET_KIND`: REA's server opens it at startup.
    pub target_path: Option<String>,
    pub target_kind: String,
    /// `HOPPER_LOADER_ARGS_JSON`: complete loader selection override.
    pub loader_args: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

fn executable(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn default_launcher(environment: &BTreeMap<String, String>) -> String {
    if !cfg!(target_os = "linux") {
        return MAC_LAUNCHER.to_string();
    }
    if executable(SYSTEM_LINUX_HOPPER) {
        return SYSTEM_LINUX_HOPPER.to_string();
    }
    let home = environment.get("HOME").cloned().unwrap_or_default();
    let user_local = PathBuf::from(home).join(".local/share/rea/hopper/bin/Hopper");
    let user_local = user_local.to_string_lossy().to_string();
    if executable(&user_local) {
        user_local
    } else {
        SYSTEM_LINUX_HOPPER.to_string()
    }
}

impl HopperConfig {
    pub fn from_environment(environment: &BTreeMap<String, String>) -> Self {
        let launcher_path = environment
            .get("HOPPER_LAUNCHER_PATH")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| default_launcher(environment));
        let loader_args = environment
            .get("HOPPER_LOADER_ARGS_JSON")
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        Self {
            launcher_path,
            target_path: environment.get("HOPPER_TARGET_PATH").filter(|v| !v.is_empty()).cloned(),
            target_kind: environment
                .get("HOPPER_TARGET_KIND")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| "executable".to_string()),
            loader_args,
            environment: environment.clone(),
        }
    }
}
