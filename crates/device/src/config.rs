//! adb binary selection and client probe (port of REA `AdbConfiguration.ts`).

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::exec::{exec_file_output, FailureCode};
use crate::parse::{js_trim, parse_adb_version_output, slice_utf16, ClientIdentity};

/// Environment key selecting the caller's adb binary.
pub const ADB_BINARY_ENV: &str = "REA_ADB_PATH";

const VERSION_TIMEOUT_MS: u64 = 10_000;
const VERSION_MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct AdbBinarySelection {
    pub binary: String,
    pub path_source: &'static str,
}

#[derive(Debug, Clone)]
pub enum ConfigurationFailure {
    NotAbsolute { message: String },
    BinaryMissing { message: String, diagnostics: Map<String, Value> },
    VersionUnresolved { message: String, diagnostics: Map<String, Value> },
}

impl ConfigurationFailure {
    pub fn message(&self) -> &str {
        match self {
            ConfigurationFailure::NotAbsolute { message }
            | ConfigurationFailure::BinaryMissing { message, .. }
            | ConfigurationFailure::VersionUnresolved { message, .. } => message,
        }
    }

    /// `${message} ${diagnostics.remediation}` when a remediation string exists.
    pub fn capability_reason(&self) -> String {
        let diagnostics = match self {
            ConfigurationFailure::BinaryMissing { diagnostics, .. }
            | ConfigurationFailure::VersionUnresolved { diagnostics, .. } => Some(diagnostics),
            ConfigurationFailure::NotAbsolute { .. } => None,
        };
        match diagnostics.and_then(|d| d.get("remediation")).and_then(Value::as_str) {
            Some(remediation) => format!("{} {remediation}", self.message()),
            None => self.message().to_string(),
        }
    }
}

/// `resolveAdbBinary` over an explicit environment lookup.
pub fn resolve_adb_binary(configured: Option<String>) -> Result<AdbBinarySelection, ConfigurationFailure> {
    match configured {
        Some(value) if !js_trim(&value).is_empty() => {
            if !Path::new(&value).is_absolute() {
                return Err(ConfigurationFailure::NotAbsolute {
                    message: format!("{ADB_BINARY_ENV} must be an absolute path to the adb binary"),
                });
            }
            Ok(AdbBinarySelection { binary: value, path_source: "environment" })
        }
        _ => Ok(AdbBinarySelection { binary: "adb".to_string(), path_source: "path" }),
    }
}

/// `inspectAdbClient`: `adb version` never contacts the adb server.
pub async fn inspect_adb_client(selection: &AdbBinarySelection) -> Result<ClientIdentity, ConfigurationFailure> {
    match exec_file_output(
        &selection.binary,
        &["version".to_string()],
        VERSION_TIMEOUT_MS,
        VERSION_MAX_OUTPUT_BYTES,
    )
    .await
    {
        Ok(output) => Ok(parse_adb_version_output(&output.stdout)),
        Err(failure) => {
            if failure.code == FailureCode::Name("ENOENT".to_string()) {
                let mut diagnostics = Map::new();
                diagnostics.insert("selected_binary".into(), json!(selection.binary));
                diagnostics.insert("path_source".into(), json!(selection.path_source));
                diagnostics.insert(
                    "remediation".into(),
                    json!(format!("Set {ADB_BINARY_ENV} to an absolute path to an existing adb binary")),
                );
                return Err(ConfigurationFailure::BinaryMissing {
                    message: format!("The selected adb binary was not found: {}", selection.binary),
                    diagnostics,
                });
            }
            let mut diagnostics = Map::new();
            diagnostics.insert("selected_binary".into(), json!(selection.binary));
            diagnostics.insert(
                "exit_code".into(),
                match &failure.code {
                    FailureCode::Exit(code) => json!(code),
                    FailureCode::Name(name) => json!(name),
                    FailureCode::None => Value::Null,
                },
            );
            diagnostics.insert("stderr_excerpt".into(), json!(slice_utf16(&failure.stderr, 512)));
            Err(ConfigurationFailure::VersionUnresolved {
                message: "The selected adb binary did not report a usable version".to_string(),
                diagnostics,
            })
        }
    }
}
