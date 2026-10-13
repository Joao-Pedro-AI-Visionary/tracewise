//! Android device tooling: the adb provider behind REA's 24 `*_adb_*` tools.
//!
//! The crate owns argument admission (`input`), the bounded child-process
//! runner (`exec`), the output parsers (`parse`), REA's error projection
//! (`error`) and the operations themselves (`provider`). The MCP server turns an
//! [`Execution`] into Evidence.

#![allow(clippy::result_large_err)] // ToolError carries the full REA error payload; it only travels on the error path

pub mod config;
pub mod error;
pub mod exec;
pub mod firmware;
pub mod fsutil;
pub mod input;
pub mod native;
pub mod parse;
pub mod provider;
pub mod testing;
pub mod ui_trace;

pub use error::ToolError;
pub use provider::{execute, Execution, ExecuteFailure, ADB_PROVIDER_ID, ADB_PROVIDER_NAME};

/// Names of the 24 adb tools in catalog order.
pub const ADB_TOOLS: [&str; 24] = [
    "inspect_adb_client",
    "list_adb_devices",
    "inspect_adb_device",
    "list_adb_packages",
    "pull_adb_package",
    "read_adb_logcat",
    "inspect_adb_package",
    "pull_adb_file",
    "push_adb_file",
    "capture_adb_screen",
    "list_adb_processes",
    "list_adb_directory",
    "list_adb_features",
    "list_adb_services",
    "inspect_adb_display",
    "inspect_adb_window",
    "read_adb_setting",
    "collect_adb_bugreport",
    "resolve_adb_packages",
    "install_adb_package",
    "uninstall_adb_package",
    "start_adb_app",
    "start_adb_activity",
    "stop_adb_app",
];
