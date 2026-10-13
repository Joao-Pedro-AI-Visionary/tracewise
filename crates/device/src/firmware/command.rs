//! Resolution of the caller-supplied firmware tools (port of
//! `resolveFirmwareCommand` in REA `FirmwareCommand.ts`). Tools are never
//! installed or searched for; they come from an absolute env path.

use crate::error::ToolError;
use crate::firmware::files::hash_file;
use crate::firmware::release::Engine;
use crate::fsutil::{is_absolute, node_io_error};

#[derive(Debug, Clone)]
pub struct ResolvedCommand {
    pub command: String,
    pub limiter: String,
    pub sha256: String,
}

/// `firmwareToolUnavailable`: the reason is also the caller-facing message.
pub fn tool_unavailable(engine: &str, operation: &str, reason: String) -> ToolError {
    ToolError::CapabilityUnavailable {
        provider_id: engine.to_string(),
        operation: operation.to_string(),
        reason: reason.clone(),
        user_message: Some(reason),
    }
}

/// `fs.access(path, mode)` with Node's error text.
fn access(path: &str, mode: i32) -> Result<(), String> {
    let c_path = std::ffi::CString::new(path).map_err(|_| format!("ERR_INVALID_ARG_VALUE: invalid path, access '{path}'"))?;
    // SAFETY: valid NUL-terminated path for the duration of the call.
    if unsafe { libc::access(c_path.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(node_io_error(&std::io::Error::last_os_error(), "access", path))
    }
}

fn is_regular_file(path: &str) -> Result<bool, String> {
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .map_err(|e| node_io_error(&e, "stat", path))
}

/// Resolve the tool and resource limiter for one engine.
pub fn resolve_command(
    env: &dyn Fn(&str) -> Option<String>,
    engine: Engine,
    operation: &str,
) -> Result<ResolvedCommand, ToolError> {
    let variable = engine.command_variable();
    let name = engine.id();
    let configured = env(variable);
    let configured = match configured {
        Some(value) if cfg!(target_os = "linux") && is_absolute(&value) => value,
        _ => {
            return Err(tool_unavailable(
                name,
                operation,
                format!("This integration requires Linux and an absolute {variable} path to the caller-supplied tool"),
            ))
        }
    };
    let command = std::fs::canonicalize(&configured)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| {
            tool_unavailable(
                name,
                operation,
                format!("{variable} is unavailable: {}", node_io_error(&e, "realpath", &configured)),
            )
        })?;
    let probe = || -> Result<String, String> {
        access(&command, libc::R_OK | libc::X_OK)?;
        if !is_regular_file(&command)? {
            return Err("Configured path is not a regular file".to_string());
        }
        hash_file(&command)
    };
    let sha256 = probe().map_err(|cause| {
        tool_unavailable(
            name,
            operation,
            format!("{variable} is not a readable executable regular file: {command}: {cause}"),
        )
    })?;
    let limiter = env("REA_FIRMWARE_PRLIMIT_COMMAND").unwrap_or_else(|| "/usr/bin/prlimit".to_string());
    if !is_absolute(&limiter) {
        return Err(tool_unavailable(name, operation, "REA_FIRMWARE_PRLIMIT_COMMAND must be absolute".to_string()));
    }
    let limiter_probe = || -> Result<(), String> {
        access(&limiter, libc::X_OK)?;
        if !is_regular_file(&limiter)? {
            return Err("Configured path is not a regular file".to_string());
        }
        Ok(())
    };
    limiter_probe().map_err(|cause| {
        tool_unavailable(
            name,
            operation,
            format!("Resource limiter is not an executable regular file: {limiter}: {cause}; provide util-linux prlimit"),
        )
    })?;
    Ok(ResolvedCommand { command, limiter, sha256 })
}
