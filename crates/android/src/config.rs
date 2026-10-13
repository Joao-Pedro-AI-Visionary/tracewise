//! Caller-supplied JADX engine and Java runtime (REA `JadxConfiguration.ts`).
//!
//! Nothing is installed or downloaded. `REA_JADX_MCP_JAR` must name the
//! jadx-headless-mcp 0.7.1 JAR and a full JDK (17+, with `jdk.compiler`) must
//! be reachable through `JAVA_HOME` or `PATH`.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Value};

use crate::error::Failure;

pub type Env = HashMap<String, String>;

pub fn process_env() -> Env {
    std::env::vars().collect()
}

pub const JADX_VERSION: &str = "0.7.1";
pub const JADX_REVISION: &str = "5844800a486d2248fa949b74c9896285f5b54de2";
pub const JADX_SHA256: &str = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75";
pub const BRIDGE_NAME: &str = "rea-jadx-bridge";
pub const BRIDGE_VERSION: &str = "1";

fn jar_remediation() -> String {
    format!(
        "Set REA_JADX_MCP_JAR to the absolute path of a caller-supplied jadx-headless-mcp {JADX_VERSION} JAR. REA does not download or install it."
    )
}

const JAVA_MODULE_LISTING_TIMEOUT: Duration = Duration::from_secs(10);
const JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct JadxConfiguration {
    pub jar: String,
    pub java: String,
    pub jvm_arguments: Vec<String>,
}

/// `JadxConfigurationFailure`.
#[derive(Debug, Clone)]
pub struct ConfigFailure {
    pub code: &'static str,
    pub message: String,
    pub diagnostics: Value,
}

impl ConfigFailure {
    fn new(code: &'static str, message: impl Into<String>, diagnostics: Value) -> Self {
        Self { code, message: message.into(), diagnostics }
    }

    /// `projectConfigurationFailure`.
    pub fn into_failure(self, operation: &str) -> Failure {
        let captured = match (self.diagnostics.get("stdout"), self.diagnostics.get("stderr")) {
            (Some(Value::String(stdout)), Some(Value::String(stderr))) => Some(json!({
                "stdout": stdout,
                "stderr": stderr,
                "truncated": self.diagnostics.get("output_truncated") == Some(&json!(true)),
            })),
            _ => None,
        };
        Failure::CapabilityUnavailable {
            provider_id: "jadx".to_string(),
            operation: operation.to_string(),
            reason: self.message.clone(),
            user_message: Some(self.message),
            captured_output: captured,
        }
    }
}

/// Node's message for a failed `access`/`stat` call.
pub fn node_fs_error(error: &std::io::Error, syscall: &str, path: &str) -> String {
    use std::io::ErrorKind::*;
    match error.kind() {
        NotFound => format!("ENOENT: no such file or directory, {syscall} '{path}'"),
        PermissionDenied => format!("EACCES: permission denied, {syscall} '{path}'"),
        _ => match error.raw_os_error() {
            Some(20) => format!("ENOTDIR: not a directory, {syscall} '{path}'"),
            _ => format!("{error}, {syscall} '{path}'"),
        },
    }
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

fn access_ok(path: &str, executable: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    // Effective-user approximation of access(2): any matching read (and execute) bit.
    let read = mode & 0o444 != 0;
    let exec = mode & 0o111 != 0;
    if !read || (executable && !exec) {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

/// Resolve caller-selected paths and JVM options without probing their contents.
pub fn read_inputs(env: &Env) -> Result<JadxConfiguration, ConfigFailure> {
    if !cfg!(unix) {
        return Err(ConfigFailure::new(
            "unsupported_host",
            format!(
                "Android JADX subprocess ownership is unsupported on {}/{}; use Linux, macOS, or Windows x64 with its bundled native controls.",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
            json!({ "platform": std::env::consts::OS }),
        ));
    }
    let jar = resolve_jar(env)?;
    let java = resolve_java(env)?;
    require_java_home_executable(env.get("JAVA_HOME").map(String::as_str), &java)?;
    Ok(JadxConfiguration { jar, java, jvm_arguments: resolve_jvm_arguments(env)? })
}

fn resolve_jar(env: &Env) -> Result<String, ConfigFailure> {
    let Some(jar) = env.get("REA_JADX_MCP_JAR").filter(|j| is_absolute(j)) else {
        return Err(ConfigFailure::new("not_configured", jar_remediation(), json!({ "jar_configured": false })));
    };
    if let Err(error) = access_ok(jar, false) {
        return Err(ConfigFailure::new(
            "executable_missing",
            format!("Cannot read REA_JADX_MCP_JAR {jar}: {}", node_fs_error(&error, "access", jar)),
            json!({ "jar_path": jar }),
        ));
    }
    match std::fs::metadata(jar) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(ConfigFailure::new(
                "executable_missing",
                format!("REA_JADX_MCP_JAR is not a regular file: {jar}"),
                json!({ "jar_path": jar }),
            ))
        }
        Err(error) => {
            return Err(ConfigFailure::new(
                "executable_missing",
                format!("Cannot read REA_JADX_MCP_JAR {jar}: {}", node_fs_error(&error, "stat", jar)),
                json!({ "jar_path": jar }),
            ))
        }
    }
    Ok(std::fs::canonicalize(jar).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| jar.clone()))
}

fn resolve_java(env: &Env) -> Result<String, ConfigFailure> {
    match env.get("JAVA_HOME") {
        None => Ok("java".to_string()),
        Some(home) if is_absolute(home) => Ok(format!("{}/bin/java", home.trim_end_matches('/'))),
        Some(home) => Err(ConfigFailure::new(
            "open_options_invalid",
            "JAVA_HOME must select an existing JDK by absolute path; omit it to use java on PATH.",
            json!({ "java_home": home }),
        )),
    }
}

fn require_java_home_executable(java_home: Option<&str>, java: &str) -> Result<(), ConfigFailure> {
    if java_home.is_none() {
        return Ok(());
    }
    if let Err(error) = access_ok(java, true) {
        return Err(ConfigFailure::new(
            "runtime_missing",
            format!("Cannot execute JAVA_HOME java {java}: {}", node_fs_error(&error, "access", java)),
            json!({ "java_executable": java }),
        ));
    }
    match std::fs::metadata(java) {
        Ok(m) if m.is_file() => Ok(()),
        _ => Err(ConfigFailure::new(
            "runtime_missing",
            format!("JAVA_HOME java is not a regular file: {java}"),
            json!({ "java_executable": java }),
        )),
    }
}

fn resolve_jvm_arguments(env: &Env) -> Result<Vec<String>, ConfigFailure> {
    let mut result = Vec::new();
    let positive = Regex::new(r"^[1-9]\d*$").expect("regex");
    for (name, prefix, suffix) in [
        ("REA_JADX_HEAP_MIB", "-Xmx", "m"),
        ("REA_JADX_ACTIVE_PROCESSOR_COUNT", "-XX:ActiveProcessorCount=", ""),
    ] {
        let Some(value) = env.get(name) else { continue };
        let safe = positive.is_match(value) && value.parse::<u64>().map(|v| v < (1u64 << 53)).unwrap_or(false);
        if !safe {
            return Err(ConfigFailure::new(
                "open_options_invalid",
                format!("{name} must be a positive safe integer; received {value}."),
                json!({ "setting": name, "value": value }),
            ));
        }
        if name == "REA_JADX_ACTIVE_PROCESSOR_COUNT" && value.parse::<u64>().unwrap_or(0) > 2_147_483_647 {
            return Err(ConfigFailure::new(
                "open_options_invalid",
                format!("{name} exceeds the JVM's signed 32-bit processor-count range."),
                json!({ "setting": name, "value": value }),
            ));
        }
        result.push(format!("{prefix}{value}{suffix}"));
    }
    Ok(result)
}

/// Probe Java and archive prerequisites before starting a new engine session.
pub fn validate_contents(config: &JadxConfiguration, env: &Env) -> Result<(), ConfigFailure> {
    inspect_java_runtime(&config.java, env)?;
    require_engine_archive(&config.jar)
}

struct Captured {
    stdout: String,
    stderr: String,
    exit: Option<i32>,
    signal: Option<i32>,
    killed: bool,
    truncated: bool,
}

fn run_bounded(command: &str, args: &[&str], env: &Env, timeout: Duration, max_buffer: usize) -> Result<Captured, std::io::Error> {
    let mut child = Command::new(command)
        .args(args)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout_pipe = child.stdout.take().expect("stdout");
    let mut stderr_pipe = child.stderr.take().expect("stderr");
    let out_thread = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match stdout_pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buffer.len() + n > max_buffer {
                        truncated = true;
                        buffer.extend_from_slice(&chunk[..max_buffer.saturating_sub(buffer.len())]);
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                }
            }
        }
        (buffer, truncated)
    });
    let err_thread = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buffer);
        buffer
    });
    let started = Instant::now();
    let mut killed = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            killed = true;
            let _ = child.kill();
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let (stdout, truncated) = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    use std::os::unix::process::ExitStatusExt;
    Ok(Captured {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit: status.code(),
        signal: status.signal(),
        killed,
        truncated,
    })
}

fn inspect_java_runtime(java: &str, env: &Env) -> Result<(), ConfigFailure> {
    let output = match run_bounded(java, &["--list-modules"], env, JAVA_MODULE_LISTING_TIMEOUT, JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES) {
        Ok(output) => output,
        Err(error) => {
            let code = match error.kind() {
                std::io::ErrorKind::NotFound => "ENOENT",
                std::io::ErrorKind::PermissionDenied => "EACCES",
                _ => "UNKNOWN",
            };
            let text = format!("spawn {java} {code}");
            return Err(ConfigFailure::new(
                "runtime_missing",
                format!("Cannot inspect selected Java runtime {java}: {text}. Select a full JDK including jdk.compiler via JAVA_HOME or PATH; verify it with java --list-modules."),
                json!({
                    "java_executable": java,
                    "phase": "module-inspection",
                    "exit_code": null,
                    "process_error_code": code,
                    "signal": null,
                    "killed": false,
                    "stdout": "",
                    "stderr": "",
                    "output_truncated": false,
                }),
            ));
        }
    };
    let diagnostics = json!({
        "java_executable": java,
        "phase": "module-inspection",
        "exit_code": output.exit,
        "process_error_code": null,
        "signal": output.signal.map(|s| format!("SIG{s}")),
        "killed": output.killed,
        "stdout": output.stdout,
        "stderr": output.stderr,
        "output_truncated": output.truncated,
    });
    let mut diagnostics_map = diagnostics.as_object().cloned().unwrap_or_default();
    if output.truncated {
        diagnostics_map.insert("failure".into(), json!("output_limit"));
        diagnostics_map.insert("output_limit_bytes".into(), json!(JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES));
        return Err(ConfigFailure::new(
            "version_unresolved",
            format!(
                "The selected Java launcher {java} exceeded the {} MiB output budget while listing modules. REA retained partial output but could not establish compiler or version availability. Inspect the selected launcher for verbose or unbounded output; java --list-modules should return a concise module listing.",
                JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES / (1024 * 1024)
            ),
            Value::Object(diagnostics_map),
        ));
    }
    if output.killed {
        diagnostics_map.insert("failure".into(), json!("probe_terminated"));
        diagnostics_map.insert("deadline_ms".into(), json!(JAVA_MODULE_LISTING_TIMEOUT.as_millis() as u64));
        return Err(ConfigFailure::new(
            "version_unresolved",
            format!(
                "The selected Java launcher {java} was terminated or did not finish the module-listing probe within {} seconds. Inspect the launcher and its startup responsiveness, then verify it returns compiler and version modules with java --list-modules.",
                JAVA_MODULE_LISTING_TIMEOUT.as_secs()
            ),
            Value::Object(diagnostics_map),
        ));
    }
    if output.exit != Some(0) {
        let text = format!("Command failed: {java} --list-modules\n{}", output.stderr);
        let reason = if output.stderr.trim().is_empty() { text } else { output.stderr.trim().to_string() };
        return Err(ConfigFailure::new(
            "runtime_missing",
            format!("Cannot inspect selected Java runtime {java}: {reason}. Select a full JDK including jdk.compiler via JAVA_HOME or PATH; verify it with java --list-modules."),
            Value::Object(diagnostics_map),
        ));
    }
    let stdout = &output.stdout;
    let compiler = Regex::new(r"(?m)^jdk\.compiler(?:@|$)").expect("regex").is_match(stdout);
    if !compiler {
        return Err(ConfigFailure::new(
            "runtime_missing",
            format!("Selected Java runtime {java} does not provide jdk.compiler. Select a full JDK including jdk.compiler via JAVA_HOME or PATH; verify it with java --list-modules. A JRE cannot compile REA's source bridge."),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": false,
                "stdout": stdout,
                "stderr": output.stderr,
                "output_truncated": false,
            }),
        ));
    }
    let major = Regex::new(r"(?m)^java\.base@(\d+)(?:[.+_-]|$)").expect("regex").captures(stdout).map(|c| c[1].to_string());
    let Some(major) = major else {
        return Err(ConfigFailure::new(
            "version_unresolved",
            format!("The selected Java launcher {java} did not report a parseable java.base version in its module listing. Inspect the launcher output and verify it with java --list-modules."),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": true,
                "java_major": null,
                "stdout": stdout,
                "stderr": output.stderr,
                "output_truncated": false,
            }),
        ));
    };
    if major.parse::<u64>().unwrap_or(0) < 17 {
        return Err(ConfigFailure::new(
            "unsupported_version",
            format!("Selected Java runtime {java} must be JDK 17 or newer and include jdk.compiler; verify it with java --list-modules."),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": true,
                "java_major": major,
                "stdout": stdout,
                "stderr": output.stderr,
                "output_truncated": false,
            }),
        ));
    }
    Ok(())
}

const REQUIRED_CLASSES: [&str; 5] = [
    "com/atxx/jhmcp/JadxSession.class",
    "com/atxx/jhmcp/SessionHolder.class",
    "jadx/api/JadxDecompiler.class",
    "com/google/gson/Gson.class",
    "io/modelcontextprotocol/kotlin/sdk/server/Server.class",
];

fn has_end_of_central_directory(path: &str) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    let tail_start = bytes.len().saturating_sub(65_557);
    bytes[tail_start..].windows(4).any(|w| w == [0x50, 0x4b, 0x05, 0x06])
}

fn require_engine_archive(jar: &str) -> Result<(), ConfigFailure> {
    let remediation = jar_remediation();
    let fail_inspect = |reason: String| {
        ConfigFailure::new(
            "version_unresolved",
            format!("Cannot inspect REA_JADX_MCP_JAR {jar} as a Java archive: {reason}. {remediation}"),
            json!({
                "jar_path": jar,
                "phase": "jar-inspection",
                "archive_error": reason,
                "maximum_metadata_read_bytes": 8 * 1024 * 1024,
            }),
        )
    };
    let file = std::fs::File::open(jar).map_err(|e| fail_inspect(e.to_string()))?;
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(error) => {
            let reason = if has_end_of_central_directory(jar) { error.to_string() } else { "End of central directory not found".to_string() };
            return Err(fail_inspect(reason));
        }
    };
    let mut missing: Vec<&str> = REQUIRED_CLASSES.to_vec();
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index_raw(index) else { continue };
        if entry.is_file() {
            missing.retain(|name| *name != entry.name());
        }
        if missing.is_empty() {
            return Ok(());
        }
    }
    Err(ConfigFailure::new(
        "unsupported_version",
        format!(
            "REA_JADX_MCP_JAR {jar} does not contain the required metadata bridge classes: {}. {remediation}",
            missing.join(", ")
        ),
        json!({ "jar_path": jar, "phase": "jar-inspection", "missing_classes": missing }),
    ))
}

/// Whether a path is a regular readable file.
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
