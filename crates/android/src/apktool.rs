//! Apktool resource decoding over a caller-selected launcher (REA
//! `ApktoolConfiguration.ts`, `ApktoolDecodeOutput.ts`, `ApktoolProvider.ts`).
//!
//! Apktool is bring-your-own. Decoding runs `apktool d --no-src` in a private
//! workspace that is removed once the requested facts are projected.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Value};

use crate::cancel::{CancelToken, GroupChild};
use crate::config::{Env, node_fs_error};
use crate::error::{Error, Failure, Outcome};
use crate::jadx::sha256_file;

pub const ENV_COMMAND: &str = "REA_APKTOOL_COMMAND";
const VERSION_TIMEOUT: Duration = Duration::from_millis(20_000);
const VERSION_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const DECODE_TIMEOUT: Duration = Duration::from_millis(600_000);
const DECODE_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MANIFEST_MAX_BYTES: usize = 512 * 1024;
const STRINGS_XML_MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRINGS: usize = 2_000;
const MAX_DECODED_ENTRIES_VISITED: usize = 100_000;
const STDERR_EXCERPT_BYTES: usize = 512;

/// Provider identity before the launcher version is known.
pub fn provider(version: Option<&str>) -> Value {
    json!({ "id": "apktool", "name": "Apktool", "version": version })
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub command: String,
    pub source: &'static str,
}

/// `ApktoolConfigurationFailure`.
#[derive(Debug, Clone)]
pub struct ConfigFailure {
    pub code: &'static str,
    pub message: String,
    pub diagnostics: Value,
}

/// Resolve the caller-supplied launcher.
pub fn resolve_command(env: &Env) -> Result<Selection, ConfigFailure> {
    match env.get(ENV_COMMAND) {
        Some(configured) if !configured.trim().is_empty() => {
            if !configured.starts_with('/') {
                return Err(ConfigFailure {
                    code: "not_absolute",
                    message: format!("{ENV_COMMAND} must be an absolute path to the apktool launcher"),
                    diagnostics: json!({ "configured_command": configured }),
                });
            }
            Ok(Selection { command: configured.clone(), source: "environment" })
        }
        _ => Ok(Selection { command: "apktool".to_string(), source: "path" }),
    }
}

struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    output_limit: bool,
    cancelled: bool,
}

fn run(
    command: &str,
    args: &[&str],
    env: &Env,
    timeout: Duration,
    max_output: usize,
    cancel: &CancelToken,
) -> std::io::Result<Captured> {
    let mut process = Command::new(command);
    process.args(args).env_clear().envs(env).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // The launcher leads its own process group: killing the group also reaches a
    // JVM that a wrapper script started without `exec`.
    let mut child = GroupChild::spawn(&mut process, cancel)?;
    let mut out_pipe = child.child.stdout.take().expect("stdout");
    let mut err_pipe = child.child.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut limited = false;
        while let Ok(read) = out_pipe.read(&mut chunk) {
            if read == 0 {
                break;
            }
            if buffer.len() < max_output {
                let take = read.min(max_output - buffer.len());
                buffer.extend_from_slice(&chunk[..take]);
                if take < read {
                    limited = true;
                }
            } else {
                limited = true;
            }
        }
        (buffer, limited)
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut limited = false;
        while let Ok(read) = err_pipe.read(&mut chunk) {
            if read == 0 {
                break;
            }
            if buffer.len() < max_output {
                let take = read.min(max_output - buffer.len());
                buffer.extend_from_slice(&chunk[..take]);
                if take < read {
                    limited = true;
                }
            } else {
                limited = true;
            }
        }
        (buffer, limited)
    });
    let started = Instant::now();
    let mut timed_out = false;
    let mut cancelled = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if cancel.is_cancelled() {
            cancelled = true;
            break child.kill_and_wait()?;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            break child.kill_and_wait()?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let (stdout, out_limited) = out.join().unwrap_or_default();
    let (stderr, err_limited) = err.join().unwrap_or_default();
    use std::os::unix::process::ExitStatusExt;
    Ok(Captured { stdout, stderr, exit: status.code(), signal: status.signal(), timed_out, output_limit: out_limited || err_limited, cancelled })
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// First non-empty line of `apktool --version`.
pub fn parse_version_output(stdout: &str) -> Option<String> {
    stdout.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
}

/// `inspectApktoolClient`.
pub fn inspect_client(selection: &Selection, env: &Env, cancel: &CancelToken) -> Result<Option<String>, ConfigFailure> {
    let remediation = format!("Set {ENV_COMMAND} to an absolute apktool launcher (the upstream wrapper or a java -jar script)");
    match run(&selection.command, &["--version"], env, VERSION_TIMEOUT, VERSION_MAX_OUTPUT_BYTES, cancel) {
        Ok(output) if output.cancelled => Err(ConfigFailure { code: "cancelled", message: String::new(), diagnostics: Value::Null }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(ConfigFailure {
            code: "command_missing",
            message: format!("The selected apktool launcher was not found: {}", selection.command),
            diagnostics: json!({
                "selected_command": selection.command,
                "command_source": selection.source,
                "remediation": remediation,
            }),
        }),
        Err(error) => Err(ConfigFailure {
            code: "version_unresolved",
            message: "The selected apktool launcher did not report a usable version".to_string(),
            diagnostics: json!({
                "selected_command": selection.command,
                "exit_code": error.raw_os_error().map(|c| c.to_string()),
                "stderr_excerpt": "",
            }),
        }),
        Ok(output) if output.exit == Some(0) && !output.timed_out && !output.output_limit => {
            Ok(parse_version_output(&text(&output.stdout)))
        }
        Ok(output) => {
            let stderr = text(&output.stderr);
            Err(ConfigFailure {
                code: "version_unresolved",
                message: "The selected apktool launcher did not report a usable version".to_string(),
                diagnostics: json!({
                    "selected_command": selection.command,
                    "exit_code": output.exit,
                    "stderr_excerpt": stderr.chars().take(512).collect::<String>(),
                }),
            })
        }
    }
}

/// `parseApktoolYml`.
pub fn parse_apktool_yml(yml: &str) -> [Option<String>; 4] {
    let version_name = Regex::new(r"^\s*versionName:\s*(?:'([^']*)'|(.*))$").expect("regex");
    let version_code = Regex::new(r"^\s*versionCode:\s*(?:'([^']*)'|(.*))$").expect("regex");
    let min_sdk = Regex::new(r"minSdkVersion:\s*'?([0-9]+)'?").expect("regex");
    let target_sdk = Regex::new(r"targetSdkVersion:\s*'?([0-9]+)'?").expect("regex");
    let mut metadata: [Option<String>; 4] = [None, None, None, None];
    for line in yml.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(c) = version_name.captures(line) {
            if metadata[0].is_none() {
                metadata[0] = Some(c.get(1).or(c.get(2)).map(|m| m.as_str()).unwrap_or("").trim().to_string());
            }
        }
        if let Some(c) = version_code.captures(line) {
            if metadata[1].is_none() {
                metadata[1] = Some(c.get(1).or(c.get(2)).map(|m| m.as_str()).unwrap_or("").trim().to_string());
            }
        }
        if let Some(c) = min_sdk.captures(line) {
            if metadata[2].is_none() {
                metadata[2] = Some(c[1].to_string());
            }
        }
        if let Some(c) = target_sdk.captures(line) {
            if metadata[3].is_none() {
                metadata[3] = Some(c[1].to_string());
            }
        }
    }
    metadata
}

pub fn parse_manifest_package(manifest: &str) -> Option<String> {
    Regex::new(r#"<manifest[^>]*\spackage="([^"]+)""#).expect("regex").captures(manifest).map(|c| c[1].to_string())
}

/// `parseDecodedStrings`: (entries, unparsed count).
pub fn parse_decoded_strings(xml: &str) -> (Vec<(String, String)>, usize) {
    let pattern = Regex::new(r#"<string\s+name="([^"]+)"[^>]*>([\s\S]*?)</string>"#).expect("regex");
    let mut entries = Vec::new();
    let mut unparsed = 0;
    for capture in pattern.captures_iter(xml) {
        let value = &capture[2];
        if value.contains('<') {
            unparsed += 1;
            continue;
        }
        entries.push((capture[1].to_string(), value.trim().to_string()));
    }
    (entries, unparsed)
}

fn locale_qualifier(locale: &str) -> String {
    Regex::new(r"^([a-z]{2,3})-([A-Z]{2}|[0-9]{3})$").expect("regex").replace(locale, "$1-r$2").into_owned()
}

/// Read at most `budget` bytes (plus one to detect truncation) before decoding.
fn read_bounded_text(path: &std::path::Path, budget: usize) -> std::io::Result<(Option<String>, bool)> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((None, false)),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(budget as u64 + 1).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > budget;
    bytes.truncate(budget);
    let text = if truncated {
        // A prefix may end within a UTF-8 character; omit those trailing bytes.
        match std::str::from_utf8(&bytes) {
            Ok(valid) => valid.to_string(),
            Err(error) if error.error_len().is_none() => String::from_utf8_lossy(&bytes[..error.valid_up_to()]).into_owned(),
            Err(_) => String::from_utf8_lossy(&bytes).into_owned(),
        }
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Ok((Some(text), truncated))
}

fn count_decoded_files(root: &std::path::Path) -> std::io::Result<(usize, bool, Vec<String>)> {
    let mut count = 0usize;
    let mut capped = false;
    let mut visited = 0usize;
    let mut directories = vec![root.to_path_buf()];
    let mut locales: Vec<String> = Vec::new();
    let locale_pattern = Regex::new(r"^values-(.+)$").expect("regex");
    while !directories.is_empty() && !capped {
        let directory = directories.pop().expect("directory");
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if visited >= MAX_DECODED_ENTRIES_VISITED {
                capped = true;
                break;
            }
            visited += 1;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                directories.push(path.clone());
                if directory == root.join("res") {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(captures) = locale_pattern.captures(&name) {
                        if path.join("strings.xml").exists() {
                            locales.push(captures[1].to_string());
                        }
                    }
                }
            } else if kind.is_file() {
                count += 1;
            }
        }
    }
    locales.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    Ok((count, capped, locales))
}

pub struct Execution {
    pub result: Value,
    pub provider: Value,
    pub limitations: Vec<String>,
}

fn capability(operation: &str, config: &ConfigFailure) -> Error {
    if config.code == "cancelled" {
        return Failure::Cancelled { operation: operation.to_string() }.into();
    }
    let reason = match config.diagnostics.get("remediation").and_then(Value::as_str) {
        Some(remediation) => format!("{} {remediation}", config.message),
        None => config.message.clone(),
    };
    Failure::capability("apktool", operation, reason).into()
}

/// `inspect_apktool_client`.
pub fn execute_client(env: &Env, cancel: &CancelToken) -> Outcome<Execution> {
    let operation = "inspect_apktool_client";
    let selection = resolve_command(env).map_err(|c| fallback_config_error(operation, &c))?;
    let version = inspect_client(&selection, env, cancel).map_err(|c| capability(operation, &c))?;
    Ok(Execution {
        result: json!({
            "client": { "command": selection.command, "command_source": selection.source, "apktool_version": version },
        }),
        provider: provider(version.as_deref()),
        limitations: vec![],
    })
}

/// A launcher that is not an absolute path rejects before the provider can classify it.
fn fallback_config_error(operation: &str, config: &ConfigFailure) -> Error {
    Failure::Adapter {
        provider_id: "apktool".to_string(),
        operation: operation.to_string(),
        diagnostics: Some(json!({ "reason": config.message })),
    }
    .into()
}

struct Workspace {
    root: tempfile::TempDir,
}

fn analysis_input_error(operation: &str) -> Error {
    Failure::Input { operation: operation.to_string(), issues: vec![] }.into()
}

/// `decode_android_resources`.
pub fn execute_decode(
    env: &Env,
    input_path: &str,
    include_strings: bool,
    locale: Option<&str>,
    cancel: &CancelToken,
) -> Outcome<Execution> {
    let operation = "decode_android_resources";
    let selection = resolve_command(env).map_err(|c| fallback_config_error(operation, &c))?;
    let version = inspect_client(&selection, env, cancel).map_err(|c| capability(operation, &c))?;
    let client = json!({ "command": selection.command, "command_source": selection.source, "apktool_version": version });
    let provider_identity = provider(version.as_deref());
    let workspace = Workspace {
        root: tempfile::Builder::new().prefix("rea-apktool-").rand_bytes(6).tempdir().map_err(|e| {
            Error::from(Failure::Protocol { message: format!("Apktool resource projection failed: {e}") })
        })?,
    };
    let root = workspace.root.path();
    let decoded_dir = root.join("decoded");
    let snapshot = root.join("input.apk");
    let framework = root.join("framework");
    // Source admission: copy the APK once, hashing while copying.
    let sha256 = {
        let mut source = std::fs::File::open(input_path).map_err(|_| analysis_input_error(operation))?;
        let size = source.metadata().map_err(|_| analysis_input_error(operation))?.len();
        if !source.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err(analysis_input_error(operation));
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&snapshot)
            .map_err(|e| Error::from(Failure::Protocol { message: format!("Apktool resource projection failed: {e}") }))?;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        let mut copied = 0u64;
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            if cancel.is_cancelled() {
                return Err(Failure::Cancelled { operation: operation.to_string() }.into());
            }
            let read = source.read(&mut buffer).map_err(|_| analysis_input_error(operation))?;
            if read == 0 {
                break;
            }
            copied += read as u64;
            if copied > size {
                return Err(analysis_input_error(operation));
            }
            sha2::Digest::update(&mut hasher, &buffer[..read]);
            std::io::Write::write_all(&mut output, &buffer[..read]).map_err(|_| analysis_input_error(operation))?;
        }
        if copied != size {
            return Err(analysis_input_error(operation));
        }
        hex::encode(sha2::Digest::finalize(hasher))
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o400));
    }
    let snapshot_bytes = std::fs::metadata(&snapshot).map(|m| m.len()).unwrap_or(0);
    std::fs::create_dir(&decoded_dir).ok();
    std::fs::create_dir(&framework).ok();
    let decoded_arg = decoded_dir.to_string_lossy().into_owned();
    let framework_arg = framework.to_string_lossy().into_owned();
    let snapshot_arg = snapshot.to_string_lossy().into_owned();
    let output = run(
        &selection.command,
        &["d", "--no-src", "-f", "-o", &decoded_arg, "--frame-path", &framework_arg, &snapshot_arg],
        env,
        DECODE_TIMEOUT,
        DECODE_MAX_OUTPUT_BYTES,
        cancel,
    );
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            return Err(Failure::Protocol { message: format!("apktool failed for {operation}: {error}") }.into());
        }
    };
    let captured = |output: &Captured| {
        json!({
            "stdout": text(&output.stdout),
            "stderr": text(&output.stderr),
            "truncated": false,
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "exit_code": output.exit,
            "signal": output.signal.map(|s| format!("SIG{s}")),
        })
    };
    if output.cancelled {
        return Err(Failure::Cancelled { operation: operation.to_string() }.into());
    }
    if output.timed_out {
        return Err(Failure::Timeout { operation: operation.to_string(), timeout_ms: DECODE_TIMEOUT.as_millis() as u64, captured_output: Some(captured(&output)) }.into());
    }
    if output.output_limit {
        return Err(Failure::ResourceConstraint {
            operation: operation.to_string(),
            resource: "memory".to_string(),
            reason: format!("apktool output exceeded the {DECODE_MAX_OUTPUT_BYTES}-byte capture budget"),
            limits: json!({ "max_output_bytes": DECODE_MAX_OUTPUT_BYTES }),
            captured_output: Some(captured(&output)),
        }
        .into());
    }
    if output.exit != Some(0) {
        let stderr_text = text(&output.stderr);
        let excerpt: String = stderr_text.trim().chars().take(STDERR_EXCERPT_BYTES).collect();
        let reason = if excerpt.is_empty() {
            format!("apktool exited with code {} for {operation}", output.exit.map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string()))
        } else {
            excerpt
        };
        return Err(Failure::UnsupportedTarget {
            operation: operation.to_string(),
            path: selection.command.clone(),
            reason,
            captured_output: Some(captured(&output)),
        }
        .into());
    }
    let protocol = |message: String| -> Error { Failure::Protocol { message }.into() };
    let (yml_text, yml_truncated) = read_bounded_text(&decoded_dir.join("apktool.yml"), MANIFEST_MAX_BYTES)
        .map_err(|e| protocol(format!("Apktool resource projection failed: {e}")))?;
    let Some(yml) = yml_text.filter(|_| !yml_truncated) else {
        return Err(protocol(format!("apktool produced missing or oversized apktool.yml: {input_path}")));
    };
    let [version_name, version_code, min_sdk, target_sdk] = parse_apktool_yml(&yml);
    let (manifest, manifest_truncated) = read_bounded_text(&decoded_dir.join("AndroidManifest.xml"), MANIFEST_MAX_BYTES)
        .map_err(|e| protocol(format!("Apktool resource projection failed: {e}")))?;
    let package_name = manifest.as_deref().and_then(parse_manifest_package);
    let strings_directory = match locale {
        None => "values".to_string(),
        Some(locale) => format!("values-{}", locale_qualifier(locale)),
    };
    let (strings_text, strings_truncated) = if include_strings {
        read_bounded_text(&decoded_dir.join("res").join(&strings_directory).join("strings.xml"), STRINGS_XML_MAX_BYTES)
            .map_err(|e| protocol(format!("Apktool resource projection failed: {e}")))?
    } else {
        (None, false)
    };
    let strings_xml = if strings_truncated { None } else { strings_text.clone() };
    let (entries, unparsed) = match &strings_xml {
        Some(xml) => parse_decoded_strings(xml),
        None => (vec![], 0),
    };
    let bounded: Vec<Value> = entries.iter().take(MAX_STRINGS).map(|(name, value)| json!({ "name": name, "value": value })).collect();
    let (file_count, capped, locales) =
        count_decoded_files(&decoded_dir).map_err(|e| protocol(format!("Apktool resource projection failed: {e}")))?;
    let coverage = if (strings_xml.is_some() && entries.len() > MAX_STRINGS) || manifest_truncated || strings_truncated || unparsed > 0 || capped {
        "partial"
    } else {
        "complete"
    };
    let mut limitations = vec!["Decoding skips smali (--no-src); Java-source recovery belongs to the JADX family".to_string()];
    if let Some(locale) = locale {
        if strings_text.is_none() && include_strings {
            limitations.push(format!("No strings.xml was found for locale {locale}"));
        }
    }
    if include_strings && strings_text.is_none() && locale.is_none() {
        limitations.push("No default res/values/strings.xml was found in the decoded workspace".to_string());
    }
    if unparsed > 0 {
        limitations.push(format!("{unparsed} string entries with nested markup were not projected"));
    }
    if entries.len() > MAX_STRINGS {
        limitations.push(format!("strings reports the first {MAX_STRINGS} of {} entries", entries.len()));
    }
    if manifest_truncated {
        limitations.push(format!("manifest is truncated at {MANIFEST_MAX_BYTES} bytes"));
    }
    if strings_truncated {
        limitations.push(format!("strings.xml exceeds the {STRINGS_XML_MAX_BYTES}-byte projection budget"));
    }
    if capped {
        limitations.push(format!(
            "Decoded workspace enumeration stopped after {MAX_DECODED_ENTRIES_VISITED} entries; decoded_file_count and locales may be partial"
        ));
    }
    drop(workspace);
    let _ = sha256_file;
    Ok(Execution {
        result: json!({
            "client": client,
            "target": { "path": input_path, "bytes": snapshot_bytes, "sha256": sha256 },
            "metadata": {
                "version_name": version_name,
                "version_code": version_code,
                "min_sdk_version": min_sdk,
                "target_sdk_version": target_sdk,
                "package_name": package_name,
            },
            "manifest": manifest,
            "strings": bounded,
            "locale": locale,
            "locales": locales,
            "decoded_file_count": file_count,
            "coverage": coverage,
        }),
        provider: provider_identity,
        limitations,
    })
}

/// Node-style description for an unreadable APK path.
pub fn describe_unreadable(path: &str, error: &std::io::Error) -> String {
    node_fs_error(error, "open", path)
}
