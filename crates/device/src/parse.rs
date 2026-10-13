//! Parsers for the adb, Package Manager and toybox output formats REA consumes.
//!
//! Direct port of REA `AdbConfiguration.ts` (version output), `AdbDeviceOutput.ts`
//! and `AdbShellOutput.ts`. JavaScript regexes use the `u` flag where `\d` is
//! ASCII only and `.` excludes every line terminator; the Rust patterns spell
//! those out so the same lines match.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::input::is_js_whitespace;

/// Class equivalent to JavaScript's `.` (no line terminators).
const DOT: &str = r"[^\n\r\u{2028}\u{2029}]";

fn re(cell: &'static OnceLock<Regex>, pattern: impl FnOnce() -> String) -> &'static Regex {
    cell.get_or_init(|| Regex::new(&pattern()).expect("static pattern"))
}

/// `String.prototype.trim`.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// `String.prototype.trimEnd`.
pub fn js_trim_end(text: &str) -> &str {
    text.trim_end_matches(is_js_whitespace)
}

/// `text.split(/\r?\n/u)`.
pub fn split_lines(text: &str) -> Vec<&str> {
    text.split('\n').map(|line| line.strip_suffix('\r').unwrap_or(line)).collect()
}

/// `text.slice(0, count)` over UTF-16 code units (never splitting a code point).
pub fn slice_utf16(text: &str, count: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars() {
        used += c.len_utf16();
        if used > count {
            break;
        }
        out.push(c);
    }
    out
}

fn number_value(digits: &str) -> Value {
    match digits.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(digits.parse::<f64>().unwrap_or(0.0)),
    }
}

fn safe_integer(digits: &str) -> Option<Value> {
    match digits.parse::<u64>() {
        Ok(n) if n <= 9_007_199_254_740_991 => Some(json!(n)),
        _ => None,
    }
}

// ------------------------------------------------------------ adb version --

pub struct ClientIdentity {
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

/// `parseAdbVersionOutput`.
pub fn parse_adb_version_output(stdout: &str) -> ClientIdentity {
    static BUILD: OnceLock<Regex> = OnceLock::new();
    static INSTALLED: OnceLock<Regex> = OnceLock::new();
    let build = re(&BUILD, || format!(r"(?mR)^Version\s+(\S{DOT}*)$"));
    let installed = re(&INSTALLED, || format!(r"(?mR)^Installed as\s+({DOT}+)$"));
    ClientIdentity {
        version: build.captures(stdout).map(|c| js_trim(&c[1]).to_string()),
        installed_path: installed.captures(stdout).map(|c| js_trim(&c[1]).to_string()),
    }
}

// ---------------------------------------------------------- adb devices -l --

const DEVICE_STATES: [&str; 11] = [
    "no permissions",
    "unauthorized",
    "authorizing",
    "offline",
    "recovery",
    "sideload",
    "connecting",
    "bootloader",
    "device",
    "unknown",
    "host",
];

fn metadata_value(remainder: &str, key: &str) -> Option<String> {
    let pattern = Regex::new(&format!(r"(?:^|\s){}:(\S+)", regex::escape(key))).expect("metadata pattern");
    pattern.captures(remainder).map(|c| c[1].to_string())
}

pub struct DevicesParse {
    pub devices: Vec<Value>,
    pub unparsed_lines: Vec<String>,
    pub daemon_started: bool,
}

/// `parseAdbDevicesOutput`.
pub fn parse_adb_devices_output(stdout: &str) -> DevicesParse {
    static LINE: OnceLock<Regex> = OnceLock::new();
    static EMULATOR: OnceLock<Regex> = OnceLock::new();
    static DIGITS: OnceLock<Regex> = OnceLock::new();
    let device_line = re(&LINE, || format!(r"^(\S+)\s+({DOT}*)$"));
    let emulator_re = re(&EMULATOR, || r"^emulator-[0-9]+$".to_string());
    let digits_re = re(&DIGITS, || r"^[0-9]+$".to_string());
    let mut devices = Vec::new();
    let mut unparsed = Vec::new();
    let mut daemon_started = false;
    for raw in split_lines(stdout) {
        let line = js_trim_end(raw);
        if line.is_empty() || line.starts_with("List of devices attached") {
            continue;
        }
        if line.starts_with("* daemon") {
            if line.contains("started successfully") {
                daemon_started = true;
            }
            continue;
        }
        let captures = device_line.captures(line);
        let state = captures
            .as_ref()
            .and_then(|c| DEVICE_STATES.iter().find(|candidate| c[2].starts_with(**candidate)));
        let (Some(captures), Some(state)) = (captures, state) else {
            if !js_trim(line).is_empty() {
                unparsed.push(line.to_string());
            }
            continue;
        };
        let serial = captures[1].to_string();
        let remainder = &captures[2][state.len()..];
        let usb = metadata_value(remainder, "usb");
        let transport_id_text = metadata_value(remainder, "transport_id");
        let transport_id = match &transport_id_text {
            Some(text) if digits_re.is_match(text) => Some(number_value(text)),
            _ => None,
        };
        let is_emulator = emulator_re.is_match(&serial);
        let kind = if is_emulator {
            "emulator"
        } else if usb.is_some() {
            "physical"
        } else {
            "unknown"
        };
        let transport = if usb.is_some() {
            "usb"
        } else if is_emulator || serial.contains(':') {
            "tcp"
        } else {
            "unknown"
        };
        devices.push(json!({
            "serial": serial,
            "state": state,
            "transport": transport,
            "product": metadata_value(remainder, "product"),
            "model": metadata_value(remainder, "model"),
            "device": metadata_value(remainder, "device"),
            "transport_id": transport_id,
            "kind": kind,
            "kind_basis": match kind {
                "emulator" => "emulator_serial_prefix",
                "physical" => "usb_transport",
                _ => "none",
            },
        }));
    }
    DevicesParse { devices, unparsed_lines: unparsed, daemon_started }
}

// ----------------------------------------------------------------- getprop --

const PROPERTY_WHITELIST: [&str; 13] = [
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.build.characteristics",
    "ro.debuggable",
    "ro.kernel.qemu",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.cpu.abilist",
];

/// `parseGetpropOutput`: (properties, emulator_observed).
pub fn parse_getprop_output(stdout: &str) -> (Vec<Value>, Option<bool>) {
    static PROP: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&PROP, || format!(r"^\[([^\]]+)\]:\s*\[({DOT}*)\]$"));
    let mut values: Vec<(String, String)> = Vec::new();
    for raw in split_lines(stdout) {
        if let Some(c) = pattern.captures(js_trim(raw)) {
            let name = c[1].to_string();
            let value = c[2].to_string();
            if let Some(slot) = values.iter_mut().find(|(n, _)| *n == name) {
                slot.1 = value;
            } else {
                values.push((name, value));
            }
        }
    }
    let lookup = |name: &str| values.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    let properties = PROPERTY_WHITELIST
        .iter()
        .filter_map(|name| match lookup(name) {
            Some(value) if !value.is_empty() => Some(json!({ "name": name, "value": value })),
            _ => None,
        })
        .collect();
    let emulator = lookup("ro.kernel.qemu").map(|value| value == "1");
    (properties, emulator)
}

// ------------------------------------------------------------ pm list etc --

/// `parsePackageListOutput`.
pub fn parse_package_list_output(stdout: &str) -> (Vec<Value>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || format!(r"^package:({DOT}+)=([^\s=]+)$"));
    let mut packages = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim(raw);
        if line.is_empty() {
            continue;
        }
        match pattern.captures(line) {
            None => unparsed.push(line.to_string()),
            Some(c) => packages.push(json!({
                "package_name": &c[2],
                "base_apk_device_path": &c[1],
            })),
        }
    }
    (packages, unparsed)
}

pub struct PmPathEntry {
    pub device_path: String,
    pub file_name: String,
    pub role: &'static str,
}

/// `parsePmPathOutput`.
pub fn parse_pm_path_output(stdout: &str) -> (Vec<PmPathEntry>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || r"^package:(\S+)$".to_string());
    let mut paths = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim(raw);
        if line.is_empty() {
            continue;
        }
        let Some(c) = pattern.captures(line) else {
            unparsed.push(line.to_string());
            continue;
        };
        let device_path = c[1].to_string();
        let file_name = device_path.rsplit('/').next().unwrap_or(&device_path).to_string();
        let role = if file_name == "base.apk" {
            "base"
        } else if file_name.starts_with("split_") && file_name.ends_with(".apk") {
            "split"
        } else {
            "unknown"
        };
        paths.push(PmPathEntry { device_path, file_name, role });
    }
    (paths, unparsed)
}

// ----------------------------------------------------------------- ps -A --

/// `parseProcessListOutput`: (columns, processes, unparsed).
pub fn parse_process_list_output(stdout: &str) -> (Option<String>, Vec<Value>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    static HEADER: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || {
        format!(r"^(\S+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+({DOT}+)$")
    });
    let header = re(&HEADER, || r"^USER\s+PID\s+PPID\b".to_string());
    let mut columns = None;
    let mut processes = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim_end(raw);
        if line.is_empty() {
            continue;
        }
        if header.is_match(line) {
            columns = Some(js_trim(line).to_string());
            continue;
        }
        let Some(c) = pattern.captures(line) else {
            unparsed.push(line.to_string());
            continue;
        };
        processes.push(json!({
            "user": &c[1],
            "pid": number_value(&c[2]),
            "ppid": safe_integer(&c[3]),
            "rss": safe_integer(&c[5]),
            "state": &c[8],
            "name": js_trim(&c[9]),
        }));
    }
    (columns, processes, unparsed)
}

// -------------------------------------------------------------------- ls --

/// `parseLsOutput`.
pub fn parse_ls_output(stdout: &str) -> (Vec<Value>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || {
        format!(
            r"^([bcdlps-][rwxstST-]{{9}})\s+(?:([0-9]+)\s+)?(\S+)\s+(\S+)\s+(?:([0-9]+)\s+)?([0-9-]{{10}})\s+([0-9:]{{4,8}})\s+({DOT}+)$"
        )
    });
    let mut entries = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim_end(raw);
        if line.is_empty() || line.starts_with("total ") {
            continue;
        }
        let Some(c) = pattern.captures(line) else {
            if !js_trim(line).is_empty() {
                unparsed.push(line.to_string());
            }
            continue;
        };
        let permissions = c[1].to_string();
        let mut name = js_trim(&c[8]).to_string();
        let mut link_target = None;
        if let Some(arrow) = name.find(" -> ") {
            if permissions.starts_with('l') {
                link_target = Some(name[arrow + 4..].to_string());
                name.truncate(arrow);
            }
        }
        let kind = if permissions.starts_with('d') {
            "directory"
        } else if permissions.starts_with('l') {
            "symlink"
        } else if permissions.starts_with('-') {
            "file"
        } else {
            "other"
        };
        let date = js_trim(&format!("{} {}", &c[6], &c[7])).to_string();
        entries.push(json!({
            "name": name,
            "kind": kind,
            "permissions": permissions,
            "owner": &c[3],
            "group": &c[4],
            "bytes": c.get(5).map(|m| number_value(m.as_str())),
            "date": if date.is_empty() { Value::Null } else { json!(date) },
            "link_target": link_target,
        }));
    }
    (entries, unparsed)
}

// ---------------------------------------------------------- pm list features --

/// `parseFeatureListOutput`.
pub fn parse_feature_list_output(stdout: &str) -> (Vec<Value>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || r"^feature:([^=\s]+)(?:=(0x[0-9a-fA-F]+|[0-9]+))?$".to_string());
    let mut features = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim(raw);
        if line.is_empty() {
            continue;
        }
        let Some(c) = pattern.captures(line) else {
            unparsed.push(line.to_string());
            continue;
        };
        let version = c.get(2).map(|m| {
            let text = m.as_str();
            match text.strip_prefix("0x") {
                Some(hex_digits) => match u64::from_str_radix(hex_digits, 16) {
                    Ok(n) => json!(n),
                    Err(_) => json!(0),
                },
                None => number_value(text),
            }
        });
        features.push(json!({ "name": &c[1], "version": version }));
    }
    (features, unparsed)
}

// --------------------------------------------------------- service list --

/// `parseServiceListOutput`.
pub fn parse_service_list_output(stdout: &str) -> (Vec<Value>, Vec<String>) {
    static LINE: OnceLock<Regex> = OnceLock::new();
    static FOUND: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || r"^\s*(?:[0-9]+\s+)?([A-Za-z0-9._$/-]+):\s*\[([^\]]*)\]\s*$".to_string());
    let found = re(&FOUND, || r"^Found [0-9]+ services:".to_string());
    let mut services = Vec::new();
    let mut unparsed = Vec::new();
    for raw in split_lines(stdout) {
        let line = js_trim_end(raw);
        if js_trim(line).is_empty() || found.is_match(js_trim(line)) {
            continue;
        }
        let Some(c) = pattern.captures(line) else {
            if !js_trim(line).is_empty() {
                unparsed.push(js_trim(line).to_string());
            }
            continue;
        };
        services.push(json!({
            "name": &c[1],
            "interface": if c[2].is_empty() { Value::Null } else { json!(&c[2]) },
        }));
    }
    (services, unparsed)
}

// --------------------------------------------------------------- wm size --

/// `parseWmSizeOutput`: (physical, override).
pub fn parse_wm_size_output(stdout: &str) -> (Option<Value>, Option<Value>) {
    static PHYSICAL: OnceLock<Regex> = OnceLock::new();
    static OVERRIDE: OnceLock<Regex> = OnceLock::new();
    let physical_re = re(&PHYSICAL, || r"^Physical size:\s+([0-9]+)x([0-9]+)$".to_string());
    let override_re = re(&OVERRIDE, || r"^Override size:\s+([0-9]+)x([0-9]+)$".to_string());
    let mut physical = None;
    let mut override_ = None;
    for line in split_lines(stdout) {
        let trimmed = js_trim(line);
        if let Some(c) = physical_re.captures(trimmed) {
            physical = Some(json!({ "width": number_value(&c[1]), "height": number_value(&c[2]) }));
        }
        if let Some(c) = override_re.captures(trimmed) {
            override_ = Some(json!({ "width": number_value(&c[1]), "height": number_value(&c[2]) }));
        }
    }
    (physical, override_)
}

/// `parseWmDensityOutput`: (physical, override).
pub fn parse_wm_density_output(stdout: &str) -> (Option<Value>, Option<Value>) {
    static PHYSICAL: OnceLock<Regex> = OnceLock::new();
    static OVERRIDE: OnceLock<Regex> = OnceLock::new();
    let physical_re = re(&PHYSICAL, || r"^Physical density:\s+([0-9]+)$".to_string());
    let override_re = re(&OVERRIDE, || r"^Override density:\s+([0-9]+)$".to_string());
    let mut physical = None;
    let mut override_ = None;
    for line in split_lines(stdout) {
        let trimmed = js_trim(line);
        if let Some(c) = physical_re.captures(trimmed) {
            physical = Some(number_value(&c[1]));
        }
        if let Some(c) = override_re.captures(trimmed) {
            override_ = Some(number_value(&c[1]));
        }
    }
    (physical, override_)
}

/// `parseWindowFocusOutput`: (focused_window, focused_app).
pub fn parse_window_focus_output(stdout: &str) -> (Option<String>, Option<String>) {
    let mut window = None;
    let mut app = None;
    for line in split_lines(stdout) {
        let trimmed = js_trim(line);
        if window.is_none() {
            if let Some(rest) = trimmed.strip_prefix("mCurrentFocus=") {
                window = Some(js_trim(rest).to_string());
            }
        }
        if app.is_none() {
            if let Some(rest) = trimmed.strip_prefix("mFocusedApp=") {
                app = Some(js_trim(rest).to_string());
            }
        }
    }
    (window, app)
}

// ------------------------------------------------------- dumpsys package --

#[derive(Default)]
pub struct PackageDetails {
    pub version_name: Option<String>,
    pub version_code: Option<Value>,
    pub first_install_time: Option<String>,
    pub last_update_time: Option<String>,
    pub installer_package_name: Option<String>,
    pub user_id: Option<Value>,
    pub pkg_flags: Option<String>,
    pub requested_permissions: u64,
}

/// `parseDumpsysPackageOutput`.
pub fn parse_dumpsys_package_output(stdout: &str) -> PackageDetails {
    static DETAIL: OnceLock<Regex> = OnceLock::new();
    static PERMISSION: OnceLock<Regex> = OnceLock::new();
    static LEADING: OnceLock<Regex> = OnceLock::new();
    let detail = re(&DETAIL, || format!(r"^\s+([A-Za-z][A-Za-z0-9_]*)=({DOT}*)$"));
    let permission = re(&PERMISSION, || r"^\s{2,}[A-Za-z0-9._]+$".to_string());
    let leading = re(&LEADING, || r"^([0-9]+)".to_string());
    let mut details = PackageDetails::default();
    let mut in_permissions = false;
    let non_empty = |value: &str| if value.is_empty() { None } else { Some(value.to_string()) };
    for line in split_lines(stdout) {
        if js_trim(line).starts_with("requested permissions:") {
            in_permissions = true;
            continue;
        }
        if in_permissions && permission.is_match(line) {
            details.requested_permissions += 1;
            continue;
        }
        in_permissions = false;
        let Some(c) = detail.captures(line) else { continue };
        let key = &c[1];
        let value = js_trim(&c[2]);
        if key == "versionName" && details.version_name.is_none() {
            details.version_name = non_empty(value);
        } else if key == "versionCode" && details.version_code.is_none() {
            if let Some(p) = leading.captures(value) {
                details.version_code = Some(number_value(&p[1]));
            }
        } else if key == "firstInstallTime" && details.first_install_time.is_none() {
            details.first_install_time = non_empty(value);
        } else if key == "lastUpdateTime" && details.last_update_time.is_none() {
            details.last_update_time = non_empty(value);
        } else if key == "installerPackageName" && details.installer_package_name.is_none() {
            details.installer_package_name = non_empty(value);
        } else if key == "userId" && details.user_id.is_none() {
            if let Some(p) = leading.captures(value) {
                details.user_id = Some(number_value(&p[1]));
            }
        } else if key == "pkgFlags" && details.pkg_flags.is_none() {
            details.pkg_flags = non_empty(value);
        }
    }
    details
}

/// `parseSettingsGetOutput`: (value, device_reported_null).
pub fn parse_settings_get_output(stdout: &str) -> (Option<String>, bool) {
    let trimmed = match stdout.strip_suffix('\n') {
        Some(rest) => rest.strip_suffix('\r').unwrap_or(rest),
        None => stdout,
    };
    if trimmed == "null" {
        (None, true)
    } else {
        (Some(trimmed.to_string()), false)
    }
}

/// `parseBugreportCopiedPath`.
pub fn parse_bugreport_copied_path(stdout: &str) -> Option<String> {
    static LINE: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&LINE, || format!(r"(?mR)^Bug report copied to ({DOT}+)\r?$"));
    pattern.captures(js_trim(stdout)).map(|c| c[1].to_string())
}

/// `parsePackageChangeOutput`: (success, reason).
pub fn parse_package_change_output(stdout: &str) -> (bool, Option<String>) {
    static SUCCESS: OnceLock<Regex> = OnceLock::new();
    static FAILURE: OnceLock<Regex> = OnceLock::new();
    let success = re(&SUCCESS, || r"(?mR)^Success$".to_string());
    let failure = re(&FAILURE, || r"Failure \[([^\]]+)\]".to_string());
    let text = js_trim(stdout);
    if success.is_match(text) {
        return (true, None);
    }
    let reason = match failure.captures(text) {
        Some(c) => Some(c[1].to_string()),
        None if text.is_empty() => None,
        None => Some(slice_utf16(text, 512)),
    };
    (false, reason)
}

/// `parseResolveActivityOutput`.
pub fn parse_resolve_activity_output(stdout: &str) -> Option<String> {
    let lines: Vec<&str> = split_lines(stdout)
        .into_iter()
        .map(js_trim)
        .filter(|line| !line.is_empty() && !line.eq_ignore_ascii_case("No activity found"))
        .collect();
    lines.last().map(|line| line.to_string())
}

pub struct AmStart {
    pub started: bool,
    pub started_activity: Option<String>,
    pub reason: Option<String>,
}

/// `parseAmStartOutput`.
pub fn parse_am_start_output(stdout: &str) -> AmStart {
    static STARTING: OnceLock<Regex> = OnceLock::new();
    static ERROR: OnceLock<Regex> = OnceLock::new();
    let starting = re(&STARTING, || format!(r"(?mR)^Starting:\s+Intent\s*\{{({DOT}*)\}}\s*$"));
    let error = re(&ERROR, || format!(r"(?mR)^(?:Error|Warning|Exception)(?::|\b)({DOT}*)$"));
    let text = js_trim(stdout);
    if let Some(c) = starting.captures(text) {
        return AmStart { started: true, started_activity: Some(js_trim(&c[1]).to_string()), reason: None };
    }
    let reason = match error.captures(text) {
        Some(c) => js_trim(&c[1]).to_string(),
        None if text.is_empty() => "am start returned no activity".to_string(),
        None => slice_utf16(text, 512),
    };
    AmStart { started: false, started_activity: None, reason: Some(reason) }
}

/// `parsePngDimensions`: (width, height) from the IHDR of a PNG payload.
pub fn parse_png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.len() < 24 || bytes[..8] != SIGNATURE {
        return None;
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    Some((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_with_crlf() {
        let id = parse_adb_version_output("Android Debug Bridge version 1.0.41\r\nVersion 34.0.5-debian\r\nInstalled as /x/adb\r\n");
        assert_eq!(id.version.as_deref(), Some("34.0.5-debian"));
        assert_eq!(id.installed_path.as_deref(), Some("/x/adb"));
    }

    #[test]
    fn ls_line_symlink() {
        let (entries, unparsed) =
            parse_ls_output("total 8\nlrwxrwxrwx 1 shell shell 9 2026-01-01 10:00 link -> notes.txt\nbogus\n");
        assert_eq!(entries[0]["link_target"], "notes.txt");
        assert_eq!(entries[0]["kind"], "symlink");
        assert_eq!(unparsed, vec!["bogus".to_string()]);
    }

    #[test]
    fn utf16_slice_never_splits_code_points() {
        assert_eq!(slice_utf16("a\u{1F600}b", 2), "a");
        assert_eq!(slice_utf16("a\u{1F600}b", 3), "a\u{1F600}");
    }
}
