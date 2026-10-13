//! Inspection of a bring-your-own Ghidra installation and JDK (port of
//! `ghidra/GhidraInstallation*.ts`, POSIX hosts only).

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

/// Ghidra build whose bridge behavior is verified.
pub const SUPPORTED_GHIDRA_VERSION: &str = "12.1.4";
/// JDK major used when an installation omits `application.java.min`.
pub const SUPPORTED_GHIDRA_JAVA_MAJOR: u32 = 21;

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub code: Option<&'static str>,
    pub detail: String,
    pub remediation: String,
}

impl Check {
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "ok": self.passed,
            "code": if self.passed { Value::Null } else { json!(self.code) },
            "detail": self.detail,
        })
    }
}

#[derive(Debug, Clone)]
pub struct JavaObservation {
    pub version: String,
    pub major: u32,
    pub home: String,
    pub bits: u32,
    pub jdk: bool,
}

#[derive(Debug, Clone)]
pub struct GhidraInstallation {
    pub available: bool,
    pub platform: &'static str,
    pub architecture: &'static str,
    pub install_dir: Option<String>,
    pub analyze_headless_path: Option<String>,
    pub native_decompiler_path: Option<String>,
    pub application_properties_path: Option<String>,
    pub provider_version: Option<String>,
    pub java_command: String,
    pub java_home: Option<String>,
    pub java_version: Option<String>,
    pub checks: Vec<Check>,
    pub rejection: Option<(&'static str, String)>,
}

impl GhidraInstallation {
    pub fn diagnostics(&self) -> Value {
        json!({
            "install_dir": self.install_dir,
            "analyze_headless_path": self.analyze_headless_path,
            "native_decompiler_path": self.native_decompiler_path,
            "application_properties_path": self.application_properties_path,
            "provider_version": self.provider_version,
            "java_command": self.java_command,
            "java_home": self.java_home,
            "java_version": self.java_version,
            "platform": self.platform,
            "architecture": self.architecture,
            "checks": self.checks.iter().map(Check::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Parsed `application.properties` values we depend on.
#[derive(Debug, Clone, Default)]
pub struct ApplicationProperties {
    pub provider_version: Option<String>,
    pub java_min: Bound,
    pub java_max: Bound,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Bound {
    #[default]
    Absent,
    Major(u32),
    Unresolved(String),
}

fn property(content: &str, name: &str) -> Option<String> {
    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == name {
                let value = value.trim();
                return if value.is_empty() { None } else { Some(value.to_string()) };
            }
        }
    }
    None
}

fn parse_bound(raw: Option<String>) -> Bound {
    match raw {
        None => Bound::Absent,
        Some(raw) => {
            let ok = !raw.is_empty()
                && raw.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
            if ok {
                match raw.split('.').next().and_then(|p| p.parse::<u32>().ok()) {
                    Some(major) => Bound::Major(major),
                    None => Bound::Unresolved(raw),
                }
            } else {
                Bound::Unresolved(raw)
            }
        }
    }
}

pub fn application_properties(content: &str) -> ApplicationProperties {
    ApplicationProperties {
        provider_version: property(content, "application.version"),
        java_min: parse_bound(property(content, "application.java.min")),
        java_max: parse_bound(property(content, "application.java.max")),
    }
}

#[derive(Debug, PartialEq)]
enum Compatibility {
    Verified,
    Compatible,
    Unsupported,
    Unresolved,
}

fn parse_release(raw: &str) -> Option<(u32, u32, u32)> {
    let re = regex::Regex::new(r"^(\d+)\.(\d+)(?:\.(\d+))?([-+].*)?$").ok()?;
    let c = re.captures(raw)?;
    let major = c.get(1)?.as_str().parse().ok()?;
    let minor = c.get(2)?.as_str().parse().ok()?;
    let patch = match c.get(3) {
        Some(p) => p.as_str().parse().ok()?,
        None => 0,
    };
    Some((major, minor, patch))
}

fn release_compatibility(raw: Option<&str>) -> Compatibility {
    let Some(raw) = raw else {
        return Compatibility::Unresolved;
    };
    let Some(version) = parse_release(raw) else {
        return Compatibility::Unresolved;
    };
    if raw == SUPPORTED_GHIDRA_VERSION {
        return Compatibility::Verified;
    }
    let verified = parse_release(SUPPORTED_GHIDRA_VERSION).unwrap();
    if version.0 == verified.0 && version.1 == verified.1 {
        Compatibility::Compatible
    } else {
        Compatibility::Unsupported
    }
}

pub fn release_line() -> String {
    let v = parse_release(SUPPORTED_GHIDRA_VERSION).unwrap();
    format!("{}.{}.x", v.0, v.1)
}

/// Limitation recorded when a session runs a compatible build other than the verified one.
pub fn unverified_build_limitation(version: &str) -> Option<String> {
    if release_compatibility(Some(version)) == Compatibility::Compatible {
        Some(format!(
            "This session uses Ghidra {version}. The bridge is verified against {SUPPORTED_GHIDRA_VERSION}; other {} builds are accepted and the observed version is reported.",
            release_line()
        ))
    } else {
        None
    }
}

fn version_detail(raw: Option<&str>) -> String {
    match release_compatibility(raw) {
        Compatibility::Unresolved => raw.unwrap_or("unknown").to_string(),
        Compatibility::Verified => raw.unwrap_or_default().to_string(),
        Compatibility::Compatible => format!(
            "{}; compatible {} release (verified build {SUPPORTED_GHIDRA_VERSION})",
            raw.unwrap_or_default(),
            release_line()
        ),
        Compatibility::Unsupported => format!(
            "{}; accepted releases are {} (verified build {SUPPORTED_GHIDRA_VERSION})",
            raw.unwrap_or_default(),
            release_line()
        ),
    }
}

struct JavaRequirement {
    minimum: u32,
    maximum: Option<u32>,
    unresolved: Option<String>,
}

fn java_requirement(props: Option<&ApplicationProperties>) -> JavaRequirement {
    let min = props.map(|p| p.java_min.clone()).unwrap_or_default();
    let max = props.map(|p| p.java_max.clone()).unwrap_or_default();
    let unresolved = |reason: String| JavaRequirement {
        minimum: SUPPORTED_GHIDRA_JAVA_MAJOR,
        maximum: None,
        unresolved: Some(reason),
    };
    if let Bound::Unresolved(raw) = &min {
        return unresolved(format!("application.java.min={raw}"));
    }
    if let Bound::Unresolved(raw) = &max {
        return unresolved(format!("application.java.max={raw}"));
    }
    let minimum = if let Bound::Major(m) = min { m } else { SUPPORTED_GHIDRA_JAVA_MAJOR };
    let maximum = if let Bound::Major(m) = max { Some(m) } else { None };
    if let Some(maximum) = maximum {
        if maximum < minimum {
            return unresolved(format!(
                "application.java.max={maximum} is below application.java.min={minimum}"
            ));
        }
    }
    JavaRequirement {
        minimum,
        maximum,
        unresolved: None,
    }
}

fn java_range_label(req: &JavaRequirement) -> String {
    if req.unresolved.is_some() {
        return "a 64-bit full JDK matching the installation's declared Java bounds".to_string();
    }
    match req.maximum {
        None => format!("a 64-bit full JDK {} or newer", req.minimum),
        Some(max) if max == req.minimum => format!("a 64-bit full JDK {}", req.minimum),
        Some(max) => format!("a 64-bit full JDK {} through {}", req.minimum, max),
    }
}

fn native_platform(arch: &str) -> Option<&'static str> {
    match arch {
        "x64" => Some("linux_x86_64"),
        "arm64" => Some("linux_arm_64"),
        _ => None,
    }
}

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "arm" => "arm",
        other => other,
    }
}

fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn java_environment(java_home: Option<&str>, env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = env.clone();
    for key in ["_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "GHIDRA_JAVA_OPTIONS"] {
        out.insert(key.to_string(), String::new());
    }
    if let Some(home) = java_home {
        out.insert("JAVA_HOME".to_string(), home.to_string());
        let path = out.get("PATH").cloned().unwrap_or_default();
        out.insert("PATH".to_string(), format!("{home}/bin:{path}"));
    }
    out
}

/// Environment that makes an explicitly selected JDK win over PATH discovery.
pub fn ghidra_java_environment(
    java_home: Option<&str>,
    env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    java_environment(java_home, env)
}

fn probe_java(command: &str, env: &BTreeMap<String, String>) -> Option<JavaObservation> {
    let mut child = Command::new(command)
        .args(["-XX:-UsePerfData", "-XshowSettings:properties", "-version"])
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // Bounded wait (REA allows 5 seconds).
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() > std::time::Duration::from_secs(5) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let prop = |name: &str| -> Option<String> {
        let re = regex::Regex::new(&format!(r"(?m)^\s*{}\s*=\s*(.+?)\s*$", regex::escape(name))).ok()?;
        re.captures(&text).map(|c| c[1].to_string())
    };
    let version = prop("java.version")?;
    let home = prop("java.home")?;
    let bits = prop("sun.arch.data.model")
        .and_then(|b| b.parse().ok())
        .unwrap_or(0);
    let first: u32 = version.split('.').next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let major = if first != 1 {
        first
    } else {
        version.split('.').nth(1).and_then(|p| p.parse().ok()).unwrap_or(0)
    };
    let jdk = is_executable_file(&Path::new(&home).join("bin").join("javac"));
    Some(JavaObservation {
        version,
        major,
        home,
        bits,
        jdk,
    })
}

/// Inspect an installation without importing a target or modifying Ghidra.
pub fn inspect_installation(
    env: &BTreeMap<String, String>,
    install_dir: Option<&str>,
    java_home: Option<&str>,
) -> GhidraInstallation {
    let arch = node_arch();
    let platform = "linux";
    let properties_path = install_dir.map(|d| PathBuf::from(d).join("Ghidra").join("application.properties"));
    let headless = install_dir.map(|d| PathBuf::from(d).join("support").join("analyzeHeadless"));
    let decompiler = match (install_dir, native_platform(arch)) {
        (Some(dir), Some(plat)) => {
            let candidates = [
                PathBuf::from(dir).join("Ghidra/Features/Decompiler/os").join(plat).join("decompile"),
                PathBuf::from(dir).join("Ghidra/Features/Decompiler/build/os").join(plat).join("decompile"),
            ];
            candidates.into_iter().find(|c| is_executable_file(c))
        }
        _ => None,
    };
    let properties = properties_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|c| application_properties(&c));
    let java_command = match java_home {
        Some(home) => PathBuf::from(home).join("bin").join("java").to_string_lossy().to_string(),
        None => "java".to_string(),
    };
    let java_absolute = java_home.map(|h| Path::new(h).is_absolute()).unwrap_or(true);
    let java = if java_absolute {
        probe_java(&java_command, &java_environment(java_home, env))
    } else {
        None
    };

    let mut checks: Vec<Check> = Vec::new();
    // configuration
    let mut relative = Vec::new();
    if let Some(d) = install_dir {
        if !Path::new(d).is_absolute() {
            relative.push("GHIDRA_INSTALL_DIR");
        }
    }
    if let Some(h) = java_home {
        if !Path::new(h).is_absolute() {
            relative.push("JAVA_HOME");
        }
    }
    if install_dir.is_none() || relative.is_empty() {
        checks.push(Check {
            name: "configuration",
            passed: install_dir.is_some(),
            code: Some("not_configured"),
            detail: install_dir.map(str::to_string).unwrap_or_else(|| "GHIDRA_INSTALL_DIR is not set".to_string()),
            remediation: format!("Set GHIDRA_INSTALL_DIR to an extracted Ghidra {} release directory.", release_line()),
        });
    } else {
        let settings = relative.join(" and ");
        checks.push(Check {
            name: "configuration",
            passed: false,
            code: Some("not_configured"),
            detail: format!("{settings} must be absolute"),
            remediation: format!(
                "Set {settings} to {}. REA's analysis and MCP server reject relative paths even when they resolve from the current directory.",
                if relative.len() == 1 { "an absolute path" } else { "absolute paths" }
            ),
        });
    }
    checks.push(Check {
        name: "platform",
        passed: true,
        code: Some("unsupported_host"),
        detail: platform.to_string(),
        remediation: "Use Linux or macOS x64/arm64, or Windows x64 with matching native Ghidra tools.".to_string(),
    });
    checks.push(Check {
        name: "architecture",
        passed: native_platform(arch).is_some(),
        code: Some("unsupported_host"),
        detail: arch.to_string(),
        remediation: "Use x64/arm64 on Linux or macOS, or x64 on Windows.".to_string(),
    });
    checks.push(Check {
        name: "installation",
        passed: properties.is_some(),
        code: Some("executable_missing"),
        detail: properties_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "Ghidra application properties unavailable".to_string()),
        remediation: "Point GHIDRA_INSTALL_DIR at the root of an extracted official Ghidra release.".to_string(),
    });
    let raw_version = properties.as_ref().and_then(|p| p.provider_version.clone());
    let compat = release_compatibility(raw_version.as_deref());
    checks.push(Check {
        name: "version",
        passed: matches!(compat, Compatibility::Verified | Compatibility::Compatible),
        code: Some(if compat == Compatibility::Unsupported { "unsupported_version" } else { "version_unresolved" }),
        detail: version_detail(raw_version.as_deref()),
        remediation: format!(
            "Install a Ghidra {} release (verified with {SUPPORTED_GHIDRA_VERSION}), or update REA for another Ghidra line.",
            release_line()
        ),
    });
    checks.push(Check {
        name: "headless",
        passed: headless.as_ref().map(|h| is_executable_file(h)).unwrap_or(false),
        code: Some("executable_missing"),
        detail: headless
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "analyzeHeadless unavailable".to_string()),
        remediation: "Restore support/analyzeHeadless or support/analyzeHeadless.bat from the official Ghidra release.".to_string(),
    });
    let decompiler_dir = native_platform(arch).unwrap_or("<platform>");
    checks.push(Check {
        name: "native_decompiler",
        passed: decompiler.is_some(),
        code: Some("executable_missing"),
        detail: match &decompiler {
            Some(path) => native_decompiler_detail(path, arch),
            None => format!("Matching native decompiler for {platform}/{arch} was not found"),
        },
        remediation: format!(
            "Provide an executable Ghidra/Features/Decompiler/os/{decompiler_dir}/decompile, or its build/os equivalent. REA does not build or install native tools."
        ),
    });
    let requirement = java_requirement(properties.as_ref());
    let range = java_range_label(&requirement);
    let java_ok = java.as_ref().map(|j| {
        requirement.unresolved.is_none()
            && j.major >= requirement.minimum
            && requirement.maximum.map(|m| j.major <= m).unwrap_or(true)
            && j.bits == 64
            && j.jdk
    }).unwrap_or(false);
    checks.push(Check {
        name: "java",
        passed: java_ok,
        code: Some(if requirement.unresolved.is_some() {
            "version_unresolved"
        } else if java.is_none() {
            "runtime_missing"
        } else {
            "unsupported_version"
        }),
        detail: match &java {
            None => match &requirement.unresolved {
                None => java_command.clone(),
                Some(u) => format!("{java_command}; {u}"),
            },
            Some(j) => format!(
                "{}; {}-bit; {}; {}; accepted {range}",
                j.version,
                j.bits,
                if j.jdk { "JDK" } else { "runtime only" },
                j.home
            ),
        },
        remediation: if let Some(u) = &requirement.unresolved {
            format!("The Ghidra installation's Java bounds could not be read ({u}). Install a 64-bit full JDK inside the declared application.java.min and application.java.max.")
        } else if java_home.is_none() {
            format!("Install {range}, or set JAVA_HOME before starting REA.")
        } else {
            format!("Update JAVA_HOME to the root of {range} installation.")
        },
    });

    let failed = checks.iter().find(|c| !c.passed).cloned();
    let rejection = failed.map(|c| (c.code.unwrap_or("executable_missing"), c.remediation.clone()));
    GhidraInstallation {
        available: rejection.is_none(),
        platform,
        architecture: arch,
        install_dir: install_dir.map(str::to_string),
        analyze_headless_path: headless.map(|p| p.to_string_lossy().to_string()),
        native_decompiler_path: decompiler.map(|p| p.to_string_lossy().to_string()),
        application_properties_path: properties_path.map(|p| p.to_string_lossy().to_string()),
        provider_version: raw_version,
        java_command,
        java_home: java.as_ref().map(|j| j.home.clone()).or_else(|| java_home.map(str::to_string)),
        java_version: java.as_ref().map(|j| j.version.clone()),
        checks,
        rejection,
    }
}

/// The decompiler's own ELF header must agree with the host (a positively
/// contradicting header would be rejected; unknown stays accepted).
fn native_decompiler_detail(path: &Path, arch: &str) -> String {
    let observed = std::fs::read(path)
        .ok()
        .filter(|b| b.len() >= 20 && b.starts_with(b"\x7fELF"))
        .map(|b| match u16::from_le_bytes([b[18], b[19]]) {
            62 => "x86_64",
            183 => "arm64",
            _ => "unknown",
        });
    let expected = match arch {
        "x64" => "x86_64",
        other => other,
    };
    match observed {
        Some(obs) if obs == expected => format!(
            "{} reports elf {obs}, which matches linux/{arch}",
            path.display()
        ),
        _ => format!(
            "{} is executable, but its executable format for linux/{arch} could not be established",
            path.display()
        ),
    }
}
