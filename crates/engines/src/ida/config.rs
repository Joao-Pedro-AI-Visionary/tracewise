//! `REA_IDA_MCP_CONFIG`: an upstream MCP registration plus the database lifecycle selection
//! (port of `IdaConfiguration.ts`).
//!
//! The registration is read, never written; reading it starts nothing. A registration is
//! either a direct object or an upstream `mcpServers` document with an `ida-pro-mcp` entry.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::error::AnalysisError;

/// Environment variable naming the registration file.
pub const SETTING: &str = "REA_IDA_MCP_CONFIG";

/// Registration files larger than this are rejected before parsing.
const REGISTRATION_LIMIT_BYTES: u64 = 65_536;

const SHAPE_CONSTRAINT: &str =
    "REA_IDA_MCP_CONFIG must contain an IDA MCP command/args or local url registration; see docs/ida-provider.md.";

/// Constraint reported when no registration was configured.
pub const NOT_CONFIGURED: &str =
    "Set REA_IDA_MCP_CONFIG to an upstream IDA MCP JSON registration; see docs/ida-provider.md.";

/// Settings read from the REA environment.
#[derive(Debug, Clone, Default)]
pub struct IdaConfig {
    pub config_path: Option<String>,
    pub environment: BTreeMap<String, String>,
}

impl IdaConfig {
    pub fn from_environment(environment: &BTreeMap<String, String>) -> Self {
        Self {
            config_path: environment.get(SETTING).filter(|v| !v.is_empty()).cloned(),
            environment: environment.clone(),
        }
    }
}

/// Which upstream compatibility profile and database lifecycle REA drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdaMode {
    /// An open IDA session; the legacy 1.4 tool family. REA never opens or closes databases.
    Attached,
    /// REA opens (and later closes) a private worker database; the supervisor tool family.
    Headless,
}

impl IdaMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Headless => "headless",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IdaTransport {
    Stdio {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
    Http {
        url: String,
        headers: BTreeMap<String, String>,
    },
}

/// A validated registration.
#[derive(Debug, Clone, PartialEq)]
pub struct IdaRegistration {
    pub mode: IdaMode,
    pub timeout_ms: u64,
    pub workspace_root: Option<String>,
    pub transport: IdaTransport,
    /// The parsed object exactly as REA's schema returns it (defaults applied); the
    /// analysis profile commits to its RFC 8785 digest.
    canonical: Value,
}

impl IdaRegistration {
    pub fn is_stdio(&self) -> bool {
        matches!(self.transport, IdaTransport::Stdio { .. })
    }

    pub fn canonical(&self) -> &Value {
        &self.canonical
    }

    /// SHA-256 of the canonical registration (credentials included, never reported).
    pub fn digest(&self) -> String {
        tracewise_domain::canonical::canonical_sha256(&self.canonical).unwrap_or_default()
    }
}

/// A `REA_IDA_MCP_CONFIG` rejection that names the setting it concerns.
pub fn configuration_error(constraint: &str) -> AnalysisError {
    AnalysisError::Configuration {
        settings: vec![(SETTING.to_string(), constraint.to_string())],
    }
}

/// Read one explicit registration. On failure the constraint text is returned
/// (`ConfigurationError.message` in REA).
pub fn read_registration(path: &str) -> Result<IdaRegistration, String> {
    let unreadable = || {
        format!("Cannot read IDA MCP registration {path}; provide a readable JSON configuration.")
    };
    let metadata = std::fs::metadata(path).map_err(|_| unreadable())?;
    if metadata.len() > REGISTRATION_LIMIT_BYTES {
        return Err("REA_IDA_MCP_CONFIG exceeds the 64 KiB registration size.".to_string());
    }
    let text = std::fs::read_to_string(path).map_err(|_| unreadable())?;
    let input: Value = serde_json::from_str(&text).map_err(|_| unreadable())?;
    let candidate = input
        .get("mcpServers")
        .and_then(Value::as_object)
        .and_then(|servers| servers.get("ida-pro-mcp"))
        .unwrap_or(&input);
    parse_registration(candidate).ok_or_else(|| SHAPE_CONSTRAINT.to_string())
}

/// Validate one registration object (the strict stdio-or-http union of REA's schema).
pub fn parse_registration(value: &Value) -> Option<IdaRegistration> {
    let object = value.as_object()?;
    parse_stdio(object).or_else(|| parse_http(object))
}

struct Common {
    mode: IdaMode,
    timeout_ms: u64,
    workspace_root: Option<String>,
}

fn parse_common(object: &Map<String, Value>) -> Option<Common> {
    let mode = match object.get("mode") {
        None => IdaMode::Attached,
        Some(Value::String(mode)) if mode == "attached" => IdaMode::Attached,
        Some(Value::String(mode)) if mode == "headless" => IdaMode::Headless,
        Some(_) => return None,
    };
    let timeout_ms = match object.get("timeoutMs") {
        None => 300_000,
        Some(Value::Number(number)) => {
            let n = number.as_f64()?;
            if n.fract() != 0.0 || n <= 0.0 || n > 2_147_483_647.0 {
                return None;
            }
            n as u64
        }
        Some(_) => return None,
    };
    let workspace_root = match object.get("workspaceRoot") {
        None => None,
        Some(Value::String(root)) if Path::new(root).is_absolute() => Some(root.clone()),
        Some(_) => return None,
    };
    Some(Common {
        mode,
        timeout_ms,
        workspace_root,
    })
}

fn string_map(value: Option<&Value>) -> Option<BTreeMap<String, String>> {
    match value {
        None => Some(BTreeMap::new()),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        Some(_) => None,
    }
}

fn only_keys(object: &Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

fn common_canonical(object: &Map<String, Value>, common: &Common) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(kind) = object.get("type") {
        out.insert("type".into(), kind.clone());
    }
    out.insert("mode".into(), json!(common.mode.as_str()));
    out.insert("timeoutMs".into(), json!(common.timeout_ms));
    if let Some(root) = &common.workspace_root {
        out.insert("workspaceRoot".into(), json!(root));
    }
    out
}

fn parse_stdio(object: &Map<String, Value>) -> Option<IdaRegistration> {
    if !only_keys(
        object,
        &[
            "type",
            "mode",
            "timeoutMs",
            "workspaceRoot",
            "command",
            "args",
            "env",
        ],
    ) {
        return None;
    }
    if let Some(kind) = object.get("type") {
        if kind != "stdio" {
            return None;
        }
    }
    let command = object
        .get("command")?
        .as_str()
        .filter(|c| !c.is_empty())?
        .to_string();
    let args: Vec<String> = match object.get("args") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        Some(_) => return None,
    };
    let env = string_map(object.get("env"))?;
    let common = parse_common(object)?;
    let mut canonical = common_canonical(object, &common);
    canonical.insert("command".into(), json!(command));
    canonical.insert("args".into(), json!(args));
    canonical.insert("env".into(), json!(env));
    Some(IdaRegistration {
        mode: common.mode,
        timeout_ms: common.timeout_ms,
        workspace_root: common.workspace_root,
        transport: IdaTransport::Stdio { command, args, env },
        canonical: Value::Object(canonical),
    })
}

fn parse_http(object: &Map<String, Value>) -> Option<IdaRegistration> {
    if !only_keys(
        object,
        &[
            "type",
            "mode",
            "timeoutMs",
            "workspaceRoot",
            "url",
            "headers",
        ],
    ) {
        return None;
    }
    if let Some(kind) = object.get("type") {
        if kind != "http" {
            return None;
        }
    }
    let url = object.get("url")?.as_str()?.to_string();
    let parsed = url::Url::parse(&url).ok()?;
    let local = matches!(parsed.scheme(), "http" | "https")
        && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
        && parsed.username().is_empty()
        && parsed.password().is_none();
    if !local {
        return None;
    }
    let headers = string_map(object.get("headers"))?;
    let common = parse_common(object)?;
    let mut canonical = common_canonical(object, &common);
    canonical.insert("url".into(), json!(url));
    canonical.insert("headers".into(), json!(headers));
    Some(IdaRegistration {
        mode: common.mode,
        timeout_ms: common.timeout_ms,
        workspace_root: common.workspace_root,
        transport: IdaTransport::Http { url, headers },
        canonical: Value::Object(canonical),
    })
}

/// The doctor's registration check (port of `IdaDoctor.ts`): validates the file without
/// launching anything and reports only the configuration file reference.
pub fn inspect_registration(path: Option<&str>) -> Value {
    let parsed = path.map(read_registration);
    let valid = matches!(parsed, Some(Ok(_)));
    let (code, detail, remediation, classification) = if valid {
        (
            Value::Null,
            "IDA MCP registration is valid. Upstream availability, compatibility, and target binding are checked when analysis starts; no IDA process was launched.".to_string(),
            Value::Null,
            "config_drift",
        )
    } else {
        (
            json!(if path.is_none() { "not_configured" } else { "invalid_configuration" }),
            match &parsed {
                Some(Err(message)) => message.clone(),
                _ => "IDA MCP registration is not configured.".to_string(),
            },
            json!("Set REA_IDA_MCP_CONFIG to your upstream IDA MCP registration JSON; see docs/ida-provider.md."),
            if path.is_none() { "missing_analysis_engine" } else { "config_drift" },
        )
    };
    json!({
        "id": "ida",
        "configured": path.is_some(),
        "available": valid,
        "providerVersion": Value::Null,
        "registrationEnvironment": match path { Some(p) if valid => json!({ "REA_IDA_MCP_CONFIG": p }), _ => json!({}) },
        "checks": [{
            "name": "registration",
            "ok": valid,
            "code": code,
            "detail": detail,
            "remediation": remediation,
            "classification": classification,
        }],
    })
}
