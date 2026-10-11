//! `capture_browser_scenario` input (port of REA domain/browserScenario.ts and
//! domain/browserScenarioValues.ts). Secret values are references only.

use serde_json::{json, Map, Value};
use tracewise_domain::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
    ExecutionEnvironment, IsolationLevel,
};
use url::Url;

use crate::browser_observation::parse_exact_origin;
use crate::error::WebError;
use crate::runtime_cdp::input_error;

const OPERATION: &str = "capture_browser_scenario";
pub const SCENARIO_PROVIDER_ID: &str = "rea-playwright-browser-scenario";
pub const SCENARIO_PROVIDER_NAME: &str = "REA Playwright browser scenario capture provider";
pub const SCENARIO_PROVIDER_VERSION: &str = "1";

#[derive(Debug, Clone)]
pub struct BrowserScenario {
    pub document: Value,
    pub mode: ScenarioMode,
    pub start: ScenarioUrl,
    pub actions: Vec<ScenarioAction>,
    pub environment: ScenarioEnvironment,
    pub storage: ScenarioStorage,
    pub secrets: Vec<SecretDeclaration>,
    pub capture: ScenarioCapture,
}

#[derive(Debug, Clone)]
pub enum ScenarioMode {
    Launch { executable_path: String, headless: bool },
    Connect { cdp_endpoint: String, target_id: String },
}

#[derive(Debug, Clone)]
pub struct ScenarioUrl {
    pub url: String,
    pub query: Vec<(String, ScenarioValue)>,
}

#[derive(Debug, Clone)]
pub enum ScenarioValue {
    Literal(String),
    Secret(String),
}

#[derive(Debug, Clone)]
pub struct ScenarioEnvironment {
    pub width: i64,
    pub height: i64,
    pub device_scale_factor: f64,
    pub locale: String,
    pub timezone: String,
    pub color_scheme: String,
    pub reduced_motion: String,
    pub service_workers: String,
}

#[derive(Debug, Clone)]
pub struct ScenarioStorage {
    pub cookies: Vec<CookieSeed>,
    pub local_storage: Vec<StorageOrigin>,
    pub session_storage: Vec<StorageOrigin>,
}

#[derive(Debug, Clone)]
pub struct CookieSeed {
    pub name: String,
    pub value: ScenarioValue,
    pub destination: ScenarioUrl,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
}

#[derive(Debug, Clone)]
pub struct StorageOrigin {
    pub origin: String,
    pub entries: Vec<(String, ScenarioValue)>,
}

#[derive(Debug, Clone)]
pub struct SecretDeclaration {
    pub secret_id: String,
    pub environment_variable: String,
}

#[derive(Debug, Clone)]
pub struct ScenarioCapture {
    pub after_each_step: Vec<String>,
    pub at_end: Vec<String>,
    pub events: Vec<String>,
    pub request_body: bool,
    pub response_body: bool,
    pub header_values: bool,
}

#[derive(Debug, Clone)]
pub enum ScenarioAction {
    Goto {
        step_id: String,
        timeout_ms: Option<i64>,
        destination: ScenarioUrl,
        wait_until: String,
    },
    Click {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        button: String,
        click_count: i64,
    },
    Fill {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        value: ScenarioValue,
    },
    Press {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        key: String,
    },
    Select {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        value: ScenarioValue,
    },
    Check {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        checked: bool,
    },
    WaitFor {
        step_id: String,
        timeout_ms: Option<i64>,
        locator: Locator,
        state: String,
    },
    WaitTimeout { step_id: String, duration_ms: i64 },
}

impl ScenarioAction {
    pub fn step_id(&self) -> &str {
        match self {
            Self::Goto { step_id, .. }
            | Self::Click { step_id, .. }
            | Self::Fill { step_id, .. }
            | Self::Press { step_id, .. }
            | Self::Select { step_id, .. }
            | Self::Check { step_id, .. }
            | Self::WaitFor { step_id, .. }
            | Self::WaitTimeout { step_id, .. } => step_id,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Goto { .. } => "goto",
            Self::Click { .. } => "click",
            Self::Fill { .. } => "fill",
            Self::Press { .. } => "press",
            Self::Select { .. } => "select_option",
            Self::Check { checked: true, .. } => "check",
            Self::Check { checked: false, .. } => "uncheck",
            Self::WaitFor { .. } => "wait_for",
            Self::WaitTimeout { .. } => "wait_for_timeout",
        }
    }

    pub fn timeout_ms(&self) -> Option<i64> {
        match self {
            Self::Goto { timeout_ms, .. }
            | Self::Click { timeout_ms, .. }
            | Self::Fill { timeout_ms, .. }
            | Self::Press { timeout_ms, .. }
            | Self::Select { timeout_ms, .. }
            | Self::Check { timeout_ms, .. }
            | Self::WaitFor { timeout_ms, .. } => *timeout_ms,
            Self::WaitTimeout { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Locator {
    TestId(String),
    Role { role: String, name: String },
    Css(String),
}

impl Locator {
    pub fn to_json(&self) -> Value {
        match self {
            Self::TestId(value) => json!({ "kind": "test_id", "value": value }),
            Self::Role { role, name } => json!({ "kind": "role", "role": role, "name": name }),
            Self::Css(selector) => json!({ "kind": "css", "selector": selector }),
        }
    }
}

pub fn parse_capture_browser_scenario_input(args: &Value) -> Result<BrowserScenario, WebError> {
    let object = expect_object(args, &[])?;
    require_keys(
        object,
        &[
            "browser",
            "start_url",
            "environment",
            "actions",
            "storage",
            "secrets",
            "capture",
        ],
    )?;
    let mode = parse_browser(object.get("browser"))?;
    let start = parse_url(object.get("start_url"), &["start_url"])?;
    let environment = parse_environment(object.get("environment"))?;
    let actions = parse_actions(object.get("actions"))?;
    let storage = parse_storage(object.get("storage"))?;
    let secrets = parse_secrets(object.get("secrets"))?;
    let capture = parse_capture(object.get("capture"))?;
    validate_references(&actions, &start, &storage, &secrets)?;
    let document = json!({
        "browser": browser_json(&mode),
        "start_url": url_json(&start),
        "environment": environment_json(&environment),
        "actions": actions.iter().map(action_json).collect::<Vec<_>>(),
        "storage": storage_json(&storage),
        "secrets": secrets.iter().map(secret_json).collect::<Vec<_>>(),
        "capture": capture_json(&capture),
    });
    Ok(BrowserScenario {
        document,
        mode,
        start,
        actions,
        environment,
        storage,
        secrets,
        capture,
    })
}

pub fn create_scenario_evidence(
    scenario: &BrowserScenario,
    capture: Value,
    product: &str,
    version: &str,
    owned: bool,
) -> Result<Evidence, WebError> {
    let scenario_sha256 = canonical_sha256(&scenario.document)?;
    let mut parameters = scenario.document.as_object().cloned().unwrap_or_default();
    parameters.insert("scenario_sha256".to_string(), Value::String(scenario_sha256));
    let mut limitations = vec!["Artifact identity is unavailable for this observation.".to_string()];
    if let Some(items) = capture.get("limitations").and_then(Value::as_array) {
        limitations.extend(items.iter().filter_map(|item| item.as_str().map(str::to_string)));
    }
    limitations.push("Browser host platform and architecture were not observed.".to_string());
    let provider = EvidenceProvider {
        id: SCENARIO_PROVIDER_ID.to_string(),
        name: SCENARIO_PROVIDER_NAME.to_string(),
        version: Some(SCENARIO_PROVIDER_VERSION.to_string()),
    };
    let observation = EvidenceObservation {
        predicate_type: Some("rea.browser-scenario-capture".to_string()),
        operation: OPERATION.to_string(),
        parameters: Value::Object(parameters),
        normalized_result: capture,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Observed),
        authority: Some(EvidenceAuthority::ControlledReplay),
        environment: Some(ExecutionEnvironment {
            id: format!("{product}@{version}"),
            platform: "unknown".to_string(),
            architecture: "unknown".to_string(),
            isolation: if owned { IsolationLevel::Process } else { IsolationLevel::None },
        }),
        limitations: Some(limitations),
        locations: Some(vec![]),
        evidence_links: Some(vec![]),
    };
    create_evidence(None, provider, observation).map_err(WebError::from)
}

fn validate_references(
    actions: &[ScenarioAction],
    start: &ScenarioUrl,
    storage: &ScenarioStorage,
    secrets: &[SecretDeclaration],
) -> Result<(), WebError> {
    let mut step_ids = Vec::new();
    for action in actions {
        step_ids.push(action.step_id().to_string());
    }
    unique(&step_ids, "actions", "Action step IDs")?;
    let mut secret_ids = Vec::new();
    let mut variables = Vec::new();
    for secret in secrets {
        secret_ids.push(secret.secret_id.clone());
        variables.push(secret.environment_variable.clone());
    }
    unique(&secret_ids, "secrets", "Secret IDs")?;
    unique(&variables, "secrets", "Secret environment variables")?;
    let mut references = Vec::new();
    references.extend(url_secret_refs(start));
    for action in actions {
        references.extend(action_secret_refs(action));
    }
    for cookie in &storage.cookies {
        references.extend(value_secret_refs(&cookie.value));
        references.extend(url_secret_refs(&cookie.destination));
    }
    for origin in storage.local_storage.iter().chain(storage.session_storage.iter()) {
        for (_, value) in &origin.entries {
            references.extend(value_secret_refs(value));
        }
    }
    let declared: std::collections::BTreeSet<&str> = secret_ids.iter().map(String::as_str).collect();
    for reference in references {
        if !declared.contains(reference.as_str()) {
            return Err(input_error(
                OPERATION,
                "secrets",
                format!("Secret reference {reference} is not declared"),
            ));
        }
    }
    Ok(())
}

fn action_secret_refs(action: &ScenarioAction) -> Vec<String> {
    match action {
        ScenarioAction::Fill { value, .. } | ScenarioAction::Select { value, .. } => value_secret_refs(value),
        ScenarioAction::Goto { destination, .. } => url_secret_refs(destination),
        _ => Vec::new(),
    }
}

fn url_secret_refs(url: &ScenarioUrl) -> Vec<String> {
    url.query.iter().flat_map(|(_, value)| value_secret_refs(value)).collect()
}

fn value_secret_refs(value: &ScenarioValue) -> Vec<String> {
    match value {
        ScenarioValue::Secret(secret_id) => vec![secret_id.clone()],
        ScenarioValue::Literal(_) => Vec::new(),
    }
}

fn unique(values: &[String], path: &str, label: &str) -> Result<(), WebError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(input_error(OPERATION, path, format!("{label} must be unique")));
        }
    }
    Ok(())
}

fn parse_browser(value: Option<&Value>) -> Result<ScenarioMode, WebError> {
    let object = expect_object(value.unwrap_or(&Value::Null), &["browser"])?;
    let mode = required_string(object, "mode", &["browser", "mode"])?;
    match mode.as_str() {
        "launch" => {
            require_keys(object, &["mode", "executable_path", "headless"])?;
            let executable_path = required_string(object, "executable_path", &["browser", "executable_path"])?;
            if !std::path::Path::new(&executable_path).is_absolute() {
                return Err(input_error(
                    OPERATION,
                    "browser.executable_path",
                    "executable_path must be an absolute local filesystem path",
                ));
            }
            let headless = match object.get("headless") {
                None => true,
                Some(Value::Bool(value)) => *value,
                Some(_) => return Err(input_error(OPERATION, "browser.headless", "headless must be a boolean")),
            };
            Ok(ScenarioMode::Launch { executable_path, headless })
        }
        "connect" => {
            require_keys(object, &["mode", "cdp_endpoint", "target_id"])?;
            let endpoint = required_string(object, "cdp_endpoint", &["browser", "cdp_endpoint"])?;
            let cdp_endpoint = crate::browser_observation::parse_cdp_endpoint(&endpoint).ok_or_else(|| {
                input_error(
                    OPERATION,
                    "browser.cdp_endpoint",
                    "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1",
                )
            })?;
            let target_id = required_string(object, "target_id", &["browser", "target_id"])?;
            Ok(ScenarioMode::Connect { cdp_endpoint, target_id })
        }
        _ => Err(input_error(OPERATION, "browser.mode", "browser.mode must be launch or connect")),
    }
}

fn parse_environment(value: Option<&Value>) -> Result<ScenarioEnvironment, WebError> {
    if value.is_none() {
        return Ok(default_environment());
    }
    let object = expect_object(value.unwrap_or(&Value::Null), &["environment"])?;
    require_keys(
        object,
        &[
            "viewport",
            "locale",
            "timezone",
            "color_scheme",
            "reduced_motion",
            "service_workers",
        ],
    )?;
    let viewport = object.get("viewport");
    let (width, height, scale) = if viewport.is_none() {
        (1280, 720, 1.0)
    } else {
        let viewport = expect_object(viewport.unwrap_or(&Value::Null), &["environment", "viewport"])?;
        require_keys(viewport, &["width", "height", "device_scale_factor"])?;
        (
            optional_i64(viewport, "width", &["environment", "viewport", "width"])?.unwrap_or(1280),
            optional_i64(viewport, "height", &["environment", "viewport", "height"])?.unwrap_or(720),
            optional_positive_f64(viewport.get("device_scale_factor"), "environment.viewport.device_scale_factor")?
                .unwrap_or(1.0),
        )
    };
    if width < 1 || height < 1 {
        return Err(input_error(OPERATION, "environment.viewport", "viewport dimensions must be positive"));
    }
    Ok(ScenarioEnvironment {
        width,
        height,
        device_scale_factor: scale,
        locale: optional_pattern(object, "locale", "en-US", &["environment", "locale"], is_locale)?,
        timezone: optional_pattern(object, "timezone", "UTC", &["environment", "timezone"], is_timezone)?,
        color_scheme: optional_enum(object, "color_scheme", "light", &["light", "dark", "no-preference"])?,
        reduced_motion: optional_enum(object, "reduced_motion", "reduce", &["reduce", "no-preference"])?,
        service_workers: optional_enum(object, "service_workers", "block", &["allow", "block"])?,
    })
}

fn default_environment() -> ScenarioEnvironment {
    ScenarioEnvironment {
        width: 1280,
        height: 720,
        device_scale_factor: 1.0,
        locale: "en-US".to_string(),
        timezone: "UTC".to_string(),
        color_scheme: "light".to_string(),
        reduced_motion: "reduce".to_string(),
        service_workers: "block".to_string(),
    }
}

fn parse_actions(value: Option<&Value>) -> Result<Vec<ScenarioAction>, WebError> {
    let Some(Value::Array(items)) = value else {
        return Err(input_error(OPERATION, "actions", "actions must be an array"));
    };
    if items.is_empty() {
        return Err(input_error(OPERATION, "actions", "actions must contain at least one action"));
    }
    items.iter().enumerate().map(|(index, item)| parse_action(item, index)).collect()
}

fn parse_action(value: &Value, index: usize) -> Result<ScenarioAction, WebError> {
    let path = format!("actions.{index}");
    let object = expect_object(value, &[&path])?;
    let action = required_string(object, "action", &[&path, "action"])?;
    let step_id = required_identifier(object, "step_id", &[&path, "step_id"])?;
    let timeout_ms = match action.as_str() {
        "wait_for_timeout" => None,
        _ => optional_timeout(object, &path)?,
    };
    match action.as_str() {
        "goto" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "destination", "wait_until"])?;
            Ok(ScenarioAction::Goto {
                step_id,
                timeout_ms,
                destination: parse_url(object.get("destination"), &[&path, "destination"])?,
                wait_until: required_enum(object, "wait_until", &[&path, "wait_until"], &["commit", "domcontentloaded", "load"])?,
            })
        }
        "click" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "locator", "button", "click_count"])?;
            Ok(ScenarioAction::Click {
                step_id,
                timeout_ms,
                locator: parse_locator(object.get("locator"), &path)?,
                button: optional_enum(object, "button", "left", &["left", "middle", "right"])?,
                click_count: positive_i64(object, "click_count", &path, 1)?,
            })
        }
        "fill" | "select_option" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "locator", "value"])?;
            let value = parse_value(object.get("value"), &[&path, "value"])?;
            let locator = parse_locator(object.get("locator"), &path)?;
            if action == "fill" {
                Ok(ScenarioAction::Fill { step_id, timeout_ms, locator, value })
            } else {
                Ok(ScenarioAction::Select { step_id, timeout_ms, locator, value })
            }
        }
        "press" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "locator", "key"])?;
            Ok(ScenarioAction::Press {
                step_id,
                timeout_ms,
                locator: parse_locator(object.get("locator"), &path)?,
                key: required_string(object, "key", &[&path, "key"])?,
            })
        }
        "check" | "uncheck" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "locator"])?;
            Ok(ScenarioAction::Check {
                step_id,
                timeout_ms,
                locator: parse_locator(object.get("locator"), &path)?,
                checked: action == "check",
            })
        }
        "wait_for" => {
            require_action_keys(object, &["step_id", "timeout_ms", "action", "locator", "state"])?;
            Ok(ScenarioAction::WaitFor {
                step_id,
                timeout_ms,
                locator: parse_locator(object.get("locator"), &path)?,
                state: required_enum(object, "state", &[&path, "state"], &["attached", "detached", "visible", "hidden"])?,
            })
        }
        "wait_for_timeout" => {
            require_action_keys(object, &["step_id", "action", "duration_ms"])?;
            let duration_ms = required_i64(object, "duration_ms", &[&path, "duration_ms"])?;
            if duration_ms < 1 {
                return Err(input_error(OPERATION, &format!("{path}.duration_ms"), "duration_ms must be at least 1"));
            }
            Ok(ScenarioAction::WaitTimeout { step_id, duration_ms })
        }
        _ => Err(input_error(OPERATION, &format!("{path}.action"), "Unsupported scenario action")),
    }
}

fn parse_locator(value: Option<&Value>, path: &str) -> Result<Locator, WebError> {
    let locator_path = format!("{path}.locator");
    let object = expect_object(value.unwrap_or(&Value::Null), &[&locator_path])?;
    let kind = required_string(object, "kind", &[&locator_path, "kind"])?;
    match kind.as_str() {
        "test_id" => {
            require_keys(object, &["kind", "value"])?;
            Ok(Locator::TestId(required_string(object, "value", &[&locator_path, "value"])?))
        }
        "css" => {
            require_keys(object, &["kind", "selector"])?;
            Ok(Locator::Css(required_string(object, "selector", &[&locator_path, "selector"])?))
        }
        "role" => {
            require_keys(object, &["kind", "role", "name"])?;
            let role = required_enum(
                object,
                "role",
                &[&locator_path, "role"],
                &[
                    "button", "checkbox", "combobox", "dialog", "link", "listbox", "menuitem", "option", "radio",
                    "slider", "spinbutton", "switch", "tab", "textbox",
                ],
            )?;
            Ok(Locator::Role {
                role,
                name: required_string(object, "name", &[&locator_path, "name"])?,
            })
        }
        _ => Err(input_error(OPERATION, &locator_path, "Unsupported locator kind")),
    }
}

fn parse_storage(value: Option<&Value>) -> Result<ScenarioStorage, WebError> {
    if value.is_none() {
        return Ok(empty_storage());
    }
    let object = expect_object(value.unwrap_or(&Value::Null), &["storage"])?;
    require_keys(object, &["cookies", "local_storage", "session_storage"])?;
    Ok(ScenarioStorage {
        cookies: parse_cookies(object.get("cookies"))?,
        local_storage: parse_storage_list(object.get("local_storage"), "local_storage")?,
        session_storage: parse_storage_list(object.get("session_storage"), "session_storage")?,
    })
}

fn empty_storage() -> ScenarioStorage {
    ScenarioStorage {
        cookies: Vec::new(),
        local_storage: Vec::new(),
        session_storage: Vec::new(),
    }
}

fn parse_cookies(value: Option<&Value>) -> Result<Vec<CookieSeed>, WebError> {
    let Some(items) = optional_array(value, "storage.cookies")? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let path = format!("storage.cookies.{index}");
            let object = expect_object(item, &[&path])?;
            require_keys(object, &["name", "value", "destination", "http_only", "secure", "same_site"])?;
            Ok(CookieSeed {
                name: required_string(object, "name", &[&path, "name"])?,
                value: parse_value(object.get("value"), &[&path, "value"])?,
                destination: parse_url(object.get("destination"), &[&path, "destination"])?,
                http_only: required_bool(object, "http_only", &path)?,
                secure: required_bool(object, "secure", &path)?,
                same_site: required_enum(object, "same_site", &[&path, "same_site"], &["Strict", "Lax", "None"])?,
            })
        })
        .collect()
}

fn parse_storage_list(value: Option<&Value>, name: &str) -> Result<Vec<StorageOrigin>, WebError> {
    let Some(items) = optional_array(value, &format!("storage.{name}"))? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let path = format!("storage.{name}.{index}");
            let object = expect_object(item, &[&path])?;
            require_keys(object, &["origin", "entries"])?;
            let origin = required_string(object, "origin", &[&path, "origin"])?;
            let origin = parse_exact_origin(&origin).ok_or_else(|| {
                input_error(OPERATION, &format!("{path}.origin"), "storage origin must be an exact HTTP(S) origin")
            })?;
            let entries = object.get("entries").and_then(Value::as_array).ok_or_else(|| {
                input_error(OPERATION, &format!("{path}.entries"), "storage entries must be an array")
            })?;
            let entries = entries
                .iter()
                .enumerate()
                .map(|(entry_index, entry)| {
                    let entry_path = format!("{path}.entries.{entry_index}");
                    let entry = expect_object(entry, &[&entry_path])?;
                    require_keys(entry, &["name", "value"])?;
                    Ok((
                        required_string(entry, "name", &[&entry_path, "name"])?,
                        parse_value(entry.get("value"), &[&entry_path, "value"])?,
                    ))
                })
                .collect::<Result<Vec<_>, WebError>>()?;
            Ok(StorageOrigin { origin, entries })
        })
        .collect()
}

fn parse_secrets(value: Option<&Value>) -> Result<Vec<SecretDeclaration>, WebError> {
    let Some(items) = optional_array(value, "secrets")? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let path = format!("secrets.{index}");
            let object = expect_object(item, &[&path])?;
            require_keys(object, &["secret_id", "environment_variable"])?;
            let environment_variable = required_string(object, "environment_variable", &[&path, "environment_variable"])?;
            if environment_variable.contains('=') || environment_variable.contains('\0') {
                return Err(input_error(
                    OPERATION,
                    &format!("{path}.environment_variable"),
                    "Environment variable names cannot contain '=' or NUL",
                ));
            }
            Ok(SecretDeclaration {
                secret_id: required_identifier(object, "secret_id", &[&path, "secret_id"])?,
                environment_variable,
            })
        })
        .collect()
}

fn parse_capture(value: Option<&Value>) -> Result<ScenarioCapture, WebError> {
    if value.is_none() {
        return Ok(default_capture());
    }
    let object = expect_object(value.unwrap_or(&Value::Null), &["capture"])?;
    require_keys(object, &["after_each_step", "at_end", "events", "network"])?;
    let network = object.get("network");
    let (request_body, response_body, header_values) = if network.is_none() {
        (false, false, false)
    } else {
        let network = expect_object(network.unwrap_or(&Value::Null), &["capture", "network"])?;
        require_keys(network, &["request_body", "response_body", "header_values"])?;
        (
            optional_bool(network, "request_body")?.unwrap_or(false),
            optional_bool(network, "response_body")?.unwrap_or(false),
            optional_bool(network, "header_values")?.unwrap_or(false),
        )
    };
    Ok(ScenarioCapture {
        after_each_step: snapshot_list(object.get("after_each_step"), "capture.after_each_step")?.unwrap_or_default(),
        at_end: snapshot_list(object.get("at_end"), "capture.at_end")?.unwrap_or_else(|| vec!["url".to_string()]),
        events: event_list(object.get("events"))?,
        request_body,
        response_body,
        header_values,
    })
}

fn default_capture() -> ScenarioCapture {
    ScenarioCapture {
        after_each_step: Vec::new(),
        at_end: vec!["url".to_string()],
        events: Vec::new(),
        request_body: false,
        response_body: false,
        header_values: false,
    }
}

fn snapshot_list(value: Option<&Value>, path: &str) -> Result<Option<Vec<String>>, WebError> {
    let Some(items) = optional_array(value, path)? else {
        return Ok(None);
    };
    items
        .iter()
        .map(|item| match item.as_str() {
            Some(kind) if matches!(kind, "screenshot" | "dom" | "accessibility" | "url" | "history" | "storage") => {
                Ok(kind.to_string())
            }
            _ => Err(input_error(OPERATION, path, "Unsupported snapshot kind")),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn event_list(value: Option<&Value>) -> Result<Vec<String>, WebError> {
    let Some(items) = optional_array(value, "capture.events")? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .map(|item| match item.as_str() {
            Some(kind)
                if matches!(
                    kind,
                    "console" | "page-errors" | "network" | "websockets" | "frames" | "workers" | "popups" | "downloads"
                ) =>
            {
                Ok(kind.to_string())
            }
            _ => Err(input_error(OPERATION, "capture.events", "Unsupported event family")),
        })
        .collect()
}

fn parse_url(value: Option<&Value>, path: &[&str]) -> Result<ScenarioUrl, WebError> {
    let object = expect_object(value.unwrap_or(&Value::Null), path)?;
    let path_text = path.join(".");
    require_keys(object, &["url", "query"])?;
    let raw = required_string(object, "url", &[&path_text, "url"])?;
    let url = normalize_http_url(&raw, &format!("{path_text}.url"))?;
    let query = match object.get("query") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let entry = format!("{path_text}.query.{index}");
                let item = expect_object(item, &[&entry])?;
                require_keys(item, &["name", "value"])?;
                Ok((
                    required_string(item, "name", &[&entry, "name"])?,
                    parse_value(item.get("value"), &[&entry, "value"])?,
                ))
            })
            .collect::<Result<Vec<_>, WebError>>()?,
        Some(_) => return Err(input_error(OPERATION, &format!("{path_text}.query"), "query must be an array")),
    };
    Ok(ScenarioUrl { url, query })
}

fn parse_value(value: Option<&Value>, path: &[&str]) -> Result<ScenarioValue, WebError> {
    let object = expect_object(value.unwrap_or(&Value::Null), path)?;
    let path_text = path.join(".");
    let source = required_string(object, "source", &[&path_text, "source"])?;
    match source.as_str() {
        "literal" => {
            require_keys(object, &["source", "value"])?;
            match object.get("value") {
                Some(Value::String(text)) => Ok(ScenarioValue::Literal(text.clone())),
                _ => Err(input_error(OPERATION, &format!("{path_text}.value"), "literal value must be a string")),
            }
        }
        "secret" => {
            require_keys(object, &["source", "secret_id"])?;
            Ok(ScenarioValue::Secret(required_identifier(object, "secret_id", &[&path_text, "secret_id"])?))
        }
        _ => Err(input_error(OPERATION, &path_text, "value source must be literal or secret")),
    }
}

fn normalize_http_url(value: &str, path: &str) -> Result<String, WebError> {
    let url = Url::parse(value).map_err(|_| input_error(OPERATION, path, "Invalid browser URL"))?;
    if (url.scheme() != "http" && url.scheme() != "https") || !url.username().is_empty() || url.password().is_some() {
        return Err(input_error(OPERATION, path, "Browser URLs must be HTTP(S) and omit credentials"));
    }
    Ok(url.to_string())
}

fn browser_json(mode: &ScenarioMode) -> Value {
    match mode {
        ScenarioMode::Launch { executable_path, headless } => json!({
            "mode": "launch",
            "executable_path": executable_path,
            "headless": headless,
        }),
        ScenarioMode::Connect { cdp_endpoint, target_id } => json!({
            "mode": "connect",
            "cdp_endpoint": cdp_endpoint,
            "target_id": target_id,
        }),
    }
}

fn url_json(url: &ScenarioUrl) -> Value {
    json!({
        "url": url.url,
        "query": url.query.iter().map(|(name, value)| json!({ "name": name, "value": value_json(value) })).collect::<Vec<_>>(),
    })
}

fn value_json(value: &ScenarioValue) -> Value {
    match value {
        ScenarioValue::Literal(text) => json!({ "source": "literal", "value": text }),
        ScenarioValue::Secret(secret_id) => json!({ "source": "secret", "secret_id": secret_id }),
    }
}

fn environment_json(environment: &ScenarioEnvironment) -> Value {
    json!({
        "viewport": {
            "width": environment.width,
            "height": environment.height,
            "device_scale_factor": json_number(environment.device_scale_factor),
        },
        "locale": environment.locale,
        "timezone": environment.timezone,
        "color_scheme": environment.color_scheme,
        "reduced_motion": environment.reduced_motion,
        "service_workers": environment.service_workers,
    })
}

fn action_json(action: &ScenarioAction) -> Value {
    let mut object = Map::new();
    object.insert("step_id".to_string(), json!(action.step_id()));
    if let Some(timeout_ms) = action.timeout_ms() {
        object.insert("timeout_ms".to_string(), json!(timeout_ms));
    }
    object.insert("action".to_string(), json!(action.name()));
    match action {
        ScenarioAction::Goto { destination, wait_until, .. } => {
            object.insert("destination".to_string(), url_json(destination));
            object.insert("wait_until".to_string(), json!(wait_until));
        }
        ScenarioAction::Click { locator, button, click_count, .. } => {
            object.insert("locator".to_string(), locator.to_json());
            object.insert("button".to_string(), json!(button));
            object.insert("click_count".to_string(), json!(click_count));
        }
        ScenarioAction::Fill { locator, value, .. } | ScenarioAction::Select { locator, value, .. } => {
            object.insert("locator".to_string(), locator.to_json());
            object.insert("value".to_string(), value_json(value));
        }
        ScenarioAction::Press { locator, key, .. } => {
            object.insert("locator".to_string(), locator.to_json());
            object.insert("key".to_string(), json!(key));
        }
        ScenarioAction::Check { locator, .. } | ScenarioAction::WaitFor { locator, .. } => {
            object.insert("locator".to_string(), locator.to_json());
            if let ScenarioAction::WaitFor { state, .. } = action {
                object.insert("state".to_string(), json!(state));
            }
        }
        ScenarioAction::WaitTimeout { duration_ms, .. } => {
            object.insert("duration_ms".to_string(), json!(duration_ms));
        }
    }
    Value::Object(object)
}

fn storage_json(storage: &ScenarioStorage) -> Value {
    json!({
        "cookies": storage.cookies.iter().map(|cookie| json!({
            "name": cookie.name,
            "value": value_json(&cookie.value),
            "destination": url_json(&cookie.destination),
            "http_only": cookie.http_only,
            "secure": cookie.secure,
            "same_site": cookie.same_site,
        })).collect::<Vec<_>>(),
        "local_storage": storage.local_storage.iter().map(storage_origin_json).collect::<Vec<_>>(),
        "session_storage": storage.session_storage.iter().map(storage_origin_json).collect::<Vec<_>>(),
    })
}

fn storage_origin_json(origin: &StorageOrigin) -> Value {
    json!({
        "origin": origin.origin,
        "entries": origin.entries.iter().map(|(name, value)| json!({ "name": name, "value": value_json(value) })).collect::<Vec<_>>(),
    })
}

fn secret_json(secret: &SecretDeclaration) -> Value {
    json!({ "secret_id": secret.secret_id, "environment_variable": secret.environment_variable })
}

fn capture_json(capture: &ScenarioCapture) -> Value {
    json!({
        "after_each_step": capture.after_each_step,
        "at_end": capture.at_end,
        "events": capture.events,
        "network": {
            "request_body": capture.request_body,
            "response_body": capture.response_body,
            "header_values": capture.header_values,
        },
    })
}

fn json_number(number: f64) -> Value {
    if number.fract() == 0.0 && number.is_finite() {
        Value::from(number as i64)
    } else {
        serde_json::Number::from_f64(number).map(Value::Number).unwrap_or(Value::Null)
    }
}

fn expect_object<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Map<String, Value>, WebError> {
    value.as_object().ok_or_else(|| input_error(OPERATION, &path.join("."), "Expected an object"))
}

fn require_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), WebError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(input_error(OPERATION, key, format!("Unrecognized key: \"{key}\"")));
        }
    }
    Ok(())
}

fn require_action_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), WebError> {
    require_keys(object, allowed)
}

fn required_string(object: &Map<String, Value>, key: &str, path: &[&str]) -> Result<String, WebError> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(input_error(OPERATION, &path.join("."), format!("{key} must be a non-empty string"))),
    }
}

fn required_identifier(object: &Map<String, Value>, key: &str, path: &[&str]) -> Result<String, WebError> {
    let value = required_string(object, key, path)?;
    if !is_identifier(&value) {
        return Err(input_error(OPERATION, &path.join("."), format!("{key} must be an identifier")));
    }
    Ok(value)
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn required_enum(object: &Map<String, Value>, key: &str, path: &[&str], allowed: &[&str]) -> Result<String, WebError> {
    let value = required_string(object, key, path)?;
    if !allowed.contains(&value.as_str()) {
        return Err(input_error(OPERATION, &path.join("."), format!("Unsupported {key}")));
    }
    Ok(value)
}

fn optional_enum(object: &Map<String, Value>, key: &str, default_value: &str, allowed: &[&str]) -> Result<String, WebError> {
    match object.get(key) {
        None => Ok(default_value.to_string()),
        Some(_) => required_enum(object, key, &[key], allowed),
    }
}

fn optional_timeout(object: &Map<String, Value>, path: &str) -> Result<Option<i64>, WebError> {
    match object.get("timeout_ms") {
        None => Ok(None),
        Some(_) => {
            let timeout = required_i64(object, "timeout_ms", &[path, "timeout_ms"])?;
            if timeout < 1 {
                return Err(input_error(OPERATION, &format!("{path}.timeout_ms"), "timeout_ms must be at least 1"));
            }
            Ok(Some(timeout))
        }
    }
}

fn positive_i64(object: &Map<String, Value>, key: &str, path: &str, default_value: i64) -> Result<i64, WebError> {
    let value = optional_i64(object, key, &[path, key])?.unwrap_or(default_value);
    if value < 1 {
        return Err(input_error(OPERATION, &format!("{path}.{key}"), format!("{key} must be positive")));
    }
    Ok(value)
}

fn optional_i64(object: &Map<String, Value>, key: &str, path: &[&str]) -> Result<Option<i64>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(_) => Ok(Some(required_i64(object, key, path)?)),
    }
}

fn required_i64(object: &Map<String, Value>, key: &str, path: &[&str]) -> Result<i64, WebError> {
    match object.get(key).and_then(Value::as_i64) {
        Some(value) => Ok(value),
        None => Err(input_error(OPERATION, &path.join("."), format!("{key} must be an integer"))),
    }
}

fn optional_positive_f64(value: Option<&Value>, path: &str) -> Result<Option<f64>, WebError> {
    match value {
        None => Ok(None),
        Some(Value::Number(number)) => {
            let number = number.as_f64().filter(|number| number.is_finite() && *number > 0.0).ok_or_else(|| {
                input_error(OPERATION, path, "device_scale_factor must be a positive number")
            })?;
            Ok(Some(number))
        }
        Some(_) => Err(input_error(OPERATION, path, "device_scale_factor must be a positive number")),
    }
}

fn optional_pattern(
    object: &Map<String, Value>,
    key: &str,
    default_value: &str,
    path: &[&str],
    pattern: fn(&str) -> bool,
) -> Result<String, WebError> {
    match object.get(key) {
        None => Ok(default_value.to_string()),
        Some(_) => {
            let value = required_string(object, key, path)?;
            if !pattern(&value) {
                return Err(input_error(OPERATION, &path.join("."), format!("{key} has an unsupported format")));
            }
            Ok(value)
        }
    }
}

fn is_locale(value: &str) -> bool {
    value.len() >= 2
        && value.split('-').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn is_timezone(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-'))
        })
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(input_error(OPERATION, key, format!("{key} must be a boolean"))),
    }
}

fn required_bool(object: &Map<String, Value>, key: &str, path: &str) -> Result<bool, WebError> {
    match object.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(input_error(OPERATION, &format!("{path}.{key}"), format!("{key} must be a boolean"))),
    }
}

fn optional_array<'a>(value: Option<&'a Value>, path: &str) -> Result<Option<&'a Vec<Value>>, WebError> {
    match value {
        None => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(input_error(OPERATION, path, format!("{path} must be an array"))),
    }
}
