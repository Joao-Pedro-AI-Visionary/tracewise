//! MCP-layer input validation for the two derived tools.
//!
//! REA parses tool arguments with zod before the handler runs, and the text of that failure
//! is what callers see. The catalog JSON Schema (`contract_input`) cannot reproduce zod's
//! wording for Evidence records (custom messages, `nonoptional`, enum wording) or the
//! `superRefine` checks on analysis profiles, so the two Evidence-bearing schemas are
//! validated here first, in zod issue order. The catalog parser then runs as the generic
//! gate and supplies the defaulted arguments.

use regex::Regex;
use serde_json::Value;

use super::dossier::{child, Check, Issue};
use super::evidence_refinement_issues;
use crate::contract_input::parse_contract_input;

const FORMATS: [&str; 24] = [
    "hopper",
    "analysis-database",
    "mach-o",
    "elf",
    "pe",
    "dos-mz",
    "dos-com",
    "zip",
    "ipa",
    "apk",
    "msix",
    "appx",
    "asar",
    "dmg",
    "pkg",
    "plist",
    "javascript",
    "source-map",
    "directory",
    "file",
    "unknown",
    "mach-o-universal",
    "javascript-bundle",
    "entitlements",
];
const ARCHITECTURES: [&str; 5] = ["x86", "x86_64", "arm", "arm64", "mips"];
const CONFIDENCES: [&str; 3] = ["observed", "derived", "inferred"];
const AUTHORITIES: [&str; 5] = [
    "shipped-artifact",
    "controlled-replay",
    "historical-reference",
    "external-service",
    "analyst-inference",
];
const ISOLATIONS: [&str; 4] = ["none", "process", "container", "virtual-machine"];
const LOCATION_KINDS: [&str; 5] = ["address", "address-range", "artifact-path", "file-offset", "file-offset-range"];
const ADDRESS_PATTERN: &str = r"^(?:(?:[A-Za-z0-9._~\x2d]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$";

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn digest(check: &mut Check, path: &[String], value: Option<&Value>) {
    match value {
        Some(Value::String(text)) => {
            if !is_digest(text) {
                check.push(path, "Invalid string: must match pattern /^[a-f0-9]{64}$/u");
            }
        }
        other => check.type_error(path, "string", other),
    }
}

fn evidence_id(check: &mut Check, path: &[String], value: Option<&Value>) {
    match value {
        Some(Value::String(text)) => {
            if !text.strip_prefix("ev_").is_some_and(is_digest) {
                check.push(path, "Expected a ev_ prefixed lowercase sha256 digest");
            }
        }
        other => check.type_error(path, "string", other),
    }
}

fn option(check: &mut Check, path: &[String], value: Option<&Value>, options: &[&str]) {
    if !value.and_then(Value::as_str).is_some_and(|text| options.contains(&text)) {
        let list: Vec<String> = options.iter().map(|o| format!("\"{o}\"")).collect();
        check.push_abort(path, format!("Invalid option: expected one of {}", list.join("|")));
    }
}

fn nullable_option(check: &mut Check, path: &[String], value: Option<&Value>, options: &[&str]) {
    if !matches!(value, Some(Value::Null)) {
        option(check, path, value, options);
    }
}

fn nonnegative_integer(check: &mut Check, path: &[String], value: Option<&Value>) {
    check_integer(check, path, value);
}

fn check_integer(check: &mut Check, path: &[String], value: Option<&Value>) {
    match value {
        Some(Value::Number(number)) => {
            let float = number.as_f64().unwrap_or(0.0);
            if float.fract() != 0.0 {
                check.push_abort(path, "Invalid input: expected int, received number");
            } else if float < 0.0 {
                check.push(path, "Too small: expected number to be >=0");
            }
        }
        other => check.type_error(path, "number", other),
    }
}

fn nullable_object<'a>(
    check: &mut Check,
    path: &[String],
    value: Option<&'a Value>,
) -> Option<&'a serde_json::Map<String, Value>> {
    if matches!(value, Some(Value::Null)) {
        None
    } else {
        check.object(path, value)
    }
}

fn subject(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = nullable_object(check, path, value) else { return };
    check.string(&child(path, "name"), map.get("name"), 1);
    let digest_path = child(path, "digest");
    if let Some(inner) = check.object(&digest_path, map.get("digest")) {
        digest(check, &child(&digest_path, "sha256"), inner.get("sha256"));
    }
    option(check, &child(path, "format"), map.get("format"), &FORMATS);
    nullable_option(check, &child(path, "architecture"), map.get("architecture"), &ARCHITECTURES);
    check.string(&child(path, "local_path"), map.get("local_path"), 0);
}

fn json_object(check: &mut Check, path: &[String], value: Option<&Value>) {
    match value {
        None => check.push_abort(path, "Invalid input: expected nonoptional, received undefined"),
        Some(Value::Object(_)) => {}
        Some(_) => check.push(path, "Expected JSON object"),
    }
}

fn json_value(check: &mut Check, path: &[String], value: Option<&Value>) {
    if value.is_none() {
        check.push_abort(path, "Invalid input: expected nonoptional, received undefined");
    }
}

fn analysis_profile(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = nullable_object(check, path, value) else { return };
    let provider_path = child(path, "provider");
    if let Some(provider) = check.object(&provider_path, map.get("provider")) {
        for key in ["id", "name", "version"] {
            check.string(&child(&provider_path, key), provider.get(key), 1);
        }
    }
    json_object(check, &child(path, "parameters"), map.get("parameters"));
    digest(check, &child(path, "digest"), map.get("digest"));
}

fn location(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = check.object(path, value) else { return };
    let kind = map.get("kind").and_then(Value::as_str);
    match kind {
        Some("address") => check.string(&child(path, "address"), map.get("address"), 1),
        Some("address-range") => {
            check.string(&child(path, "start"), map.get("start"), 1);
            check.string(&child(path, "end"), map.get("end"), 1);
        }
        Some("artifact-path") => check.string(&child(path, "path"), map.get("path"), 1),
        Some("file-offset") => nonnegative_integer(check, &child(path, "offset"), map.get("offset")),
        Some("file-offset-range") => {
            nonnegative_integer(check, &child(path, "start"), map.get("start"));
            nonnegative_integer(check, &child(path, "end"), map.get("end"));
        }
        _ => {
            let list: Vec<String> = LOCATION_KINDS.iter().map(|k| format!("'{k}'")).collect();
            check.push_abort(
                &child(path, "kind"),
                format!("Invalid discriminator value. Expected {}", list.join(" | ")),
            );
        }
    }
}

/// `evidenceSchema`: the strict record, then its profile refinements (only when the record
/// itself is well formed, as zod skips refinements after other issues).
fn evidence(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = check.object(path, value) else { return };
    let before = check.aborts;
    evidence_id(check, &child(path, "evidence_id"), map.get("evidence_id"));
    subject(check, &child(path, "subject"), map.get("subject"));
    let provider_path = child(path, "provider");
    if let Some(provider) = check.object(&provider_path, map.get("provider")) {
        check.string(&child(&provider_path, "id"), provider.get("id"), 1);
        check.string(&child(&provider_path, "name"), provider.get("name"), 1);
        match provider.get("version") {
            Some(Value::Null) => {}
            other => check.string(&child(&provider_path, "version"), other, 0),
        }
    }
    analysis_profile(check, &child(path, "analysis_profile"), map.get("analysis_profile"));
    check.string(&child(path, "predicate_type"), map.get("predicate_type"), 1);
    check.string(&child(path, "operation"), map.get("operation"), 1);
    json_object(check, &child(path, "parameters"), map.get("parameters"));
    if !matches!(map.get("raw_result"), Some(Value::Null)) {
        json_value(check, &child(path, "raw_result"), map.get("raw_result"));
    }
    json_value(check, &child(path, "normalized_result"), map.get("normalized_result"));
    option(check, &child(path, "confidence"), map.get("confidence"), &CONFIDENCES);
    option(check, &child(path, "authority"), map.get("authority"), &AUTHORITIES);
    let environment_path = child(path, "environment");
    if let Some(environment) = nullable_object(check, &environment_path, map.get("environment")) {
        for key in ["id", "platform", "architecture"] {
            check.string(&child(&environment_path, key), environment.get(key), 1);
        }
        option(check, &child(&environment_path, "isolation"), environment.get("isolation"), &ISOLATIONS);
    }
    let limitations_path = child(path, "limitations");
    if let Some(items) = check.array(&limitations_path, map.get("limitations")) {
        for (index, item) in items.iter().enumerate() {
            check.string(&child(&limitations_path, index), Some(item), 0);
        }
    }
    let locations_path = child(path, "locations");
    if let Some(items) = check.array(&locations_path, map.get("locations")) {
        for (index, item) in items.iter().enumerate() {
            location(check, &child(&locations_path, index), Some(item));
        }
    }
    let links_path = child(path, "evidence_links");
    if let Some(items) = check.array(&links_path, map.get("evidence_links")) {
        for (index, item) in items.iter().enumerate() {
            evidence_id(check, &child(&links_path, index), Some(item));
        }
    }
    check.strict_keys(
        path,
        map,
        &[
            "evidence_id",
            "subject",
            "provider",
            "analysis_profile",
            "predicate_type",
            "operation",
            "parameters",
            "raw_result",
            "normalized_result",
            "confidence",
            "authority",
            "environment",
            "limitations",
            "locations",
            "evidence_links",
        ],
    );
    if check.aborts == before {
        for issue in evidence_refinement_issues(&Value::Object(map.clone())) {
            let mut full = path.to_vec();
            full.extend(issue.path);
            check.push(&full, issue.message);
        }
    }
}

fn address_input(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = check.object(path, value) else { return };
    let address_path = child(path, "address");
    match map.get("address") {
        Some(Value::String(text)) => {
            let pattern = Regex::new(ADDRESS_PATTERN).expect("valid pattern");
            if !pattern.is_match(text) {
                check.push(&address_path, format!("Invalid string: must match pattern /{ADDRESS_PATTERN}/u"));
            }
        }
        other => check.type_error(&address_path, "string", other),
    }
    check.strict_keys(path, map, &["address"]);
}

fn format_issue(issue: &Issue) -> String {
    if issue.path.is_empty() {
        issue.message.clone()
    } else {
        format!("{}: {}", issue.path.join("."), issue.message)
    }
}

/// zod issues for a derived tool's arguments (empty when they are well formed).
pub fn input_issues(tool: &str, arguments: &Value) -> Vec<Issue> {
    let Some(map) = arguments.as_object() else {
        return Vec::new();
    };
    let mut check = Check {
        issues: Vec::new(),
        aborts: 0,
    };
    let root: Vec<String> = Vec::new();
    match tool {
        "compare_functions" => {
            evidence(&mut check, &child(&root, "left"), map.get("left"));
            evidence(&mut check, &child(&root, "right"), map.get("right"));
            check.strict_keys(&root, map, &["left", "right"]);
        }
        "build_call_path" => {
            let functions_path = child(&root, "functions");
            if let Some(items) = check.array(&functions_path, map.get("functions")) {
                if items.is_empty() {
                    check.push(&functions_path, "Too small: expected array to have >=1 items");
                }
                for (index, item) in items.iter().enumerate() {
                    evidence(&mut check, &child(&functions_path, index), Some(item));
                }
            }
            address_input(&mut check, &child(&root, "start"), map.get("start"));
            address_input(&mut check, &child(&root, "goal"), map.get("goal"));
            check.strict_keys(&root, map, &["functions", "start", "goal"]);
        }
        _ => {}
    }
    check.issues
}

/// Parse a derived tool's arguments the way REA's MCP layer does. Failures are the SDK's
/// input error text.
pub fn validate_tool_input(tool: &str, arguments: &Value) -> Result<Value, String> {
    let prefix = format!("Input validation error: Invalid arguments for tool {tool}: ");
    let issues = input_issues(tool, arguments);
    if !issues.is_empty() {
        let lines: Vec<String> = issues.iter().map(format_issue).collect();
        return Err(format!("{prefix}{}", lines.join(", ")));
    }
    // The SDK joins issues with `, `; the shared catalog parser joins them with `; `.
    parse_contract_input(tool, arguments).map_err(|message| match message.strip_prefix(&prefix) {
        Some(rest) => format!("{prefix}{}", rest.replace("; ", ", ")),
        None => message,
    })
}
