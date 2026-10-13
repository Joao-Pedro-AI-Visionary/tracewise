//! Native dispatch metadata (port of `NativeDispatchMetadataInspection.ts` and the
//! symbol-only decoder of `objcSwiftMetadata.ts`).

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::{json, Value};

use crate::error::AnalysisError;

use super::Env;

/// Prefer validated binary metadata, otherwise preserve the bound provider's symbol-only coverage.
pub async fn inspect(env: &Env<'_>, max_records: usize) -> Result<Value, AnalysisError> {
    match env
        .execute("inspect_native_dispatch_metadata", json!({ "max_records": max_records }))
        .await
    {
        Ok(execution) => return Ok(execution.result),
        Err(AnalysisError::CapabilityUnavailable { .. }) => {}
        Err(other) => return Err(other),
    }
    let execution = env.execute("list_names", json!({})).await?;
    let invalid = || AnalysisError::output("list_names", "provider returned an invalid inventory");
    let items = execution.result.as_array().ok_or_else(invalid)?;
    let mut names: Vec<(String, String)> = Vec::new();
    for item in items {
        // Strict records: exactly `{ address, value }` or `{ address, name }`.
        let object = item.as_object().ok_or_else(invalid)?;
        let address = object.get("address").and_then(Value::as_str);
        let label = object
            .get("value")
            .and_then(Value::as_str)
            .or_else(|| object.get("name").and_then(Value::as_str));
        match (address, label) {
            (Some(address), Some(label)) if object.len() == 2 => names.push((address.to_string(), label.to_string())),
            _ => return Err(invalid()),
        }
    }
    let subject_sha = env.subject.as_ref().map(|s| s.digest.sha256.clone());
    Ok(json!({
        "target_sha256": subject_sha,
        "provider": execution.provider.to_json(),
        "analysis_profile_digest": execution.analysis_profile.as_ref().map(|p| p.digest.clone()),
        "result": decode_symbols(&names, max_records),
    }))
}

fn symbol_evidence(name: &str, address: &str) -> Value {
    json!([{
        "kind": "symbol",
        "description": format!("Provider symbol {name}"),
        "location": { "address": address, "file_offset": Value::Null },
        "artifact_path": Value::Null,
        "artifact_sha256": Value::Null,
    }])
}

fn parse_metadata_address(address: &str) -> Option<u64> {
    let re = Regex::new(r"(?i)(?:^|:)0x([0-9a-f]+)$").ok()?;
    let value = u64::from_str_radix(re.captures(address)?.get(1)?.as_str(), 16).ok()?;
    (value <= 9_007_199_254_740_991).then_some(value)
}

/// Decode only facts visible in a provider's existing name inventory.
pub fn decode_symbols(names: &[(String, String)], max_records: usize) -> Value {
    let class_re = Regex::new(r"(?:OBJC_CLASS_|OBJC_METACLASS_)\$_([^\s]+)").unwrap();
    let method_re = Regex::new(r"^([+-])\[([^\s\]]+)\s+([^\]]+)\]$").unwrap();
    let swift_re = Regex::new(r"^(?:_?\$s|_Tt)").unwrap();
    let examined = &names[..names.len().min(max_records)];
    let mut class_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // (class, selector, type) -> implementation, in first-insertion order like a JS Map.
    let mut implementations: Vec<((String, String, String), Value)> = Vec::new();
    let mut swift_symbols: Vec<Value> = Vec::new();
    for (address, name) in examined {
        if let Some(found) = class_re.captures(name) {
            class_names.insert(found[1].to_string());
        }
        if let Some(found) = method_re.captures(name) {
            let method_type = if &found[1] == "+" { "class" } else { "instance" };
            let class = found[2].to_string();
            let selector = found[3].to_string();
            let key = (class.clone(), selector.clone(), method_type.to_string());
            let value = json!({
                    "class_name": class,
                    "selector": selector,
                    "method_type": method_type,
                    "implementation_address": address,
                    "location": { "address": address, "file_offset": Value::Null },
                    "decode": { "status": "partial", "reason": "symbol_name_only" },
                    "evidence": symbol_evidence(name, address),
            });
            match implementations.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => implementations.push((key, value)),
            }
            class_names.insert(class);
        }
        if swift_re.is_match(name) {
            swift_symbols.push(json!({
                "mangled_name": name,
                "address": address,
                "decode": { "status": "partial", "reason": "mangled_symbol_not_demangled" },
                "evidence": symbol_evidence(name, address),
            }));
        }
    }
    let mut methods_by_class: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (_, implementation) in implementations.iter() {
        let class = implementation["class_name"].as_str().unwrap_or_default().to_string();
        methods_by_class.entry(class).or_default().push(json!({
            "selector": implementation["selector"],
            "method_type": implementation["method_type"],
            "address": implementation["implementation_address"].as_str().and_then(parse_metadata_address),
            "is_required": Value::Null,
            "is_optional": Value::Null,
        }));
    }
    let classes: Vec<Value> = class_names
        .iter()
        .map(|name| {
            json!({
                "name": name,
                "super_class": Value::Null,
                "is_meta_class": Value::Null,
                "is_root_class": Value::Null,
                "methods": methods_by_class.get(name).cloned().unwrap_or_default(),
                "properties": [],
                "protocols": [],
                "ivar_count": Value::Null,
                "instance_size": Value::Null,
            })
        })
        .collect();
    let mut decoded: Vec<Value> = implementations.iter().map(|(_, v)| v.clone()).collect();
    decoded.sort_by_key(|i| {
        serde_json::to_string(&json!([i["class_name"], i["selector"]])).unwrap_or_default()
    });
    let truncated = names.len() > examined.len();
    let swift = !swift_symbols.is_empty();
    json!({
        "objc_classes": classes,
        "objc_protocols": [],
        "objc_categories": [],
        "swift_decls": [],
        "objc_ivars": [],
        "objc_protocol_records": [],
        "objc_dispatch_implementations": decoded,
        "swift_conformances": [],
        "swift_dispatch_slots": [],
        "swift_symbols": swift_symbols,
        "relative_pointers": [],
        "coverage": [
            {
                "facet": "objc_class_symbols",
                "status": "partial",
                "reason": if truncated { "record_limit_reached_and_symbol_names_are_not_runtime_class_metadata" } else { "symbol_names_do_not_recover_all_runtime_class_metadata" },
                "examined": examined.len(),
                "decoded": classes.len(),
            },
            {
                "facet": "objc_dispatch_implementations",
                "status": if decoded.is_empty() { "unsupported" } else { "partial" },
                "reason": if truncated {
                    "record_limit_reached_and_only_symbolized_methods_are_resolved"
                } else if !decoded.is_empty() {
                    "only_symbolized_methods_are_resolved"
                } else {
                    "provider_name_inventory_has_no_objc_method_symbols"
                },
                "examined": examined.len(),
                "decoded": decoded.len(),
            },
            {
                "facet": "objc_ivar_layouts",
                "status": "unsupported",
                "reason": "symbol_inventory_does_not_expose_runtime_ivar_layouts",
                "examined": 0,
                "decoded": 0,
            },
            {
                "facet": "swift_declarations",
                "status": if swift { "partial" } else { "unsupported" },
                "reason": if swift { "symbols_are_not_demangled_declarations" } else { "no_swift_symbols_observed" },
                "examined": swift_symbols.len(),
                "decoded": 0,
            },
            {
                "facet": "swift_dispatch_tables",
                "status": "unsupported",
                "reason": "provider_name_inventory_does_not_decode_witness_or_class_vtables",
                "examined": 0,
                "decoded": 0,
            },
            {
                "facet": "relative_pointers",
                "status": "unsupported",
                "reason": "provider_name_inventory_does_not_decode_binary_relative_pointers",
                "examined": 0,
                "decoded": 0,
            },
        ],
        "db_save_result": Value::Null,
    })
}
