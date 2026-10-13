//! `verify_managed_native_boundaries` (REA `managedNativeVerification*.ts`).

use std::collections::HashSet;

use serde_json::{json, Value};

use super::{input_error, parse_evidence, parse_managed_inspection_evidence, sha256_canonical, WR};

#[derive(Clone)]
struct NativeSymbol {
    evidence_id: String,
    operation: String,
    name: String,
    address: Option<String>,
    module_name: Option<String>,
    module_path: Option<String>,
    source: &'static str,
}

impl NativeSymbol {
    fn to_json(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "operation": self.operation,
            "name": self.name,
            "address": self.address,
            "module_name": self.module_name,
            "module_path": self.module_path,
            "source": self.source,
        })
    }
}

struct Native {
    symbols: Vec<NativeSymbol>,
    accepted: usize,
    unsupported: usize,
}

fn optional_text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn collect_native_symbols(observations: &[Value]) -> WR<Native> {
    let mut symbols = Vec::new();
    let mut accepted = 0;
    let mut unsupported = 0;
    for raw in observations {
        let evidence = parse_evidence(raw)?;
        let module_name = evidence.subject.as_ref().map(|s| s.name.clone());
        let module_path = evidence.subject.as_ref().map(|s| s.local_path.clone());
        match evidence.operation.as_str() {
            "inspect_macho" => {
                accepted += 1;
                let items = evidence.normalized_result["exports"]["items"]
                    .as_array()
                    .ok_or_else(|| input_error("inspect_macho Evidence has no exports.items"))?;
                for symbol in items {
                    symbols.push(NativeSymbol {
                        evidence_id: evidence.evidence_id.clone(),
                        operation: evidence.operation.clone(),
                        name: symbol["name"].as_str().unwrap_or_default().to_string(),
                        address: optional_text(&symbol["address"]),
                        module_name: module_name.clone(),
                        module_path: module_path.clone(),
                        source: "macho-export",
                    });
                }
            }
            "analyze_function" => {
                accepted += 1;
                let procedure = &evidence.normalized_result["procedure"];
                symbols.push(NativeSymbol {
                    evidence_id: evidence.evidence_id.clone(),
                    operation: evidence.operation.clone(),
                    name: procedure["name"].as_str().unwrap_or_default().to_string(),
                    address: optional_text(&procedure["address"]),
                    module_name,
                    module_path,
                    source: "function-dossier",
                });
            }
            _ => unsupported += 1,
        }
    }
    Ok(Native { symbols, accepted, unsupported })
}

fn same_symbol_name(expected: &str, native: &NativeSymbol) -> bool {
    let name = if native.source == "macho-export" && native.name.starts_with('_') { &native.name[1..] } else { &native.name };
    expected == name
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn strip_native_extension(name: &str) -> &str {
    for ext in [".dll", ".dylib", ".so", ".node", ".exe"] {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem;
        }
    }
    name
}

fn normalize_module(value: &str) -> String {
    strip_native_extension(&basename(value).to_lowercase()).to_string()
}

fn native_module_identities(value: &str) -> HashSet<String> {
    let filename = basename(value).to_lowercase();
    let stem = normalize_module(&filename);
    let mut identities = HashSet::new();
    identities.insert(stem.clone());
    if (filename.ends_with(".dylib") || filename.ends_with(".so")) && stem.starts_with("lib") {
        identities.insert(stem["lib".len()..].to_string());
    }
    identities
}

fn module_compatible(scope: Option<&str>, symbol: &NativeSymbol) -> bool {
    let Some(scope) = scope else { return true };
    let expected = normalize_module(scope);
    [&symbol.module_name, &symbol.module_path]
        .into_iter()
        .flatten()
        .any(|value| native_module_identities(value).contains(&expected))
}

fn candidate_names(import: &Value) -> Vec<String> {
    let import_name = import["import_name"].as_str().unwrap_or_default().to_string();
    let mut names = vec![import_name.clone()];
    if import["no_mangle"] != true {
        let mut push = |name: String| {
            if !names.contains(&name) {
                names.push(name);
            }
        };
        if import["char_set"] == "unicode" {
            push(format!("{import_name}W"));
        }
        if import["char_set"] == "ansi" {
            push(format!("{import_name}A"));
        }
        if import["call_convention"] == "stdcall" {
            push(format!("_{import_name}"));
            push(format!("_{import_name}@0"));
        }
    }
    names
}

struct MatchResult {
    status: &'static str,
    basis: &'static str,
    confidence: &'static str,
    matched: Option<NativeSymbol>,
    candidates: Vec<NativeSymbol>,
}

fn match_pinvoke(import: &Value, symbols: &[NativeSymbol], supported_native_evidence: usize) -> MatchResult {
    let names = candidate_names(import);
    let all: Vec<NativeSymbol> =
        symbols.iter().filter(|symbol| names.iter().any(|name| same_symbol_name(name, symbol))).cloned().collect();
    if all.is_empty() {
        return MatchResult {
            status: "unresolved",
            basis: if supported_native_evidence > 0 { "no-native-candidate" } else { "unsupported-native-evidence" },
            confidence: "unknown",
            matched: None,
            candidates: vec![],
        };
    }
    let scope = import["import_scope_name"].as_str();
    let import_name = import["import_name"].as_str().unwrap_or_default();
    let exact = all.iter().find(|symbol| import_name == symbol.name && module_compatible(scope, symbol));
    let decorated = all.iter().find(|symbol| module_compatible(scope, symbol));
    let selected = exact.or(decorated).unwrap_or(&all[0]).clone();
    if !module_compatible(scope, &selected) {
        return MatchResult {
            status: "contradicted",
            basis: "module-mismatch",
            confidence: "unknown",
            matched: Some(selected),
            candidates: all,
        };
    }
    if exact.is_some() {
        return MatchResult {
            status: "verified",
            basis: if selected.source == "macho-export" { "exact-export-name" } else { "exact-function-name" },
            confidence: "observed",
            matched: Some(selected),
            candidates: all,
        };
    }
    MatchResult {
        status: "inferred",
        basis: "decorated-name-candidate",
        confidence: "inferred",
        matched: Some(selected),
        candidates: all,
    }
}

fn pinvoke_limitations(status: &str, import: &Value) -> Vec<&'static str> {
    let mut out = Vec::new();
    if import["import_scope_name"].is_null() {
        out.push("Managed declaration does not name an import scope/module.");
    }
    if status == "inferred" {
        out.push("Native symbol matched a decorated candidate rather than the exact declared import name.");
    }
    if status == "contradicted" {
        out.push("A symbol name candidate exists, but the supplied native Evidence module identity does not match the managed import scope.");
    }
    if status == "unresolved" {
        out.push("No supplied native export/function Evidence matched this declared import.");
    }
    out
}

fn verify_pinvoke(import: &Value, managed_evidence_id: &str, native: &Native) -> WR<Value> {
    let managed = json!({
        "token": import["token"],
        "member_token": import["member_token"],
        "member_name": import["member_name"],
        "import_name": import["import_name"],
        "import_scope_name": import["import_scope_name"],
        "no_mangle": import["no_mangle"],
        "char_set": import["char_set"],
        "call_convention": import["call_convention"],
        "declaration_verification": import["verification"],
    });
    let selection = match_pinvoke(import, &native.symbols, native.accepted);
    let limitations = pinvoke_limitations(selection.status, import);
    let candidates: Vec<Value> = selection.candidates.iter().map(NativeSymbol::to_json).collect();
    let item_id = sha256_canonical(&json!({
        "managedEvidenceId": managed_evidence_id,
        "token": import["token"],
        "importName": import["import_name"],
        "importScope": import["import_scope_name"],
        "candidates": candidates,
    }))?;
    let mut link_ids: Vec<String> = vec![managed_evidence_id.to_string()];
    for candidate in &selection.candidates {
        if !link_ids.contains(&candidate.evidence_id) {
            link_ids.push(candidate.evidence_id.clone());
        }
    }
    Ok(json!({
        "item_id": format!("mnv_pinvoke_{item_id}"),
        "managed": managed,
        "status": selection.status,
        "basis": selection.basis,
        "confidence": selection.confidence,
        "matched_native": selection.matched.as_ref().map(NativeSymbol::to_json),
        "candidates": candidates,
        "evidence_links": link_ids,
        "limitations": limitations,
    }))
}

/// Verify managed P/Invoke declarations against authenticated native Evidence.
pub fn verify_managed_native_boundaries(managed_boundaries: &Value, native_observations: &[Value]) -> WR<Value> {
    // Input-level invariants (strict schema refinement).
    let managed_id = managed_boundaries["evidence_id"].as_str().unwrap_or_default();
    let mut seen: HashSet<&str> = HashSet::new();
    for observation in native_observations {
        let id = observation["evidence_id"].as_str().unwrap_or_default();
        if id == managed_id {
            return Err(input_error("Native observation Evidence must be distinct from managed boundary Evidence"));
        }
        if !seen.insert(id) {
            return Err(input_error("Native observation Evidence IDs must be unique"));
        }
    }
    let (managed_evidence, managed) =
        parse_managed_inspection_evidence(managed_boundaries, "inspect_managed_native_boundaries")?;
    let native = collect_native_symbols(native_observations)?;
    let empty = Vec::new();
    let imports = managed["pinvoke_imports"].as_array().unwrap_or(&empty);
    let mut verified = Vec::new();
    for import in imports {
        verified.push(verify_pinvoke(import, &managed_evidence.evidence_id, &native)?);
    }
    let count = |status: &str| verified.iter().filter(|item| item["status"] == status).count();
    let native_body_unresolved = managed["native_implementations"]
        .as_array()
        .map(|items| items.iter().filter(|item| item["boundary_kind"] != "pinvoke").count())
        .unwrap_or(0);
    let coverage_complete = managed["coverage"]["state"] == "complete" && native.unsupported == 0;
    let mut limitations: Vec<String> = vec![
        "P/Invoke verification checks declared import names against supplied native export or function-name Evidence only.".into(),
        "A matching native symbol verifies that a candidate export/function was observed; it does not prove CLR binding, marshaling behavior, call reachability, or runtime loading.".into(),
        "Missing supplied native symbols are reported as unresolved, not proof that a dependency cannot exist.".into(),
        "Managed metadata tokens and method RVAs are not interpreted as native addresses.".into(),
    ];
    if managed["coverage"]["state"] != "complete" {
        limitations.push("Managed boundary input is partial or unavailable.".into());
    }
    if native.unsupported != 0 {
        limitations.push("Some native Evidence operations were unsupported by this workflow.".into());
    }
    let mut evidence_links: Vec<String> = vec![managed_evidence.evidence_id.clone()];
    for observation in native_observations {
        evidence_links.push(observation["evidence_id"].as_str().unwrap_or_default().to_string());
    }
    let without_id = json!({
        "algorithm": {
            "name": "rea-managed-native-verification",
            "token_identity": "build-local",
            "token_to_address_mapping": "not-inferred",
        },
        "managed_boundary": {
            "evidence_id": managed_evidence.evidence_id,
            "artifact_sha256": managed["artifact"]["sha256"],
            "artifact_path": managed["artifact"]["path"],
            "mvid": managed["module"]["mvid"],
            "metadata_status": managed["metadata"]["status"],
            "pinvoke_imports_total": imports.len(),
            "native_implementations_total": managed["native_implementations"].as_array().map(Vec::len).unwrap_or(0),
            "coverage_state": managed["coverage"]["state"],
        },
        "native_observations": {
            "total": native_observations.len(),
            "accepted": native.accepted,
            "unsupported": native.unsupported,
            "symbols": native.symbols.len(),
        },
        "summary": {
            "verified": count("verified"),
            "inferred": count("inferred"),
            "unresolved": count("unresolved"),
            "contradicted": count("contradicted"),
            "native_body_unresolved": native_body_unresolved,
        },
        "pinvoke_imports": verified,
        "native_implementations": {
            "unresolved": native_body_unresolved,
            "reason": "Managed metadata tokens and RVAs are not translated to native provider addresses by this workflow; C++/CLI, ReadyToRun, and native-body mappings require explicit provider-supported bridge evidence.",
        },
        "coverage": { "status": if coverage_complete { "complete-within-inputs" } else { "partial" } },
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let verification_id = sha256_canonical(&without_id)?;
    let mut result = without_id;
    result["verification_id"] = json!(format!("mnv_{verification_id}"));
    Ok(result)
}
