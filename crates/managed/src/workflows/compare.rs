//! `compare_managed_members` (REA `managedMemberComparison*.ts`).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use super::{input_error, parse_managed_inspection_evidence, sha256_canonical, WR};

/// One authenticated side of a comparison.
pub struct Side {
    pub evidence_id: String,
    pub result: Value,
}

pub fn parse_side(raw: &Value) -> WR<Side> {
    let (evidence, result) = parse_managed_inspection_evidence(raw, "inspect_managed_members")?;
    Ok(Side { evidence_id: evidence.evidence_id, result })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Basis {
    ExactIlSignature,
    ExactSignature,
    StructuralMethodShape,
    FieldSignature,
}

impl Basis {
    fn name(self) -> &'static str {
        match self {
            Basis::ExactIlSignature => "exact-il-signature",
            Basis::ExactSignature => "exact-signature",
            Basis::StructuralMethodShape => "structural-method-shape",
            Basis::FieldSignature => "field-signature",
        }
    }

    fn confidence(self) -> &'static str {
        match self {
            Basis::StructuralMethodShape => "high",
            _ => "exact",
        }
    }
}

struct Keyed<'a> {
    item: &'a Value,
    exact: Option<String>,
    signature: Option<String>,
    structural: Option<String>,
}

fn string_of(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn key_method(item: &Value) -> WR<Keyed<'_>> {
    let body = &item["body"];
    let signature = &item["signature"];
    let exact = if body["status"] == "present" && !body["normalized_il_sha256"].is_null() {
        Some(sha256_canonical(&json!(["method-exact", signature["raw_sha256"], body["normalized_il_sha256"]]))?)
    } else {
        None
    };
    let signature_key = Some(sha256_canonical(&json!([
        "method-signature",
        item["declaring_type"],
        item["name"],
        signature["raw_sha256"]
    ]))?);
    let structural = if signature["parse_status"] == "decoded" && body["status"] == "present" {
        let anchors: Vec<Value> = body["anchors"]
            .as_array()
            .map(|a| a.iter().map(|x| json!([x["opcode"], x["operand_kind"]])).collect())
            .unwrap_or_default();
        let regions: Vec<Value> = body["exception_regions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| {
                        json!([
                            r["flags"],
                            r["try_length"],
                            r["handler_length"],
                            if r["class_token"].is_null() { Value::Null } else { json!("type-token") },
                            if r["filter_offset"].is_null() { Value::Null } else { json!("filter") },
                        ])
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(sha256_canonical(&json!([
            "method-structural",
            signature["kind"],
            signature["calling_convention"],
            signature["generic_parameter_count"],
            signature["parameter_count"],
            signature["return_type"],
            signature["parameter_types"],
            body["status"],
            body["header_format"],
            body["il_size"],
            body["max_stack"],
            body["init_locals"],
            body["opcode_counts"],
            anchors,
            regions,
        ]))?)
    } else {
        None
    };
    Ok(Keyed { item, exact, signature: signature_key, structural })
}

fn key_field(item: &Value) -> WR<Keyed<'_>> {
    let signature = &item["signature"];
    let exact = if signature["parse_status"] == "decoded" {
        Some(sha256_canonical(&json!(["field-exact", signature["raw_sha256"]]))?)
    } else {
        None
    };
    let signature_key = Some(sha256_canonical(&json!([
        "field-signature",
        item["declaring_type"],
        item["name"],
        signature["raw_sha256"]
    ]))?);
    let structural = Some(sha256_canonical(&json!([
        "field-structural",
        signature["kind"],
        signature["field_type"],
        item["flags"]
    ]))?);
    Ok(Keyed { item, exact, signature: signature_key, structural })
}

struct Pair {
    left: usize,
    right: usize,
    basis: Basis,
}

struct Ambiguous {
    left: Vec<usize>,
    right: Vec<usize>,
    basis: Basis,
}

struct Matches {
    pairs: Vec<Pair>,
    ambiguous: Vec<Ambiguous>,
    left_only: Vec<usize>,
    right_only: Vec<usize>,
}

#[derive(Clone, Copy)]
enum KeyKind {
    Exact,
    Signature,
    Structural,
}

fn key_of<'a>(item: &'a Keyed<'_>, kind: KeyKind) -> Option<&'a String> {
    match kind {
        KeyKind::Exact => item.exact.as_ref(),
        KeyKind::Signature => item.signature.as_ref(),
        KeyKind::Structural => item.structural.as_ref(),
    }
}

type KeyFn = KeyKind;

fn group_by(indices: &[usize], items: &[Keyed], key: KeyFn) -> Vec<(String, Vec<usize>)> {
    let mut order: Vec<(String, Vec<usize>)> = Vec::new();
    let mut lookup: HashMap<String, usize> = HashMap::new();
    for &index in indices {
        let Some(k) = key_of(&items[index], key) else { continue };
        match lookup.get(k) {
            Some(&slot) => order[slot].1.push(index),
            None => {
                lookup.insert(k.clone(), order.len());
                order.push((k.clone(), vec![index]));
            }
        }
    }
    order
}

fn match_by_keys(left: &[Keyed], right: &[Keyed], rounds: &[(Basis, KeyFn)]) -> Matches {
    let mut used_left: HashSet<usize> = HashSet::new();
    let mut used_right: HashSet<usize> = HashSet::new();
    let mut pairs = Vec::new();
    let mut ambiguous = Vec::new();
    for (basis, key) in rounds {
        let left_free: Vec<usize> = (0..left.len()).filter(|i| !used_left.contains(i)).collect();
        let right_free: Vec<usize> = (0..right.len()).filter(|i| !used_right.contains(i)).collect();
        let left_groups = group_by(&left_free, left, *key);
        let right_groups: HashMap<String, Vec<usize>> = group_by(&right_free, right, *key).into_iter().collect();
        for (k, left_items) in left_groups {
            let Some(right_items) = right_groups.get(&k) else { continue };
            if left_items.len() == 1 && right_items.len() == 1 {
                used_left.insert(left_items[0]);
                used_right.insert(right_items[0]);
                pairs.push(Pair { left: left_items[0], right: right_items[0], basis: *basis });
            } else {
                used_left.extend(left_items.iter().copied());
                used_right.extend(right_items.iter().copied());
                ambiguous.push(Ambiguous { left: left_items, right: right_items.clone(), basis: *basis });
            }
        }
    }
    Matches {
        pairs,
        ambiguous,
        left_only: (0..left.len()).filter(|i| !used_left.contains(i)).collect(),
        right_only: (0..right.len()).filter(|i| !used_right.contains(i)).collect(),
    }
}


fn call_shape(anchors: &Value, kind: &str) -> Vec<(String, String)> {
    anchors
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|x| x["operand_kind"] == kind)
                .map(|x| (string_of(&x["opcode"]).to_string(), string_of(&x["operand_kind"]).to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn method_dimensions(left: &Value, right: &Value) -> (Vec<&'static str>, bool) {
    let mut dimensions = Vec::new();
    if left["flags"] != right["flags"] || left["impl_flags"] != right["impl_flags"] {
        dimensions.push("metadata");
    }
    if left["signature"]["raw_sha256"] != right["signature"]["raw_sha256"] {
        dimensions.push("signature");
    }
    let complete = |m: &Value| m["body"]["status"] == "present" && m["body"]["truncated_instructions"] == 0;
    let left_complete = complete(left);
    let right_complete = complete(right);
    let both_absent = left["body"]["status"] == "absent" && right["body"]["status"] == "absent";
    if (left["body"]["status"] == "absent" && right_complete) || (right["body"]["status"] == "absent" && left_complete) {
        dimensions.push("availability");
    }
    if both_absent {
        return (dimensions, false);
    }
    if !left_complete || !right_complete {
        return (dimensions, true);
    }
    let (lb, rb) = (&left["body"], &right["body"]);
    if lb["normalized_il_sha256"] != rb["normalized_il_sha256"] {
        dimensions.push("cil");
    }
    if lb["opcode_counts"] != rb["opcode_counts"] {
        dimensions.push("opcode-shape");
    }
    if call_shape(&lb["anchors"], "method") != call_shape(&rb["anchors"], "method") {
        dimensions.push("call-shape");
    }
    if call_shape(&lb["anchors"], "field") != call_shape(&rb["anchors"], "field") {
        dimensions.push("field-shape");
    }
    if lb["exception_regions"] != rb["exception_regions"] {
        dimensions.push("exception-shape");
    }
    (dimensions, false)
}

fn method_identity(item: &Value) -> Value {
    json!({
        "token": item["token"],
        "declaring_type": item["declaring_type"],
        "name": item["name"],
        "signature_sha256": item["signature"]["raw_sha256"],
        "normalized_il_sha256": item["body"]["normalized_il_sha256"],
    })
}

fn field_identity(item: &Value) -> Value {
    json!({
        "token": item["token"],
        "declaring_type": item["declaring_type"],
        "name": item["name"],
        "signature_sha256": item["signature"]["raw_sha256"],
    })
}

fn unmatched() -> Value {
    json!({ "status": "unmatched", "basis": "none", "confidence": "unknown", "candidate_left_tokens": [], "candidate_right_tokens": [] })
}

fn declared_name(member: &Value) -> String {
    serde_json::to_string(&json!([member["declaring_type"], member["name"]])).unwrap_or_default()
}

struct Opposite<'a> {
    complete: bool,
    undecoded_names: &'a HashSet<String>,
    side: &'static str,
    inventory: &'static str,
}

fn absence_limitations(member: &Value, opposite: &Opposite) -> Vec<String> {
    let mut out = Vec::new();
    if !opposite.complete {
        out.push(format!(
            "unknown-within-incomplete-metadata: The {} {} inventory is incomplete, so absence was not observed.",
            opposite.side, opposite.inventory
        ));
    }
    let decoded = member["signature"]["parse_status"] == "decoded";
    if !decoded {
        out.push(format!(
            "signature-not-decoded: The member's {} signature was compared only by exact declared type, name, and raw bytes, so a changed or renamed counterpart could not be sought.",
            string_of(&member["signature"]["parse_status"])
        ));
    }
    if decoded && opposite.undecoded_names.contains(&declared_name(member)) {
        out.push(format!(
            "counterpart-signature-not-decoded: The {} {} inventory has an unpaired member with the same declared type and name whose signature was not decoded, so it may be this member with a changed signature.",
            opposite.side, opposite.inventory
        ));
    }
    out
}

struct Undecoded {
    left: HashSet<String>,
    right: HashSet<String>,
}

fn undecoded_one_sided(matches: &Matches, left: &[Keyed], right: &[Keyed]) -> Undecoded {
    let names = |indices: Vec<usize>, items: &[Keyed]| -> HashSet<String> {
        indices
            .into_iter()
            .filter(|i| items[*i].item["signature"]["parse_status"] != "decoded")
            .map(|i| declared_name(items[i].item))
            .collect()
    };
    let mut left_all: Vec<usize> = matches.left_only.clone();
    let mut right_all: Vec<usize> = matches.right_only.clone();
    for group in &matches.ambiguous {
        left_all.extend(group.left.iter().copied());
        right_all.extend(group.right.iter().copied());
    }
    Undecoded { left: names(left_all, left), right: names(right_all, right) }
}

fn ambiguity_limitation(members: &str, basis: Basis) -> String {
    if basis == Basis::ExactSignature {
        format!("Multiple managed {members} share the same declared type, name, and raw signature; REA did not guess a token remap.")
    } else if members == "methods" {
        "Multiple managed methods share the same non-name identity key; REA did not guess a token remap.".to_string()
    } else {
        "Multiple managed fields share the same signature; REA did not guess a token remap from names.".to_string()
    }
}

struct Context<'a> {
    left_id: &'a str,
    right_id: &'a str,
    left_complete: bool,
    right_complete: bool,
}

fn tokens(indices: &[usize], items: &[Keyed]) -> Vec<Value> {
    indices.iter().map(|i| items[*i].item["token"].clone()).collect()
}

fn build_method_items(matches: &Matches, left: &[Keyed], right: &[Keyed], ctx: &Context) -> WR<Vec<Value>> {
    let mut items = Vec::new();
    let links = json!([ctx.left_id, ctx.right_id]);
    for pair in &matches.pairs {
        let l = left[pair.left].item;
        let r = right[pair.right].item;
        let (observed, body_unknown) = method_dimensions(l, r);
        let mut dimensions: Vec<&str> = observed.clone();
        if body_unknown {
            dimensions.push("body-coverage");
        }
        let observed_change = !observed.is_empty();
        items.push(json!({
            "item_id": format!("mmc_method_{}", sha256_canonical(&json!({
                "left": l["token"], "right": r["token"], "basis": pair.basis.name()
            }))?),
            "status": if observed_change { "changed" } else if body_unknown { "unknown" } else { "unchanged" },
            "left": method_identity(l),
            "right": method_identity(r),
            "match": {
                "status": "matched",
                "basis": pair.basis.name(),
                "confidence": pair.basis.confidence(),
                "candidate_left_tokens": [],
                "candidate_right_tokens": [],
            },
            "dimensions": dimensions,
            "evidence_links": links,
            "limitations": if body_unknown {
                json!(["Method body facets are unknown because at least one side has unavailable or partial body data."])
            } else { json!([]) },
        }));
    }
    for group in &matches.ambiguous {
        let left_tokens = tokens(&group.left, left);
        let right_tokens = tokens(&group.right, right);
        items.push(json!({
            "item_id": format!("mmc_method_{}", sha256_canonical(&json!({
                "left": left_tokens, "right": right_tokens, "basis": group.basis.name()
            }))?),
            "status": "unknown",
            "left": null,
            "right": null,
            "match": {
                "status": "ambiguous",
                "basis": group.basis.name(),
                "confidence": "unknown",
                "candidate_left_tokens": left_tokens,
                "candidate_right_tokens": right_tokens,
            },
            "dimensions": ["availability"],
            "evidence_links": links,
            "limitations": [ambiguity_limitation("methods", group.basis)],
        }));
    }
    let undecoded = undecoded_one_sided(matches, left, right);
    for &index in &matches.left_only {
        let member = left[index].item;
        let limitations = absence_limitations(
            member,
            &Opposite { complete: ctx.right_complete, undecoded_names: &undecoded.right, side: "right", inventory: "method" },
        );
        items.push(json!({
            "item_id": format!("mmc_method_{}", sha256_canonical(&json!({ "token": member["token"], "side": "left" }))?),
            "status": if limitations.is_empty() { "removed" } else { "unknown" },
            "left": method_identity(member),
            "right": null,
            "match": unmatched(),
            "dimensions": ["availability"],
            "evidence_links": links,
            "limitations": limitations,
        }));
    }
    for &index in &matches.right_only {
        let member = right[index].item;
        let limitations = absence_limitations(
            member,
            &Opposite { complete: ctx.left_complete, undecoded_names: &undecoded.left, side: "left", inventory: "method" },
        );
        items.push(json!({
            "item_id": format!("mmc_method_{}", sha256_canonical(&json!({ "token": member["token"], "side": "right" }))?),
            "status": if limitations.is_empty() { "added" } else { "unknown" },
            "left": null,
            "right": method_identity(member),
            "match": unmatched(),
            "dimensions": ["availability"],
            "evidence_links": links,
            "limitations": limitations,
        }));
    }
    Ok(items)
}

fn build_field_items(matches: &Matches, left: &[Keyed], right: &[Keyed], ctx: &Context) -> WR<Vec<Value>> {
    let mut items = Vec::new();
    let links = json!([ctx.left_id, ctx.right_id]);
    for pair in &matches.pairs {
        let l = left[pair.left].item;
        let r = right[pair.right].item;
        let changed = l["signature"]["raw_sha256"] != r["signature"]["raw_sha256"] || l["flags"] != r["flags"];
        items.push(json!({
            "item_id": format!("mmc_field_{}", sha256_canonical(&json!({ "left": l["token"], "right": r["token"] }))?),
            "status": if changed { "changed" } else { "unchanged" },
            "left": field_identity(l),
            "right": field_identity(r),
            "match": {
                "status": "matched",
                "basis": pair.basis.name(),
                "confidence": pair.basis.confidence(),
                "candidate_left_tokens": [],
                "candidate_right_tokens": [],
            },
            "evidence_links": links,
            "limitations": [],
        }));
    }
    for group in &matches.ambiguous {
        let left_tokens = tokens(&group.left, left);
        let right_tokens = tokens(&group.right, right);
        items.push(json!({
            "item_id": format!("mmc_field_{}", sha256_canonical(&json!({ "left": left_tokens, "right": right_tokens }))?),
            "status": "unknown",
            "left": null,
            "right": null,
            "match": {
                "status": "ambiguous",
                "basis": group.basis.name(),
                "confidence": "unknown",
                "candidate_left_tokens": left_tokens,
                "candidate_right_tokens": right_tokens,
            },
            "evidence_links": links,
            "limitations": [ambiguity_limitation("fields", group.basis)],
        }));
    }
    let undecoded = undecoded_one_sided(matches, left, right);
    for &index in &matches.left_only {
        let member = left[index].item;
        let limitations = absence_limitations(
            member,
            &Opposite { complete: ctx.right_complete, undecoded_names: &undecoded.right, side: "right", inventory: "field" },
        );
        items.push(json!({
            "item_id": format!("mmc_field_{}", sha256_canonical(&json!({ "token": member["token"], "side": "left" }))?),
            "status": if limitations.is_empty() { "removed" } else { "unknown" },
            "left": field_identity(member),
            "right": null,
            "match": unmatched(),
            "evidence_links": links,
            "limitations": limitations,
        }));
    }
    for &index in &matches.right_only {
        let member = right[index].item;
        let limitations = absence_limitations(
            member,
            &Opposite { complete: ctx.left_complete, undecoded_names: &undecoded.left, side: "left", inventory: "field" },
        );
        items.push(json!({
            "item_id": format!("mmc_field_{}", sha256_canonical(&json!({ "token": member["token"], "side": "right" }))?),
            "status": if limitations.is_empty() { "added" } else { "unknown" },
            "left": null,
            "right": field_identity(member),
            "match": unmatched(),
            "evidence_links": links,
            "limitations": limitations,
        }));
    }
    Ok(items)
}

fn side_manifest(side: &Side) -> Value {
    json!({
        "evidence_id": side.evidence_id,
        "artifact_sha256": side.result["artifact"]["sha256"],
        "mvid": side.result["module"]["mvid"],
        "module_name": side.result["module"]["name"],
        "metadata_status": side.result["metadata"]["status"],
        "methods_total": side.result["methods"].as_array().map(Vec::len).unwrap_or(0),
        "fields_total": side.result["fields"].as_array().map(Vec::len).unwrap_or(0),
    })
}

fn side_coverage_status(result: &Value) -> &'static str {
    match result["coverage"]["state"].as_str() {
        Some("unavailable") => "unavailable",
        Some("complete") => "complete",
        _ => "partial",
    }
}

fn count_status(items: &[Value], status: &str) -> usize {
    items.iter().filter(|i| i["status"] == status).count()
}

/// Compare managed members with constrained exact and structural identities.
pub fn compare_managed_members(left: &Side, right: &Side) -> WR<Value> {
    let empty = Vec::new();
    let left_methods = left.result["methods"].as_array().unwrap_or(&empty);
    let right_methods = right.result["methods"].as_array().unwrap_or(&empty);
    let left_fields = left.result["fields"].as_array().unwrap_or(&empty);
    let right_fields = right.result["fields"].as_array().unwrap_or(&empty);
    let lm: Vec<Keyed> = left_methods.iter().map(key_method).collect::<WR<_>>()?;
    let rm: Vec<Keyed> = right_methods.iter().map(key_method).collect::<WR<_>>()?;
    let lf: Vec<Keyed> = left_fields.iter().map(key_field).collect::<WR<_>>()?;
    let rf: Vec<Keyed> = right_fields.iter().map(key_field).collect::<WR<_>>()?;
    let method_matches = match_by_keys(
        &lm,
        &rm,
        &[(Basis::ExactIlSignature, KeyKind::Exact), (Basis::ExactSignature, KeyKind::Signature), (Basis::StructuralMethodShape, KeyKind::Structural)],
    );
    let field_matches = match_by_keys(&lf, &rf, &[(Basis::FieldSignature, KeyKind::Exact), (Basis::ExactSignature, KeyKind::Signature)]);
    let ctx = Context {
        left_id: &left.evidence_id,
        right_id: &right.evidence_id,
        left_complete: left.result["metadata"]["status"] == "complete",
        right_complete: right.result["metadata"]["status"] == "complete",
    };
    let method_items = build_method_items(&method_matches, &lm, &rm, &ctx)?;
    let field_items = build_field_items(&field_matches, &lf, &rf, &ctx)?;
    let all: Vec<Value> = method_items.iter().chain(field_items.iter()).cloned().collect();
    let summary = json!({
        "unchanged": count_status(&all, "unchanged"),
        "changed": count_status(&all, "changed"),
        "added": count_status(&all, "added"),
        "removed": count_status(&all, "removed"),
        "unknown": count_status(&all, "unknown"),
    });
    let basis_count = |items: &[Value], basis: &str| items.iter().filter(|i| i["match"]["basis"] == basis).count();
    let matching = json!({
        "exact_il_signature": basis_count(&method_items, "exact-il-signature"),
        "exact_signature": basis_count(&all, "exact-signature"),
        "structural_method_shape": basis_count(&method_items, "structural-method-shape"),
        "field_signature": basis_count(&field_items, "field-signature"),
        "ambiguous": all.iter().filter(|i| i["match"]["status"] == "ambiguous").count(),
        "unmatched": all.iter().filter(|i| i["match"]["status"] == "unmatched").count(),
    });
    let left_status = side_coverage_status(&left.result);
    let right_status = side_coverage_status(&right.result);
    let unknown_input = left.result["coverage"]["state"] != "complete" || right.result["coverage"]["state"] != "complete";
    let coverage = json!({
        "status": if !unknown_input && left_status == "complete" && right_status == "complete" { "complete-within-inputs" } else { "partial" },
        "left_status": left_status,
        "right_status": right_status,
    });
    let mut limitations = vec![
        "Metadata tokens are build-local coordinates; matched pairs are remaps, not persistent identities.".to_string(),
        "Methods pair by exact CIL/signature, then declared type, name, and signature, then structural shape; names alone are never a matching basis.".to_string(),
        "Fields pair by exact signature, then declared type, name, and signature; an undecoded signature is compared only by its raw bytes, and an unmatched member with one stays unknown.".to_string(),
    ];
    if unknown_input {
        limitations.push("At least one managed member observation is partial.".to_string());
    }
    let comparison_id = sha256_canonical(&json!({
        "left": left.evidence_id,
        "right": right.evidence_id,
        "methods": method_items,
        "fields": field_items,
    }))?;
    Ok(json!({
        "comparison_id": format!("mmc_{comparison_id}"),
        "algorithm": {
            "name": "rea-managed-member-comparison",
            "token_identity": "build-local",
            "name_matching": "exact-signature-fallback",
        },
        "left": side_manifest(left),
        "right": side_manifest(right),
        "summary": summary,
        "matching": matching,
        "methods": method_items,
        "fields": field_items,
        "coverage": coverage,
        "evidence_links": [left.evidence_id, right.evidence_id],
        "limitations": limitations,
    }))
}

/// Evidence-level entry: the two inputs must be distinct and authenticated.
pub fn compare_evidence(left: &Value, right: &Value) -> WR<Value> {
    let left_side = parse_side(left)?;
    let right_side = parse_side(right)?;
    if left_side.evidence_id == right_side.evidence_id {
        return Err(input_error("Managed member Evidence must be distinct"));
    }
    compare_managed_members(&left_side, &right_side)
}
