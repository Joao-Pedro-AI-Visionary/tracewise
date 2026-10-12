//! Port of REA `domain/reconstructionCoverage.ts`,
//! `reconstructionCoverageEvaluation.ts`, and `application/ReconstructionCoverageService.ts`.
//!
//! The result is a plain JSON value (REA returns it through `toCallToolResult`,
//! not as Evidence). `now_epoch_ms` replaces REA's `Date.now()`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};
use tracewise_domain::bundle::parse_evidence_bundle;

use super::common::*;
use crate::error::JsError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    artifact_id: String,
    artifact_sha256: String,
    version: String,
    environment_sha256: String,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Surface {
    surface_id: String,
    family: String,
    artifact_id: String,
    occurrence_id: Option<String>,
    location: String,
    authority: String,
    dependency_surface_ids: Vec<String>,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    surface_id: String,
    ownership: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    claim_id: String,
    title: String,
    kind: String,
    surface_ids: Vec<String>,
    required_dimensions: Vec<String>,
    required_authority: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierResult {
    verifier_id: String,
    contract_sha256: String,
    observed_at: String,
    status: String,
    covered_claim_ids: Vec<String>,
    covered_dimensions: Vec<String>,
    artifact_sha256s: Vec<String>,
    owner_sha256s: Vec<String>,
    normalization_sha256: String,
    repeats: u64,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contradiction {
    contradiction_id: String,
    status: String,
    surface_ids: Vec<String>,
    claim_ids: Vec<String>,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProof {
    proof_id: String,
    kind: String,
    status: String,
    artifact_sha256s: Vec<String>,
    evidence_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    boundary_id: String,
    title: String,
    required_surface_ids: Vec<String>,
    required_claim_ids: Vec<String>,
    required_package_proof_kinds: Vec<String>,
    allowed_dispositions: Vec<String>,
    allowed_unknown_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    evidence_bundle: Value,
    artifacts: Vec<Artifact>,
    surfaces: Vec<Surface>,
    owners: Vec<Owner>,
    claims: Vec<Claim>,
    verifier_contracts: Vec<Value>,
    verifier_results: Vec<VerifierResult>,
    residual_unknown_ids: Vec<String>,
    contradictions: Vec<Contradiction>,
    package_proofs: Vec<PackageProof>,
    boundaries: Vec<Boundary>,
}

struct Contract {
    verifier_id: String,
    claim_ids: Vec<String>,
    dimensions: Vec<String>,
    authority: String,
    max_age_ms: i64,
    minimum_repeats: u64,
    normalization_sha256: String,
    contract_sha256: String,
}

enum Ownership {
    Implemented {
        owner_sha256: String,
        path_state: String,
        package_state: String,
        authority_route: String,
    },
    Disposition(String),
}

/// `^[A-Za-z][A-Za-z0-9._:/-]{0,199}$`.
fn is_stable_id(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 200
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c))
}

fn non_blank(value: &str) -> bool {
    !value.trim().is_empty()
}

fn check(condition: bool, message: &str) -> Result<(), JsError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message.to_string()))
    }
}

fn stable_ids(values: &[String], min: usize, label: &str) -> Result<(), JsError> {
    check(values.len() >= min && values.iter().all(|v| is_stable_id(v)), label)
}

fn evidence_ids(values: &[String], min: usize, label: &str) -> Result<(), JsError> {
    check(values.len() >= min && values.iter().all(|v| is_evidence_id(v)), label)
}

fn digests(values: &[String], min: usize, label: &str) -> Result<(), JsError> {
    check(values.len() >= min && values.iter().all(|v| is_digest(v)), label)
}

const PROOF_AUTHORITIES: [&str; 4] = ["shipped-artifact", "controlled-replay", "live-observation", "external"];
const PACKAGE_PROOF_KINDS: [&str; 5] = [
    "build",
    "clean-install",
    "package-contents",
    "runtime-routing",
    "authority-independence",
];

fn parse_contract(value: &Value) -> Result<Contract, JsError> {
    const KEYS: [&str; 10] = [
        "verifier_id",
        "claim_ids",
        "dimensions",
        "authority",
        "max_age_ms",
        "minimum_repeats",
        "normalization_sha256",
        "normalization_removes_dimensions",
        "contract_sha256",
        "",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| invalid("verifier contract must be an object"))?;
    check(
        object.keys().all(|k| KEYS[..9].contains(&k.as_str())) && object.len() == 9,
        "verifier contract has unexpected or missing properties",
    )?;
    let string = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let list = |key: &str| -> Vec<String> {
        object
            .get(key)
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let positive = |key: &str| object.get(key).and_then(Value::as_i64).filter(|n| *n >= 1);
    let contract = Contract {
        verifier_id: string("verifier_id"),
        claim_ids: list("claim_ids"),
        dimensions: list("dimensions"),
        authority: string("authority"),
        max_age_ms: positive("max_age_ms").ok_or_else(|| invalid("max_age_ms must be a positive integer"))?,
        minimum_repeats: positive("minimum_repeats")
            .ok_or_else(|| invalid("minimum_repeats must be a positive integer"))? as u64,
        normalization_sha256: string("normalization_sha256"),
        contract_sha256: string("contract_sha256"),
    };
    check(is_stable_id(&contract.verifier_id), "verifier_id is invalid")?;
    stable_ids(&contract.claim_ids, 1, "verifier claim_ids are invalid")?;
    stable_ids(&contract.dimensions, 1, "verifier dimensions are invalid")?;
    check(PROOF_AUTHORITIES.contains(&contract.authority.as_str()), "verifier authority is invalid")?;
    check(is_digest(&contract.normalization_sha256), "normalization_sha256 is invalid")?;
    check(is_digest(&contract.contract_sha256), "contract_sha256 is invalid")?;
    check(
        object.get("normalization_removes_dimensions") == Some(&Value::Bool(false)),
        "normalization_removes_dimensions must be false",
    )?;
    let mut base = object.clone();
    base.remove("contract_sha256");
    if contract.contract_sha256 != digest(&Value::Object(base))? {
        return Err(invalid(format!("Verifier contract digest is invalid: {}", contract.verifier_id)));
    }
    Ok(contract)
}

fn parse_ownership(value: &Value) -> Result<Ownership, JsError> {
    let object = value.as_object().ok_or_else(|| invalid("ownership must be an object"))?;
    let text = |key: &str| object.get(key).and_then(Value::as_str);
    match text("disposition") {
        Some("implemented") => {
            const KEYS: [&str; 8] = [
                "disposition",
                "owner_path",
                "owner_export",
                "owner_sha256",
                "path_state",
                "package_state",
                "authority_route",
                "",
            ];
            check(
                object.keys().all(|k| KEYS[..7].contains(&k.as_str())) && object.len() == 7,
                "implemented ownership has unexpected or missing properties",
            )?;
            check(text("owner_path").is_some_and(non_blank), "owner_path is invalid")?;
            check(
                object.get("owner_export").is_some_and(|v| v.is_null() || v.as_str().is_some_and(non_blank)),
                "owner_export is invalid",
            )?;
            let owner_sha256 = text("owner_sha256").filter(|v| is_digest(v)).ok_or_else(|| invalid("owner_sha256 is invalid"))?;
            let pick = |key: &str, allowed: &[&str]| -> Result<String, JsError> {
                text(key)
                    .filter(|v| allowed.contains(v))
                    .map(str::to_string)
                    .ok_or_else(|| invalid(format!("{key} is invalid")))
            };
            Ok(Ownership::Implemented {
                owner_sha256: owner_sha256.to_string(),
                path_state: pick("path_state", &["present", "missing", "unknown"])?,
                package_state: pick("package_state", &["distributed", "missing", "unknown"])?,
                authority_route: pick("authority_route", &["none", "detected", "unknown"])?,
            })
        }
        Some(disposition @ ("external" | "non-goal")) => {
            check(
                object.len() == 2 && text("rationale").is_some_and(non_blank),
                "external ownership requires a rationale",
            )?;
            Ok(Ownership::Disposition(disposition.to_string()))
        }
        _ => Err(invalid("ownership disposition is invalid")),
    }
}

/// `offsetDateTimeSchema` + `Date.parse`: epoch milliseconds.
pub fn parse_offset_date_time(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let digit = |i: usize| bytes.get(i).filter(|b| b.is_ascii_digit()).map(|b| i64::from(b - b'0'));
    let number = |start: usize, len: usize| -> Option<i64> {
        (start..start + len).try_fold(0i64, |acc, i| digit(i).map(|d| acc * 10 + d))
    };
    let year = number(0, 4)?;
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T') {
        return None;
    }
    let month = number(5, 2)?;
    let day = number(8, 2)?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > max_day {
        return None;
    }
    let hour = number(11, 2)?;
    if bytes.get(13) != Some(&b':') || hour > 23 {
        return None;
    }
    let minute = number(14, 2)?;
    if minute > 59 {
        return None;
    }
    let mut index = 16;
    let mut second = 0;
    let mut millis = 0;
    if bytes.get(index) == Some(&b':') {
        second = number(index + 1, 2)?;
        if second > 59 {
            return None;
        }
        index += 3;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while digit(index).is_some() {
                index += 1;
            }
            if index == start {
                return None;
            }
            let fraction = &value[start..index];
            let padded = format!("{fraction:0<3}");
            millis = padded[..3].parse::<i64>().ok()?;
        }
    }
    let offset_minutes = match bytes.get(index) {
        Some(b'Z') if index + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if index + 6 == bytes.len() => {
            let oh = number(index + 1, 2)?;
            let om = number(index + 4, 2)?;
            if bytes.get(index + 3) != Some(&b':') || oh > 23 || om > 59 {
                return None;
            }
            let total = oh * 60 + om;
            if *sign == b'+' {
                total
            } else {
                -total
            }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    Some(seconds * 1000 + millis)
}

fn validate(coverage: &Coverage) -> Result<(Vec<Contract>, Vec<Ownership>), JsError> {
    let bundle = parse_evidence_bundle(&serde_json::to_string(&coverage.evidence_bundle)?)
        .map_err(|error| invalid(error.to_string()))?;
    for artifact in &coverage.artifacts {
        check(is_stable_id(&artifact.artifact_id), "artifact_id is invalid")?;
        check(is_digest(&artifact.artifact_sha256) && is_digest(&artifact.environment_sha256), "artifact digest is invalid")?;
        check(non_blank(&artifact.version), "artifact version is invalid")?;
        evidence_ids(&artifact.evidence_ids, 1, "artifact evidence_ids are invalid")?;
    }
    for surface in &coverage.surfaces {
        check(is_stable_id(&surface.surface_id) && is_stable_id(&surface.artifact_id), "surface ids are invalid")?;
        check(non_blank(&surface.family) && non_blank(&surface.location), "surface text is invalid")?;
        check(surface.occurrence_id.as_deref().is_none_or(non_blank), "surface occurrence_id is invalid")?;
        check(
            ["observed", "derived", "inferred", "historical", "external"].contains(&surface.authority.as_str()),
            "surface authority is invalid",
        )?;
        stable_ids(&surface.dependency_surface_ids, 0, "surface dependency ids are invalid")?;
        evidence_ids(&surface.evidence_ids, 1, "surface evidence_ids are invalid")?;
    }
    let ownerships: Vec<Ownership> = coverage
        .owners
        .iter()
        .map(|owner| {
            check(is_stable_id(&owner.surface_id), "owner surface_id is invalid")?;
            parse_ownership(&owner.ownership)
        })
        .collect::<Result<_, _>>()?;
    for claim in &coverage.claims {
        check(is_stable_id(&claim.claim_id), "claim_id is invalid")?;
        check(non_blank(&claim.title) && non_blank(&claim.kind), "claim text is invalid")?;
        stable_ids(&claim.surface_ids, 1, "claim surface_ids are invalid")?;
        stable_ids(&claim.required_dimensions, 1, "claim required_dimensions are invalid")?;
        check(PROOF_AUTHORITIES.contains(&claim.required_authority.as_str()), "claim authority is invalid")?;
    }
    let contracts: Vec<Contract> = coverage.verifier_contracts.iter().map(parse_contract).collect::<Result<_, _>>()?;
    for result in &coverage.verifier_results {
        check(is_stable_id(&result.verifier_id), "verifier result id is invalid")?;
        check(is_digest(&result.contract_sha256) && is_digest(&result.normalization_sha256), "verifier result digest is invalid")?;
        check(parse_offset_date_time(&result.observed_at).is_some(), "Use an ISO-8601 date-time with an explicit UTC offset")?;
        check(
            ["pass", "fail", "unknown", "unsupported", "truncated", "skipped"].contains(&result.status.as_str()),
            "verifier result status is invalid",
        )?;
        stable_ids(&result.covered_claim_ids, 1, "covered_claim_ids are invalid")?;
        stable_ids(&result.covered_dimensions, 1, "covered_dimensions are invalid")?;
        digests(&result.artifact_sha256s, 1, "artifact_sha256s are invalid")?;
        digests(&result.owner_sha256s, 0, "owner_sha256s are invalid")?;
        check(result.repeats >= 1, "repeats must be positive")?;
        evidence_ids(&result.evidence_ids, 1, "verifier result evidence_ids are invalid")?;
    }
    stable_ids(&coverage.residual_unknown_ids, 0, "residual_unknown_ids are invalid")?;
    for contradiction in &coverage.contradictions {
        check(is_stable_id(&contradiction.contradiction_id), "contradiction_id is invalid")?;
        check(["active", "resolved"].contains(&contradiction.status.as_str()), "contradiction status is invalid")?;
        stable_ids(&contradiction.surface_ids, 0, "contradiction surface_ids are invalid")?;
        stable_ids(&contradiction.claim_ids, 0, "contradiction claim_ids are invalid")?;
        evidence_ids(&contradiction.evidence_ids, 2, "contradiction evidence_ids are invalid")?;
    }
    for proof in &coverage.package_proofs {
        check(is_stable_id(&proof.proof_id), "proof_id is invalid")?;
        check(PACKAGE_PROOF_KINDS.contains(&proof.kind.as_str()), "package proof kind is invalid")?;
        check(
            ["pass", "fail", "unknown", "unsupported", "skipped"].contains(&proof.status.as_str()),
            "package proof status is invalid",
        )?;
        digests(&proof.artifact_sha256s, 1, "package proof artifact_sha256s are invalid")?;
        evidence_ids(&proof.evidence_ids, 1, "package proof evidence_ids are invalid")?;
    }
    for boundary in &coverage.boundaries {
        check(is_stable_id(&boundary.boundary_id) && non_blank(&boundary.title), "boundary is invalid")?;
        stable_ids(&boundary.required_surface_ids, 1, "boundary required_surface_ids are invalid")?;
        stable_ids(&boundary.required_claim_ids, 1, "boundary required_claim_ids are invalid")?;
        check(
            !boundary.required_package_proof_kinds.is_empty()
                && boundary.required_package_proof_kinds.iter().all(|k| PACKAGE_PROOF_KINDS.contains(&k.as_str())),
            "boundary package proof kinds are invalid",
        )?;
        check(
            boundary.allowed_dispositions.iter().all(|d| d == "external" || d == "non-goal"),
            "boundary allowed_dispositions are invalid",
        )?;
        stable_ids(&boundary.allowed_unknown_ids, 0, "boundary allowed_unknown_ids are invalid")?;
    }

    // validateCoverageReferences
    let record_ids: BTreeSet<&str> = bundle.records.iter().map(|r| r.evidence_id.as_str()).collect();
    let unknown_ids: BTreeSet<&str> = bundle.unknowns.iter().map(|u| u.unknown_id.as_str()).collect();
    fn unique<'a>(values: impl Iterator<Item = &'a String>, key: &str) -> Result<BTreeSet<&'a str>, JsError> {
        let values: Vec<&str> = values.map(String::as_str).collect();
        let set: BTreeSet<&str> = values.iter().copied().collect();
        if set.len() != values.len() {
            return Err(invalid(format!("Duplicate reconstruction coverage {key}")));
        }
        Ok(set)
    }
    let artifacts = unique(coverage.artifacts.iter().map(|a| &a.artifact_id), "artifact_id")?;
    let surfaces = unique(coverage.surfaces.iter().map(|s| &s.surface_id), "surface_id")?;
    let claims = unique(coverage.claims.iter().map(|c| &c.claim_id), "claim_id")?;
    let contract_ids = unique(contracts.iter().map(|c| &c.verifier_id), "verifier_id")?;
    unique(coverage.contradictions.iter().map(|c| &c.contradiction_id), "contradiction_id")?;
    unique(coverage.package_proofs.iter().map(|p| &p.proof_id), "proof_id")?;
    unique(coverage.boundaries.iter().map(|b| &b.boundary_id), "boundary_id")?;
    for surface in &coverage.surfaces {
        if !artifacts.contains(surface.artifact_id.as_str()) {
            return Err(invalid(format!("Surface artifact is missing: {}", surface.surface_id)));
        }
    }
    for owner in &coverage.owners {
        if !surfaces.contains(owner.surface_id.as_str()) {
            return Err(invalid(format!("Owner surface is missing: {}", owner.surface_id)));
        }
    }
    for claim in &coverage.claims {
        if claim.surface_ids.iter().any(|id| !surfaces.contains(id.as_str())) {
            return Err(invalid(format!("Claim surface is missing: {}", claim.claim_id)));
        }
    }
    for contract in &contracts {
        if contract.claim_ids.iter().any(|id| !claims.contains(id.as_str())) {
            return Err(invalid(format!("Verifier claim is missing: {}", contract.verifier_id)));
        }
    }
    for result in &coverage.verifier_results {
        if !contract_ids.contains(result.verifier_id.as_str()) {
            return Err(invalid(format!("Verifier result contract is missing: {}", result.verifier_id)));
        }
    }
    let referenced = coverage
        .artifacts
        .iter()
        .flat_map(|a| &a.evidence_ids)
        .chain(coverage.surfaces.iter().flat_map(|s| &s.evidence_ids))
        .chain(coverage.verifier_results.iter().flat_map(|r| &r.evidence_ids))
        .chain(coverage.contradictions.iter().flat_map(|c| &c.evidence_ids))
        .chain(coverage.package_proofs.iter().flat_map(|p| &p.evidence_ids));
    for id in referenced {
        if !record_ids.contains(id.as_str()) {
            return Err(invalid(format!("Coverage workspace Evidence is missing: {id}")));
        }
    }
    if let Some(id) = coverage.residual_unknown_ids.iter().find(|id| !unknown_ids.contains(id.as_str())) {
        return Err(invalid(format!("Coverage workspace residual unknown is missing: {id}")));
    }
    Ok((contracts, ownerships))
}

struct Context<'a> {
    coverage: &'a Coverage,
    ownerships: &'a [Ownership],
    contracts: &'a [Contract],
    boundary: &'a Boundary,
    now: i64,
    reasons: Vec<(String, String, String)>,
    evidence: BTreeSet<String>,
}

impl Context<'_> {
    fn reason(&mut self, code: &str, subject: &str, detail: impl Into<String>) {
        self.reasons.push((code.to_string(), subject.to_string(), detail.into()));
    }

    fn add_evidence(&mut self, ids: &[String]) {
        self.evidence.extend(ids.iter().cloned());
    }

    fn owners_of(&self, surface_id: &str) -> Vec<&Ownership> {
        self.coverage
            .owners
            .iter()
            .zip(self.ownerships)
            .filter(|(owner, _)| owner.surface_id == surface_id)
            .map(|(_, ownership)| ownership)
            .collect()
    }

    fn artifact_digest_for_surface(&self, surface_id: &str) -> Option<String> {
        // Map construction keeps the last duplicate, like JS `new Map`.
        let surface = self.coverage.surfaces.iter().rev().find(|s| s.surface_id == surface_id)?;
        let artifact = self.coverage.artifacts.iter().rev().find(|a| a.artifact_id == surface.artifact_id)?;
        Some(artifact.artifact_sha256.clone())
    }
}

fn evaluate_surfaces(context: &mut Context<'_>) {
    let surfaces: BTreeMap<&str, &Surface> =
        context.coverage.surfaces.iter().map(|s| (s.surface_id.as_str(), s)).collect();
    for surface_id in &context.boundary.required_surface_ids {
        let Some(surface) = surfaces.get(surface_id.as_str()) else {
            context.reason(
                "surface-missing",
                surface_id,
                "Required surface is absent from the authoritative inventory.",
            );
            continue;
        };
        context.add_evidence(&surface.evidence_ids);
        for dependency in &surface.dependency_surface_ids {
            if !surfaces.contains_key(dependency.as_str()) {
                context.reason(
                    "dependency-surface-missing",
                    surface_id,
                    format!("Declared dependency surface is absent: {dependency}"),
                );
            }
        }
        evaluate_owner(context, surface_id);
    }
}

fn evaluate_owner(context: &mut Context<'_>, surface_id: &str) {
    let owners = context.owners_of(surface_id);
    if owners.is_empty() {
        context.reason(
            "owner-missing",
            surface_id,
            "Required surface has no reconstructed owner or explicit disposition.",
        );
        return;
    }
    if owners.len() > 1 {
        context.reason(
            "owner-duplicate",
            surface_id,
            "Required surface has conflicting ownership declarations.",
        );
        return;
    }
    let checks: Vec<(&str, &str)> = match owners[0] {
        Ownership::Disposition(disposition) => {
            if !context.boundary.allowed_dispositions.contains(disposition) {
                let detail = format!("{disposition} is not allowed by this completion boundary.");
                context.reason("disposition-not-allowed", surface_id, detail);
            }
            return;
        }
        Ownership::Implemented { path_state, package_state, authority_route, .. } => {
            let mut checks = Vec::new();
            if path_state == "missing" {
                checks.push(("owner-path-missing", "Declared owner path is missing."));
            }
            if path_state == "unknown" {
                checks.push(("owner-path-unknown", "Declared owner path has not been checked."));
            }
            if package_state == "missing" {
                checks.push(("owner-undistributed", "Declared owner is absent from the distributable."));
            }
            if package_state == "unknown" {
                checks.push(("owner-distribution-unknown", "Owner distribution state is unknown."));
            }
            if authority_route == "detected" {
                checks.push(("authority-routing-detected", "Reconstructed owner routes into the authority."));
            }
            if authority_route == "unknown" {
                checks.push(("authority-routing-unknown", "Authority independence has not been established."));
            }
            checks
        }
    };
    for (code, detail) in checks {
        context.reason(code, surface_id, detail);
    }
}

fn evaluate_claims(context: &mut Context<'_>) {
    let claims: BTreeMap<&str, &Claim> = context.coverage.claims.iter().map(|c| (c.claim_id.as_str(), c)).collect();
    let mut contracts_by_claim: BTreeMap<&str, Vec<&Contract>> = BTreeMap::new();
    for contract in context.contracts {
        let unique: BTreeSet<&String> = contract.claim_ids.iter().collect();
        for claim_id in unique {
            contracts_by_claim.entry(claim_id.as_str()).or_default().push(contract);
        }
    }
    let mut latest: BTreeMap<&str, &VerifierResult> = BTreeMap::new();
    for result in &context.coverage.verifier_results {
        let replace = match latest.get(result.verifier_id.as_str()) {
            None => true,
            Some(current) => {
                parse_offset_date_time(&result.observed_at) > parse_offset_date_time(&current.observed_at)
            }
        };
        if replace {
            latest.insert(result.verifier_id.as_str(), result);
        }
    }
    for claim_id in context.boundary.required_claim_ids.clone() {
        let Some(claim) = claims.get(claim_id.as_str()).copied() else {
            context.reason("claim-missing", &claim_id, "Required finite claim is absent.");
            continue;
        };
        let contracts = contracts_by_claim.get(claim_id.as_str()).cloned().unwrap_or_default();
        if contracts.is_empty() {
            context.reason("verifier-missing", &claim_id, "No verifier contract covers this claim.");
            continue;
        }
        if contracts.len() > 1 {
            context.reason(
                "verifier-duplicate",
                &claim_id,
                "Multiple verifier contracts claim primary coverage.",
            );
            continue;
        }
        evaluate_verifier_result(context, claim, contracts[0], latest.get(contracts[0].verifier_id.as_str()).copied());
    }
}

fn evaluate_verifier_result(
    context: &mut Context<'_>,
    claim: &Claim,
    contract: &Contract,
    result: Option<&VerifierResult>,
) {
    let Some(result) = result else {
        context.reason("verifier-result-missing", &claim.claim_id, "Verifier has no recorded result.");
        return;
    };
    context.add_evidence(&result.evidence_ids);
    if !verifier_result_compatible(context, claim, contract, result) {
        context.reason(
            "verifier-result-incompatible",
            &claim.claim_id,
            "Latest verifier result does not match current artifacts, owners, dimensions, authority, normalization, repeats, or contract.",
        );
        return;
    }
    let observed = parse_offset_date_time(&result.observed_at).unwrap_or(i64::MAX);
    if observed > context.now || context.now - observed > contract.max_age_ms {
        context.reason("verifier-result-stale", &claim.claim_id, "Latest compatible verifier result is stale.");
        return;
    }
    if result.status == "fail" {
        context.reason("verifier-failed", &claim.claim_id, "Latest compatible verifier result failed.");
    } else if result.status != "pass" {
        context.reason(
            "verifier-unknown",
            &claim.claim_id,
            format!("Latest compatible verifier result is {}.", result.status),
        );
    }
}

fn verifier_result_compatible(context: &Context<'_>, claim: &Claim, contract: &Contract, result: &VerifierResult) -> bool {
    let artifact_digests: BTreeSet<&str> = context.coverage.artifacts.iter().map(|a| a.artifact_sha256.as_str()).collect();
    let owner_digests: BTreeSet<&str> = context
        .ownerships
        .iter()
        .filter_map(|o| match o {
            Ownership::Implemented { owner_sha256, .. } => Some(owner_sha256.as_str()),
            Ownership::Disposition(_) => None,
        })
        .collect();
    let expected_artifacts: Vec<String> = claim
        .surface_ids
        .iter()
        .filter_map(|id| context.artifact_digest_for_surface(id))
        .collect();
    let expected_owners: Vec<String> = claim
        .surface_ids
        .iter()
        .flat_map(|id| context.owners_of(id))
        .filter_map(|o| match o {
            Ownership::Implemented { owner_sha256, .. } => Some(owner_sha256.clone()),
            Ownership::Disposition(_) => None,
        })
        .collect();
    result.contract_sha256 == contract.contract_sha256
        && result.normalization_sha256 == contract.normalization_sha256
        && result.covered_claim_ids.contains(&claim.claim_id)
        && result.covered_claim_ids.iter().all(|id| contract.claim_ids.contains(id))
        && claim.required_dimensions.iter().all(|d| contract.dimensions.contains(d))
        && claim.required_dimensions.iter().all(|d| result.covered_dimensions.contains(d))
        && result.covered_dimensions.iter().all(|d| contract.dimensions.contains(d))
        && result.artifact_sha256s.iter().all(|d| artifact_digests.contains(d.as_str()))
        && expected_artifacts.iter().all(|d| result.artifact_sha256s.contains(d))
        && result.owner_sha256s.iter().all(|d| owner_digests.contains(d.as_str()))
        && expected_owners.iter().all(|d| result.owner_sha256s.contains(d))
        && result.repeats >= contract.minimum_repeats
        && claim.required_authority == contract.authority
}

fn evaluate_risks(context: &mut Context<'_>) {
    for unknown_id in &context.coverage.residual_unknown_ids {
        if !context.boundary.allowed_unknown_ids.contains(unknown_id) {
            context.reasons.push((
                "active-unknown".into(),
                unknown_id.clone(),
                "Active residual unknown is not permitted by the completion boundary.".into(),
            ));
        }
    }
    for contradiction in &context.coverage.contradictions {
        if contradiction.status == "active"
            && (contradiction.surface_ids.iter().any(|id| context.boundary.required_surface_ids.contains(id))
                || contradiction.claim_ids.iter().any(|id| context.boundary.required_claim_ids.contains(id)))
        {
            context.evidence.extend(contradiction.evidence_ids.iter().cloned());
            context.reasons.push((
                "active-contradiction".into(),
                contradiction.contradiction_id.clone(),
                "Active contradiction affects the completion boundary.".into(),
            ));
        }
    }
}

fn evaluate_package_proofs(context: &mut Context<'_>) {
    let required: Vec<String> = context
        .boundary
        .required_surface_ids
        .iter()
        .filter_map(|id| context.artifact_digest_for_surface(id))
        .collect();
    for kind in context.boundary.required_package_proof_kinds.clone() {
        let proofs: Vec<&PackageProof> = context.coverage.package_proofs.iter().filter(|p| p.kind == kind).collect();
        if let Some(passing) = proofs
            .iter()
            .find(|p| p.status == "pass" && required.iter().all(|d| p.artifact_sha256s.contains(d)))
        {
            context.add_evidence(&passing.evidence_ids);
            continue;
        }
        if proofs.iter().any(|p| p.status == "fail") {
            context.reason("package-proof-failed", &kind, "Required package or integration proof failed.");
        } else if !proofs.is_empty() {
            context.reason("package-proof-unknown", &kind, "Required package or integration proof is not passing.");
        } else {
            context.reason("package-proof-missing", &kind, "Required package or integration proof is missing.");
        }
    }
}

fn closure_status(reasons: &[(String, String, String)]) -> &'static str {
    if reasons.is_empty() {
        return "ready";
    }
    let has = |codes: &[&str]| reasons.iter().any(|(code, _, _)| codes.contains(&code.as_str()));
    if has(&[
        "verifier-failed",
        "active-contradiction",
        "authority-routing-detected",
        "owner-path-missing",
        "owner-undistributed",
        "package-proof-failed",
    ]) {
        return "failed";
    }
    if has(&[
        "verifier-result-stale",
        "verifier-result-incompatible",
        "verifier-unknown",
        "active-unknown",
        "owner-path-unknown",
        "owner-distribution-unknown",
        "authority-routing-unknown",
        "package-proof-unknown",
    ]) {
        return "unknown";
    }
    "partial"
}

fn probe_operation(code: &str) -> &'static str {
    if code.starts_with("owner-") || code.starts_with("authority-routing") {
        "reconcile_reconstruction_owner"
    } else if code.starts_with("verifier-") {
        "run_reconstruction_verifier"
    } else if code.starts_with("package-proof") {
        "verify_reconstruction_package"
    } else if code == "active-contradiction" {
        "resolve_contradiction"
    } else if code == "active-unknown" {
        "probe_residual_unknown"
    } else {
        "update_authoritative_inventory"
    }
}

/// `evaluate_reconstruction_coverage`: the closure result for one named boundary.
pub fn evaluate_reconstruction_coverage(args: &Value, now_epoch_ms: i64) -> Result<Value, JsError> {
    let object = args.as_object().ok_or_else(|| invalid("input must be an object"))?;
    if object.keys().any(|k| k != "coverage" && k != "boundary_id") {
        return Err(invalid("evaluate_reconstruction_coverage accepts only coverage and boundary_id"));
    }
    let boundary_id = object
        .get("boundary_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("evaluate_reconstruction_coverage requires boundary_id"))?;
    let coverage: Coverage = serde_json::from_value(
        object
            .get("coverage")
            .cloned()
            .ok_or_else(|| invalid("evaluate_reconstruction_coverage requires coverage"))?,
    )
    .map_err(|error| invalid(format!("Invalid reconstruction coverage: {error}")))?;
    let (contracts, ownerships) = validate(&coverage)?;
    let boundary = coverage
        .boundaries
        .iter()
        .find(|b| b.boundary_id == boundary_id)
        .ok_or_else(|| invalid(format!("Unknown reconstruction boundary: {boundary_id}")))?;
    let mut context = Context {
        coverage: &coverage,
        ownerships: &ownerships,
        contracts: &contracts,
        boundary,
        now: now_epoch_ms,
        reasons: Vec::new(),
        evidence: BTreeSet::new(),
    };
    evaluate_surfaces(&mut context);
    evaluate_claims(&mut context);
    evaluate_risks(&mut context);
    evaluate_package_proofs(&mut context);
    let mut reasons = context.reasons;
    reasons.sort_by(|a, b| {
        compare_unicode_code_points(&composite_key(&[&a.0, &a.1]), &composite_key(&[&b.0, &b.1]))
    });
    let reason_values: Vec<Value> = reasons
        .iter()
        .map(|(code, subject, detail)| json!({ "code": code, "subject_id": subject, "detail": detail }))
        .collect();
    let probes: Vec<Value> = reasons
        .iter()
        .map(|(code, subject, detail)| {
            json!({ "operation": probe_operation(code), "subject_id": subject, "rationale": detail })
        })
        .collect();
    Ok(json!({
        "boundary_id": boundary.boundary_id,
        "status": closure_status(&reasons),
        "summary": {
            "required_surfaces": boundary.required_surface_ids.len(),
            "required_claims": boundary.required_claim_ids.len(),
            "reasons": reasons.len(),
        },
        "reasons": reason_values,
        "recommended_probes": probes,
        "evidence_ids": default_sorted_unique(context.evidence),
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_offset_date_time;

    #[test]
    fn offset_date_time_matches_date_parse() {
        assert_eq!(parse_offset_date_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_offset_date_time("2026-02-01T00:00:00+02:00"), Some(1_769_896_800_000));
        assert_eq!(parse_offset_date_time("2026-01-01T00:00Z"), Some(1_767_225_600_000));
        assert_eq!(parse_offset_date_time("2026-01-01T00:00:00.1239Z"), Some(1_767_225_600_123));
        assert_eq!(parse_offset_date_time("2025-02-29T00:00:00Z"), None);
        assert_eq!(parse_offset_date_time("2026-01-01T00:00:00"), None);
    }
}
