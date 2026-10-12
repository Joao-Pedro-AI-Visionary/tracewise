//! Port of REA `application/ReconstructionObligation*.ts` and
//! `domain/reconstructionObligationLedgerSchemas.ts`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracewise_domain::bundle::{parse_evidence_bundle, EvidenceBundle};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use super::common::*;
use crate::error::JsError;

const CASE_KINDS: [&str; 5] = ["positive", "negative", "malformed", "cancellation", "teardown"];
const PROOF_AUTHORITIES: [&str; 8] = [
    "unit",
    "integration",
    "protocol",
    "renderer",
    "packaged-process",
    "native-abi",
    "live-observation",
    "external",
];
const ORIGINAL_AUTHORITIES: [&str; 4] = ["static", "runtime", "process", "external"];
const LAYERS: [&str; 10] = [
    "cli",
    "protocol",
    "electron",
    "persistence",
    "process",
    "runtime",
    "packaging",
    "native-abi",
    "application",
    "other",
];
const STATUSES: [&str; 8] = [
    "unowned",
    "characterized",
    "implemented",
    "verified",
    "contradicted",
    "blocked",
    "out-of-scope",
    "unknown",
];

// ---------------------------------------------------------------- input types

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    artifact_sha256: Option<String>,
    application_node_id: Option<String>,
    semantic_node_id: Option<String>,
    location: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedCase {
    kind: String,
    evidence_id: String,
    location: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerBinding {
    module_path: String,
    symbol: String,
    owner_sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserType {
    parser: String,
    schema: String,
    domain_type: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureBinding {
    fixture_id: String,
    case_kind: String,
    authority: String,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nondeterminism {
    mode: String,
    specification: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierBinding {
    verifier_id: String,
    claim_id: String,
    command: String,
    authority: String,
    status: String,
    result_evidence_id: String,
    enumerated_obligation_ids: Vec<String>,
    nondeterminism: Nondeterminism,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    obligation_id: String,
    owner: OwnerBinding,
    parser_type: Option<ParserType>,
    original_cases: Vec<ObservedCase>,
    fixtures: Vec<FixtureBinding>,
    verifier: Option<VerifierBinding>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestContradiction {
    obligation_id: String,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    bindings: Vec<Binding>,
    contradictions: Vec<ManifestContradiction>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reviewed {
    obligation_id: String,
    obligation_version: u64,
    title: String,
    application_layer: String,
    family: String,
    target: Target,
    required: bool,
    required_case_kinds: Vec<String>,
    required_original_authority: String,
    required_fixture_authority: String,
    required_verifier_authority: String,
    requires_parser_type: bool,
    dependency_obligation_ids: Vec<String>,
    residual_unknown_ids: Vec<String>,
    unavailable_authority: Vec<String>,
    required_next_evidence: Vec<String>,
    disposition: String,
    review_evidence_ids: Vec<String>,
}

// ---------------------------------------------------------------- validation

/// `STABLE_IDENTIFIER_PATTERN`: `^[A-Za-z][A-Za-z0-9._:/-]*$`.
fn is_stable_id(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c))
}

/// `z.string().trim().min(1)`: trims in place and rejects blank text.
fn text(value: &mut String, label: &str) -> Result<(), JsError> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(invalid(format!("{label} must be non-empty text")));
    }
    *value = trimmed;
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<(), JsError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message.to_string()))
    }
}

fn one_of(value: &str, allowed: &[&str], label: &str) -> Result<(), JsError> {
    ensure(allowed.contains(&value), &format!("{label} is invalid"))
}

fn ids(values: &[String], min: usize, label: &str) -> Result<(), JsError> {
    ensure(values.len() >= min && values.iter().all(|v| is_evidence_id(v)), label)
}

fn stable(values: &[String], min: usize, label: &str) -> Result<(), JsError> {
    ensure(values.len() >= min && values.iter().all(|v| is_stable_id(v)), label)
}

fn validate_target(target: &mut Target) -> Result<(), JsError> {
    ensure(target.artifact_sha256.as_deref().is_none_or(is_digest), "target.artifact_sha256 is invalid")?;
    ensure(
        target.application_node_id.as_deref().is_none_or(|v| is_prefixed_digest(v, "jag_node")),
        "target.application_node_id is invalid",
    )?;
    ensure(
        target.semantic_node_id.as_deref().is_none_or(|v| is_prefixed_digest(v, "jsrg_node")),
        "target.semantic_node_id is invalid",
    )?;
    text(&mut target.location, "target.location")
}

fn validate_case(case: &mut ObservedCase) -> Result<(), JsError> {
    one_of(&case.kind, &CASE_KINDS, "case kind")?;
    ensure(is_evidence_id(&case.evidence_id), "case evidence_id is invalid")?;
    text(&mut case.location, "case location")
}

fn validate_binding(binding: &mut Binding) -> Result<(), JsError> {
    ensure(is_stable_id(&binding.obligation_id), "binding obligation_id is invalid")?;
    text(&mut binding.owner.module_path, "owner.module_path")?;
    text(&mut binding.owner.symbol, "owner.symbol")?;
    ensure(is_digest(&binding.owner.owner_sha256), "owner.owner_sha256 is invalid")?;
    if let Some(parser) = binding.parser_type.as_mut() {
        text(&mut parser.parser, "parser_type.parser")?;
        text(&mut parser.schema, "parser_type.schema")?;
        text(&mut parser.domain_type, "parser_type.domain_type")?;
    }
    for case in &mut binding.original_cases {
        validate_case(case)?;
    }
    for fixture in &binding.fixtures {
        ensure(is_stable_id(&fixture.fixture_id), "fixture_id is invalid")?;
        one_of(&fixture.case_kind, &CASE_KINDS, "fixture case_kind")?;
        one_of(&fixture.authority, &PROOF_AUTHORITIES, "fixture authority")?;
        ids(&fixture.evidence_ids, 1, "fixture evidence_ids are invalid")?;
    }
    if let Some(verifier) = binding.verifier.as_mut() {
        ensure(
            is_stable_id(&verifier.verifier_id) && is_stable_id(&verifier.claim_id),
            "verifier ids are invalid",
        )?;
        text(&mut verifier.command, "verifier.command")?;
        one_of(&verifier.authority, &PROOF_AUTHORITIES, "verifier authority")?;
        one_of(&verifier.status, &["pass", "fail", "unknown", "unsupported", "skipped"], "verifier status")?;
        ensure(is_evidence_id(&verifier.result_evidence_id), "verifier result_evidence_id is invalid")?;
        stable(&verifier.enumerated_obligation_ids, 1, "verifier enumerated_obligation_ids are invalid")?;
        one_of(
            &verifier.nondeterminism.mode,
            &["total-order", "partial-order", "finite-traces"],
            "nondeterminism mode",
        )?;
        text(&mut verifier.nondeterminism.specification, "nondeterminism.specification")?;
    }
    Ok(())
}

fn validate_reviewed(item: &mut Reviewed) -> Result<(), JsError> {
    ensure(is_stable_id(&item.obligation_id), "reviewed obligation_id is invalid")?;
    ensure(item.obligation_version >= 1, "obligation_version must be positive")?;
    text(&mut item.title, "title")?;
    one_of(&item.application_layer, &LAYERS, "application_layer")?;
    text(&mut item.family, "family")?;
    validate_target(&mut item.target)?;
    ensure(!item.required_case_kinds.is_empty(), "required_case_kinds must be non-empty")?;
    for kind in &item.required_case_kinds {
        one_of(kind, &CASE_KINDS, "required case kind")?;
    }
    one_of(&item.required_original_authority, &ORIGINAL_AUTHORITIES, "required_original_authority")?;
    one_of(&item.required_fixture_authority, &PROOF_AUTHORITIES, "required_fixture_authority")?;
    one_of(&item.required_verifier_authority, &PROOF_AUTHORITIES, "required_verifier_authority")?;
    stable(&item.dependency_obligation_ids, 0, "dependency_obligation_ids are invalid")?;
    stable(&item.residual_unknown_ids, 0, "residual_unknown_ids are invalid")?;
    for value in item.unavailable_authority.iter_mut().chain(item.required_next_evidence.iter_mut()) {
        text(value, "obligation text")?;
    }
    one_of(&item.disposition, &["active", "blocked", "out-of-scope"], "disposition")?;
    ids(&item.review_evidence_ids, 1, "review_evidence_ids are invalid")
}

// ---------------------------------------------------------------- candidates

#[derive(Clone, Serialize)]
struct AuthorityReference {
    evidence_id: String,
    authority: String,
    state: String,
    location: String,
}

#[derive(Clone)]
struct Candidate {
    obligation_id: String,
    obligation_version: u64,
    title: String,
    origin: &'static str,
    application_layer: String,
    family: String,
    target: Target,
    authority_references: Vec<AuthorityReference>,
    source_state: String,
    observed_cases: Vec<ObservedCase>,
    required: bool,
    required_case_kinds: Vec<String>,
    required_original_authority: String,
    required_fixture_authority: String,
    required_verifier_authority: String,
    requires_parser_type: bool,
    dependency_obligation_ids: Vec<String>,
    residual_unknown_ids: Vec<String>,
    unavailable_authority: Vec<String>,
    required_next_evidence: Vec<String>,
    definition_count: u64,
    disposition: String,
}

struct Policy {
    layer: &'static str,
    family: &'static str,
    fixture: &'static str,
    verifier: &'static str,
    original: &'static str,
    cases: &'static [&'static str],
    parser: bool,
}

const fn policy(layer: &'static str, family: &'static str, authority: &'static str, cases: &'static [&'static str]) -> Policy {
    Policy { layer, family, fixture: authority, verifier: authority, original: "runtime", cases, parser: false }
}

const fn parser_policy(layer: &'static str, family: &'static str, authority: &'static str) -> Policy {
    Policy {
        layer,
        family,
        fixture: authority,
        verifier: authority,
        original: "runtime",
        cases: &["positive", "negative", "malformed"],
        parser: true,
    }
}

const fn native_policy(family: &'static str) -> Policy {
    Policy {
        layer: "native-abi",
        family,
        fixture: "native-abi",
        verifier: "native-abi",
        original: "static",
        cases: &["positive", "negative"],
        parser: false,
    }
}

/// `APPLICATION_NODE_POLICIES`.
fn application_policy(kind: &str) -> Option<Policy> {
    const PNT: &[&str] = &["positive", "negative", "teardown"];
    const PNM: &[&str] = &["positive", "negative", "malformed"];
    const PCT: &[&str] = &["positive", "cancellation", "teardown"];
    Some(match kind {
        "package" => policy("packaging", "package-lifecycle", "packaged-process", PNT),
        "installer" => policy("packaging", "installer", "packaged-process", PNT),
        "context-bridge-api" => policy("electron", "context-bridge", "renderer", PNM),
        "ipc-channel" | "ipc-handler" => policy("electron", "ipc", "renderer", PNM),
        "endpoint" => policy("protocol", "endpoint", "protocol", PNM),
        "storage" => policy("persistence", "persistence", "integration", PNM),
        "worker" | "service-worker" => policy("process", "worker-lifecycle", "packaged-process", PCT),
        "native-addon" => native_policy("native-addon"),
        "native-export" => native_policy("native-export"),
        "managed-pinvoke-import" => native_policy("managed-pinvoke"),
        "managed-native-implementation" => native_policy("managed-native"),
        _ => return None,
    })
}

/// `SEMANTIC_NODE_POLICIES`.
fn semantic_policy(kind: &str) -> Option<Policy> {
    Some(match kind {
        "child-process" => policy(
            "process",
            "child-process",
            "packaged-process",
            &["positive", "negative", "cancellation", "teardown"],
        ),
        "stdio" => policy("process", "stdio", "packaged-process", &["positive", "negative", "teardown"]),
        "signal" => policy("process", "signal", "packaged-process", &["positive", "cancellation", "teardown"]),
        "config-source" => parser_policy("cli", "configuration", "integration"),
        "request" => parser_policy("protocol", "request", "protocol"),
        "response" => parser_policy("protocol", "response", "protocol"),
        "boundary" => parser_policy("application", "parser-boundary", "integration"),
        "resource" => policy("persistence", "resource-lifecycle", "integration", &["positive", "negative", "teardown"]),
        "event" => policy("runtime", "event", "packaged-process", &["positive", "negative", "cancellation"]),
        "timer" => policy("runtime", "timer", "packaged-process", &["positive", "cancellation", "teardown"]),
        "promise" => policy("runtime", "promise-ownership", "packaged-process", &["positive", "negative", "cancellation"]),
        "task" => policy("runtime", "task-lifecycle", "packaged-process", &["positive", "cancellation", "teardown"]),
        _ => return None,
    })
}

fn obligation_id(key: &str) -> Result<String, JsError> {
    Ok(format!("obl_{}", digest(&json!({ "schema": "ReconstructionObligation", "key": key }))?))
}

fn source_state(references: &[AuthorityReference]) -> String {
    for state in ["observed", "candidate", "reviewed"] {
        if references.iter().any(|r| r.state == state) {
            return state.to_string();
        }
    }
    "unknown".to_string()
}

/// `uniqueBy`: last value per key wins its first-insertion slot, then locale sort by key.
fn unique_by<T: Clone>(values: Vec<T>, key: impl Fn(&T) -> String) -> Vec<T> {
    let mut order: Vec<String> = Vec::new();
    let mut map: BTreeMap<String, T> = BTreeMap::new();
    for value in values {
        let k = key(&value);
        if !map.contains_key(&k) {
            order.push(k.clone());
        }
        map.insert(k, value);
    }
    order.sort_by(|a, b| locale_compare(a, b));
    order.into_iter().filter_map(|k| map.remove(&k)).collect()
}

fn reference_key(r: &AuthorityReference) -> String {
    format!("{}:{}:{}", r.evidence_id, r.state, r.location)
}

fn case_key(c: &ObservedCase) -> String {
    format!("{}:{}:{}", c.kind, c.evidence_id, c.location)
}

fn add_candidate(candidates: &mut BTreeMap<String, Candidate>, candidate: Candidate) {
    let Some(current) = candidates.get(&candidate.obligation_id).cloned() else {
        candidates.insert(candidate.obligation_id.clone(), candidate);
        return;
    };
    let all_references: Vec<AuthorityReference> = current
        .authority_references
        .iter()
        .chain(&candidate.authority_references)
        .cloned()
        .collect();
    let mut merged = current.clone();
    merged.authority_references = unique_by(all_references.clone(), reference_key);
    merged.observed_cases = unique_by(
        current.observed_cases.iter().chain(&candidate.observed_cases).cloned().collect(),
        case_key,
    );
    merged.source_state = source_state(&all_references);
    merged.definition_count = current.definition_count + candidate.definition_count;
    candidates.insert(merged.obligation_id.clone(), merged);
}

struct GeneratedInput {
    key: String,
    title: String,
    policy: Policy,
    artifact_sha256: Option<String>,
    application_node_id: Option<String>,
    semantic_node_id: Option<String>,
    location: String,
    references: Vec<AuthorityReference>,
}

fn generated_candidate(input: GeneratedInput) -> Result<Candidate, JsError> {
    let policy = input.policy;
    Ok(Candidate {
        obligation_id: obligation_id(&input.key)?,
        obligation_version: 1,
        title: input.title,
        origin: "generated",
        application_layer: policy.layer.to_string(),
        family: policy.family.to_string(),
        target: Target {
            artifact_sha256: input.artifact_sha256,
            application_node_id: input.application_node_id,
            semantic_node_id: input.semantic_node_id,
            location: input.location,
        },
        source_state: source_state(&input.references),
        authority_references: input.references,
        observed_cases: vec![],
        required: true,
        required_case_kinds: policy.cases.iter().map(|s| s.to_string()).collect(),
        required_original_authority: policy.original.to_string(),
        required_fixture_authority: policy.fixture.to_string(),
        required_verifier_authority: policy.verifier.to_string(),
        requires_parser_type: policy.parser,
        dependency_obligation_ids: vec![],
        residual_unknown_ids: vec![],
        unavailable_authority: vec![],
        required_next_evidence: vec![format!(
            "Obtain {} authority for this finite {} claim.",
            policy.original, policy.family
        )],
        definition_count: 1,
        disposition: "active".to_string(),
    })
}

/// `graphReference`.
fn graph_reference(
    envelope: &Evidence,
    records: &BTreeMap<String, Evidence>,
    graph_evidence: &Value,
    location: String,
) -> AuthorityReference {
    let linked_id = graph_evidence["evidence_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .find(|id| records.contains_key(*id))
        .map(str::to_string)
        .unwrap_or_else(|| envelope.evidence_id.clone());
    let linked = records.get(&linked_id).unwrap_or(envelope);
    let authority = graph_evidence["authority"].as_str().unwrap_or_default();
    let state = graph_evidence["state"].as_str().unwrap_or_default();
    let runtime = authority == "passive-cdp-runtime" || authority == "controlled-replay";
    AuthorityReference {
        evidence_id: linked.evidence_id.clone(),
        authority: authority_str(linked.authority).to_string(),
        state: if runtime && state == "observed" {
            "observed"
        } else if state == "unknown" || state == "unavailable" {
            "unknown"
        } else {
            "candidate"
        }
        .to_string(),
        location,
    }
}

/// Graph source of `parseApplicationGraphEvidence`.
struct GraphSource<'a> {
    graph: &'a Value,
    root_artifact_sha256: String,
    semantic_graph: Option<&'a Value>,
}

fn links_within(evidence: &Evidence) -> bool {
    evidence.normalized_result["evidence_links"]
        .as_array()
        .is_some_and(|links| links.iter().all(|id| id.as_str().is_some_and(|id| evidence.evidence_links.iter().any(|l| l == id))))
}

/// Envelope checks of `parseApplicationGraphEvidence` (the nested zod result schemas
/// are only checked for the fields obligation derivation consumes).
fn parse_graph_source(evidence: &Evidence) -> Option<GraphSource<'_>> {
    let result = &evidence.normalized_result;
    let graph = result.get("graph").filter(|g| g.get("nodes").is_some_and(Value::is_array))?;
    match evidence.operation.as_str() {
        "analyze_javascript_application" => {
            let subject = evidence.subject.as_ref()?;
            let root = result["root_artifact_sha256"].as_str()?;
            let ok = evidence.predicate_type == "rea.javascript-application-analysis"
                && provider_is(evidence, "rea-javascript-application", "REA JavaScript application analyzer", "1")
                && evidence.authority == EvidenceAuthority::ShippedArtifact
                && evidence.confidence == EvidenceConfidence::Derived
                && subject.digest.sha256 == root
                && Some(subject.format.as_str()) == result["format"].as_str()
                && Some(subject.local_path.as_str()) == result["input_path"].as_str();
            ok.then(|| GraphSource {
                graph,
                root_artifact_sha256: root.to_string(),
                semantic_graph: result.get("semantic_graph").filter(|s| s.is_object()),
            })
        }
        "reconcile_javascript_runtime" => {
            let ok = evidence.predicate_type == "rea.javascript-runtime-reconciliation"
                && provider_is(
                    evidence,
                    "rea-javascript-runtime-reconciliation",
                    "REA JavaScript runtime reconciliation",
                    "1",
                )
                && evidence.authority == EvidenceAuthority::AnalystInference
                && evidence.confidence == EvidenceConfidence::Inferred
                && links_within(evidence);
            if !ok {
                return None;
            }
            let layer = result["static_layers"]
                .as_array()?
                .iter()
                .find(|layer| layer["role"] == "application")?;
            Some(GraphSource {
                graph,
                root_artifact_sha256: layer["root_artifact_sha256"].as_str()?.to_string(),
                semantic_graph: None,
            })
        }
        "project_managed_application_graph" => {
            let ok = evidence.predicate_type == "rea.managed-application-graph"
                && provider_is(evidence, "rea-dotnet-workflows", "REA managed-code workflows", "1")
                && evidence.authority == EvidenceAuthority::AnalystInference
                && evidence.confidence == EvidenceConfidence::Inferred
                && links_within(evidence);
            ok.then(|| {
                Some(GraphSource {
                    graph,
                    root_artifact_sha256: result["root_artifact_sha256"].as_str()?.to_string(),
                    semantic_graph: None,
                })
            })
            .flatten()
        }
        _ => None,
    }
}

fn derive_application_candidates(
    evidence: &Evidence,
    records: &BTreeMap<String, Evidence>,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) {
    if ![
        "analyze_javascript_application",
        "reconcile_javascript_runtime",
        "project_managed_application_graph",
    ]
    .contains(&evidence.operation.as_str())
    {
        return;
    }
    let Some(source) = parse_graph_source(evidence) else {
        limitations.insert(format!(
            "Application Evidence {} could not generate candidates because it failed graph validation.",
            evidence.evidence_id
        ));
        return;
    };
    if let Err(error) = derive_from_source(evidence, &source, records, candidates, limitations) {
        limitations.insert(format!(
            "Application Evidence {} could not generate candidates: {}",
            evidence.evidence_id, error
        ));
    }
}

fn derive_from_source(
    evidence: &Evidence,
    source: &GraphSource<'_>,
    records: &BTreeMap<String, Evidence>,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) -> Result<(), JsError> {
    let graph_id = source.graph["graph_id"].as_str().unwrap_or_default();
    for node in source.graph["nodes"].as_array().into_iter().flatten() {
        let kind = node["kind"].as_str().unwrap_or_default();
        let node_id = node["node_id"].as_str().unwrap_or_default();
        let Some(policy) = application_policy(kind) else {
            if kind == "unknown" {
                limitations.insert(format!(
                    "Application graph {graph_id} contains unresolved node {node_id}; reconstruction obligations remain unknown."
                ));
            }
            continue;
        };
        let observations: Vec<&Value> = node["observations"].as_array().into_iter().flatten().collect();
        let references = observations
            .iter()
            .map(|observation| {
                graph_reference(
                    evidence,
                    records,
                    &observation["evidence"],
                    format!(
                        "{graph_id}/node/{node_id}/observation/{}",
                        observation["observation_id"].as_str().unwrap_or_default()
                    ),
                )
            })
            .collect();
        let title = observations
            .first()
            .and_then(|o| o["label"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{kind} boundary"));
        let family = policy.family;
        add_candidate(
            candidates,
            generated_candidate(GeneratedInput {
                key: format!("application:{node_id}:{family}"),
                title,
                policy,
                artifact_sha256: Some(source.root_artifact_sha256.clone()),
                application_node_id: Some(node_id.to_string()),
                semantic_node_id: None,
                location: format!("application-graph:{graph_id}/nodes/{node_id}"),
                references,
            })?,
        );
    }
    if let Some(semantic) = source.semantic_graph {
        let semantic_id = semantic["graph_id"].as_str().unwrap_or_default();
        let contexts: BTreeMap<&str, &Value> = semantic["evidence_contexts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["context_id"].as_str().map(|id| (id, c)))
            .collect();
        for node in semantic["nodes"].as_array().into_iter().flatten() {
            let kind = node["kind"].as_str().unwrap_or_default();
            let Some(policy) = semantic_policy(kind) else { continue };
            let node_id = node["node_id"].as_str().unwrap_or_default();
            let context = contexts
                .get(node["evidence"]["context_id"].as_str().unwrap_or_default())
                .ok_or_else(|| invalid("Semantic evidence reference names an absent context"))?;
            let title = node["label"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{kind} semantic boundary"));
            let family = policy.family;
            add_candidate(
                candidates,
                generated_candidate(GeneratedInput {
                    key: format!("semantic:{node_id}:{family}"),
                    title,
                    policy,
                    artifact_sha256: node["identity"]["artifact_sha256"].as_str().map(str::to_string),
                    application_node_id: node["application_node_ids"]
                        .as_array()
                        .and_then(|ids| ids.first())
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    semantic_node_id: Some(node_id.to_string()),
                    location: format!("semantic-graph:{semantic_id}/nodes/{node_id}"),
                    references: vec![graph_reference(
                        evidence,
                        records,
                        context,
                        format!("{semantic_id}/node/{node_id}"),
                    )],
                    })?,
            );
        }
    }
    let coverage = source.graph["coverage"]["status"].as_str().unwrap_or("unknown");
    if coverage != "complete" {
        limitations.insert(format!(
            "Application graph {graph_id} coverage is {coverage}; omitted candidates remain unknown."
        ));
    }
    Ok(())
}

fn derive_process_candidate(
    evidence: &Evidence,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) {
    if evidence.operation != "capture_process_scenario" || evidence.predicate_type != "rea.process-capture" {
        return;
    }
    if let Err(error) = derive_process(evidence, candidates, limitations) {
        limitations.insert(format!(
            "Process Evidence {} could not generate candidates: {}",
            evidence.evidence_id, error
        ));
    }
}

fn derive_process(
    evidence: &Evidence,
    candidates: &mut BTreeMap<String, Candidate>,
    limitations: &mut BTreeSet<String>,
) -> Result<(), JsError> {
    let capture = &evidence.normalized_result;
    let exit = capture
        .get("exit")
        .filter(|e| e.is_object())
        .ok_or_else(|| invalid("Process capture exit is missing"))?;
    let manifest = capture
        .get("manifest")
        .filter(|m| m.is_object())
        .ok_or_else(|| invalid("Process capture manifest is missing"))?;
    let truncated = capture["truncated"]
        .as_bool()
        .ok_or_else(|| invalid("Process capture truncated flag is missing"))?;
    let residual = capture["residual_unknowns"]
        .as_array()
        .ok_or_else(|| invalid("Process capture residual_unknowns are missing"))?;
    let full_scenario = manifest["full_scenario_sha256"]
        .as_str()
        .ok_or_else(|| invalid("Process capture full_scenario_sha256 is missing"))?;
    let id = evidence.evidence_id.clone();
    let case = |kind: &str, location: &str| ObservedCase {
        kind: kind.to_string(),
        evidence_id: id.clone(),
        location: location.to_string(),
    };
    let mut observed = vec![
        case(
            if exit["code"].as_i64() == Some(0) { "positive" } else { "negative" },
            "/normalized_result/exit",
        ),
        case("teardown", "/normalized_result/settlement"),
    ];
    if !exit["signal"].is_null() || exit["reason"] != "exited" {
        observed.push(case("cancellation", "/normalized_result/exit"));
    }
    let Some(executable) = manifest["executable_sha256"].as_str() else {
        limitations.insert(format!(
            "Process capture {id} has no validated executable artifact identity; packaged-process lifecycle obligation was not bound to an artifact."
        ));
        return Ok(());
    };
    let references = vec![AuthorityReference {
        evidence_id: id.clone(),
        authority: authority_str(evidence.authority).to_string(),
        state: "observed".to_string(),
        location: "/normalized_result".to_string(),
    }];
    add_candidate(
        candidates,
        Candidate {
            obligation_id: obligation_id(&format!("process:{executable}:{full_scenario}"))?,
            obligation_version: 1,
            title: "Captured packaged-process lifecycle".to_string(),
            origin: "generated",
            application_layer: "process".to_string(),
            family: "packaged-process-lifecycle".to_string(),
            target: Target {
                artifact_sha256: Some(executable.to_string()),
                application_node_id: None,
                semantic_node_id: None,
                location: format!("/evidence/{id}/normalized_result"),
            },
            authority_references: references,
            source_state: "observed".to_string(),
            observed_cases: observed,
            required: true,
            required_case_kinds: ["positive", "negative", "cancellation", "teardown"].map(String::from).to_vec(),
            required_original_authority: "process".to_string(),
            required_fixture_authority: "packaged-process".to_string(),
            required_verifier_authority: "packaged-process".to_string(),
            requires_parser_type: false,
            dependency_obligation_ids: vec![],
            residual_unknown_ids: vec![],
            unavailable_authority: residual
                .iter()
                .map(|u| format!("{}: {}", u["scope"].as_str().unwrap_or_default(), u["reason"].as_str().unwrap_or_default()))
                .collect(),
            required_next_evidence: if truncated {
                vec!["Repeat the packaged-process capture without truncation.".to_string()]
            } else {
                vec![]
            },
            definition_count: 1,
            disposition: "active".to_string(),
        },
    );
    if truncated {
        limitations.insert(format!(
            "Process Evidence {id} is truncated; absence and upper bounds remain unknown."
        ));
    }
    Ok(())
}

fn reviewed_state(evidence: &Evidence) -> &'static str {
    if evidence.operation == "capture_process_scenario"
        && evidence.predicate_type == "rea.process-capture"
        && evidence.confidence == EvidenceConfidence::Observed
    {
        return "observed";
    }
    if evidence.authority == EvidenceAuthority::ExternalService && evidence.confidence == EvidenceConfidence::Observed {
        return "observed";
    }
    if evidence.authority == EvidenceAuthority::ShippedArtifact {
        return "candidate";
    }
    "reviewed"
}

fn reviewed_candidate(item: &Reviewed, records: &BTreeMap<String, Evidence>) -> Result<Candidate, JsError> {
    let references = item
        .review_evidence_ids
        .iter()
        .map(|id| {
            let evidence = records
                .get(id)
                .ok_or_else(|| invalid(format!("Reviewed obligation Evidence is missing: {id}")))?;
            Ok(AuthorityReference {
                evidence_id: id.clone(),
                authority: authority_str(evidence.authority).to_string(),
                state: reviewed_state(evidence).to_string(),
                location: format!("/evidence/{id}"),
            })
        })
        .collect::<Result<Vec<_>, JsError>>()?;
    Ok(Candidate {
        obligation_id: item.obligation_id.clone(),
        obligation_version: item.obligation_version,
        title: item.title.clone(),
        origin: "reviewed",
        application_layer: item.application_layer.clone(),
        family: item.family.clone(),
        target: item.target.clone(),
        authority_references: references,
        source_state: "reviewed".to_string(),
        observed_cases: vec![],
        required: item.required,
        required_case_kinds: item.required_case_kinds.clone(),
        required_original_authority: item.required_original_authority.clone(),
        required_fixture_authority: item.required_fixture_authority.clone(),
        required_verifier_authority: item.required_verifier_authority.clone(),
        requires_parser_type: item.requires_parser_type,
        dependency_obligation_ids: item.dependency_obligation_ids.clone(),
        residual_unknown_ids: item.residual_unknown_ids.clone(),
        unavailable_authority: item.unavailable_authority.clone(),
        required_next_evidence: item.required_next_evidence.clone(),
        definition_count: 1,
        disposition: item.disposition.clone(),
    })
}

// ---------------------------------------------------------------- authority

fn proof_evidence_authorities(authority: &str) -> &'static [&'static str] {
    match authority {
        "unit" | "native-abi" => &["shipped-artifact", "controlled-replay"],
        "integration" | "packaged-process" => &["controlled-replay"],
        "protocol" | "renderer" | "live-observation" => &["controlled-replay", "external-service"],
        _ => &["external-service"],
    }
}

/// `proofAuthoritySatisfies`.
fn proof_satisfies(actual: &str, required: &str) -> bool {
    let accepted: &[&str] = match required {
        "unit" => &PROOF_AUTHORITIES,
        "integration" => &[
            "integration",
            "protocol",
            "renderer",
            "packaged-process",
            "native-abi",
            "live-observation",
        ],
        "protocol" => &["protocol", "packaged-process", "live-observation"],
        "renderer" => &["renderer", "packaged-process", "live-observation"],
        "packaged-process" => &["packaged-process", "live-observation"],
        "native-abi" => &["native-abi"],
        "live-observation" => &["live-observation"],
        _ => &["external"],
    };
    accepted.contains(&actual)
}

#[derive(Default)]
struct ExpectedProof<'a> {
    obligation_id: &'a str,
    fixture_id: Option<&'a str>,
    case_kind: Option<&'a str>,
    verifier_id: Option<&'a str>,
    claim_id: Option<&'a str>,
}

/// `evidenceAuthoritySupportsProof`.
fn supports_proof(evidence: &Evidence, authority: &str, expected: &ExpectedProof<'_>) -> bool {
    if evidence.confidence != EvidenceConfidence::Observed
        || !proof_evidence_authorities(authority).contains(&authority_str(evidence.authority))
        || evidence.predicate_type != "rea.reconstruction-proof"
        || evidence.operation != "verify_reconstruction_obligations"
    {
        return false;
    }
    let result = &evidence.normalized_result;
    if !result.is_object() {
        return false;
    }
    let includes = |key: &str, value: Option<&str>| {
        value.is_none_or(|value| {
            result[key]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
        })
    };
    result["passed"] == Value::Bool(true)
        && includes("obligation_ids", Some(expected.obligation_id))
        && includes("fixture_ids", expected.fixture_id)
        && includes("case_kinds", expected.case_kind)
        && includes("verifier_ids", expected.verifier_id)
        && includes("claim_ids", expected.claim_id)
}

/// `evidenceSupportsOriginalAuthority`.
fn supports_original(evidence: &Evidence, authority: &str) -> bool {
    if evidence.confidence != EvidenceConfidence::Observed {
        return false;
    }
    match authority {
        "static" => evidence.authority == EvidenceAuthority::ShippedArtifact,
        "runtime" => matches!(
            evidence.authority,
            EvidenceAuthority::ControlledReplay | EvidenceAuthority::ExternalService
        ),
        "process" => evidence.operation == "capture_process_scenario" && evidence.predicate_type == "rea.process-capture",
        _ => evidence.authority == EvidenceAuthority::ExternalService,
    }
}

// ---------------------------------------------------------------- evaluation

#[derive(Clone)]
struct Diagnostic {
    code: &'static str,
    detail: String,
}

fn diag(diagnostics: &mut Vec<Diagnostic>, code: &'static str, detail: impl Into<String>) {
    diagnostics.push(Diagnostic { code, detail: detail.into() });
}

fn has(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|d| d.code == code)
}

/// `uniqueObligationDiagnostics`.
fn unique_diagnostics(diagnostics: Vec<Diagnostic>) -> Vec<Diagnostic> {
    unique_by(diagnostics, |d| format!("{}:{}", d.code, d.detail))
}

/// `originalCasesFor`.
fn original_cases(candidate: &Candidate, binding: Option<&Binding>) -> Vec<ObservedCase> {
    let all: Vec<ObservedCase> = candidate
        .observed_cases
        .iter()
        .chain(binding.map(|b| b.original_cases.as_slice()).unwrap_or_default())
        .cloned()
        .collect();
    unique_by(all, case_key)
}

struct Obligation {
    candidate: Candidate,
    binding: Option<Binding>,
    observed_cases: Vec<ObservedCase>,
    status: &'static str,
    diagnostics: Vec<Diagnostic>,
}

struct EvaluationContext<'a> {
    candidates: BTreeSet<String>,
    evidence: &'a BTreeMap<String, Evidence>,
    bindings: BTreeMap<String, Vec<Binding>>,
    contradictions: BTreeMap<String, Vec<String>>,
}

fn evaluate_obligation(candidate: &Candidate, context: &EvaluationContext<'_>) -> Obligation {
    let bindings = context.bindings.get(&candidate.obligation_id).cloned().unwrap_or_default();
    let binding = (bindings.len() == 1).then(|| bindings[0].clone());
    let mut diagnostics = Vec::new();
    if candidate.definition_count > 1 {
        diag(&mut diagnostics, "duplicate-definition", "Multiple candidate definitions share this obligation ID.");
    }
    if bindings.is_empty() {
        diag(&mut diagnostics, "missing-owner", "No reconstruction manifest binding owns this obligation.");
    }
    if bindings.len() > 1 {
        diag(&mut diagnostics, "ambiguous-owner", "Multiple reconstruction manifest bindings claim this obligation.");
    }
    if let Some(binding) = &binding {
        evaluate_binding(candidate, binding, context, &mut diagnostics);
    }
    let cases = original_cases(candidate, binding.as_ref());
    // originalCaseDiagnostics
    for kind in &candidate.required_case_kinds {
        let matching: Vec<&ObservedCase> = cases.iter().filter(|c| &c.kind == kind).collect();
        if matching.is_empty() {
            diag(&mut diagnostics, "missing-original-case", format!("Original {kind} behavior has not been observed."));
            continue;
        }
        if !matching.iter().any(|c| {
            context
                .evidence
                .get(&c.evidence_id)
                .is_some_and(|e| supports_original(e, &candidate.required_original_authority))
        }) {
            diag(
                &mut diagnostics,
                "weak-original-case-authority",
                format!(
                    "Original {kind} behavior lacks {} Evidence.",
                    candidate.required_original_authority
                ),
            );
        }
    }
    // evaluateAuthority
    let original = candidate.required_original_authority.as_str();
    let reference_ok = candidate.authority_references.iter().any(|r| {
        context.evidence.get(&r.evidence_id).is_some_and(|e| {
            (if original == "static" {
                r.state == "candidate" || r.state == "observed"
            } else {
                r.state == "observed"
            }) && supports_original(e, original)
        })
    });
    let case_ok = cases
        .iter()
        .any(|c| context.evidence.get(&c.evidence_id).is_some_and(|e| supports_original(e, original)));
    if !reference_ok && !case_ok {
        diag(
            &mut diagnostics,
            "static-only",
            format!("No {original} authority characterizes the original finite behavior."),
        );
    }
    // evaluateDisposition
    if candidate.disposition == "blocked" {
        diag(&mut diagnostics, "blocked", "Reviewed disposition marks this obligation blocked.");
    }
    if candidate.disposition == "out-of-scope" {
        diag(
            &mut diagnostics,
            "out-of-scope",
            "Reviewed disposition marks this obligation out of scope; it remains visible.",
        );
    }
    // contradictionDiagnostics
    let contradiction_ids = context.contradictions.get(&candidate.obligation_id).cloned().unwrap_or_default();
    if !contradiction_ids.is_empty() {
        let missing: Vec<&String> = contradiction_ids.iter().filter(|id| !context.evidence.contains_key(*id)).collect();
        if missing.is_empty() {
            diag(&mut diagnostics, "contradiction", "Authenticated contradictory Evidence reopens this obligation.");
        } else {
            diag(
                &mut diagnostics,
                "contradiction-evidence-missing",
                format!(
                    "Contradiction references missing Evidence: {}.",
                    missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
            );
        }
    }
    for unknown in &candidate.residual_unknown_ids {
        diag(&mut diagnostics, "residual-unknown", format!("Residual unknown remains visible: {unknown}."));
    }
    for unavailable in &candidate.unavailable_authority {
        diag(&mut diagnostics, "unavailable-authority", unavailable.clone());
    }
    let status = obligation_status(binding.is_some(), &diagnostics);
    Obligation {
        candidate: candidate.clone(),
        binding,
        observed_cases: cases,
        status,
        diagnostics: unique_diagnostics(diagnostics),
    }
}

fn evaluate_binding(
    candidate: &Candidate,
    binding: &Binding,
    context: &EvaluationContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if candidate.requires_parser_type && binding.parser_type.is_none() {
        diag(
            diagnostics,
            "missing-parser-type",
            "This boundary requires an explicit parser, schema, and domain type.",
        );
    }
    for kind in &candidate.required_case_kinds {
        let fixtures: Vec<&FixtureBinding> = binding.fixtures.iter().filter(|f| &f.case_kind == kind).collect();
        if fixtures.is_empty() {
            diag(diagnostics, "missing-case", format!("Required {kind} fixture is missing."));
            continue;
        }
        let ok = fixtures.iter().any(|fixture| {
            proof_satisfies(&fixture.authority, &candidate.required_fixture_authority)
                && fixture.evidence_ids.iter().all(|id| {
                    context.evidence.get(id).is_some_and(|e| {
                        supports_proof(
                            e,
                            &fixture.authority,
                            &ExpectedProof {
                                obligation_id: &candidate.obligation_id,
                                fixture_id: Some(&fixture.fixture_id),
                                case_kind: Some(&fixture.case_kind),
                                ..Default::default()
                            },
                        )
                    })
                })
        });
        if !ok {
            diag(
                diagnostics,
                "weak-fixture-authority",
                format!(
                    "{kind} fixture lacks {} authority or authenticated Evidence.",
                    candidate.required_fixture_authority
                ),
            );
        }
    }
    let Some(verifier) = &binding.verifier else {
        diag(diagnostics, "missing-verifier", "No verifier claim is bound to this obligation.");
        return;
    };
    if !verifier.enumerated_obligation_ids.contains(&candidate.obligation_id) {
        diag(
            diagnostics,
            "verifier-does-not-enumerate",
            "The verifier claim does not enumerate this obligation ID.",
        );
    }
    let result = context.evidence.get(&verifier.result_evidence_id);
    if result.is_none() {
        diag(
            diagnostics,
            "missing-verifier-result",
            "The latest verifier result Evidence is absent from the bundle.",
        );
    }
    let weak = !proof_satisfies(&verifier.authority, &candidate.required_verifier_authority)
        || result.is_some_and(|e| {
            !supports_proof(
                e,
                &verifier.authority,
                &ExpectedProof {
                    obligation_id: &candidate.obligation_id,
                    verifier_id: Some(&verifier.verifier_id),
                    claim_id: Some(&verifier.claim_id),
                    ..Default::default()
                },
            )
        });
    if weak {
        diag(
            diagnostics,
            "weak-verifier-authority",
            format!(
                "Verifier authority does not satisfy {}.",
                candidate.required_verifier_authority
            ),
        );
    }
    if verifier.status != "pass" {
        diag(diagnostics, "verifier-failed", format!("Latest verifier status is {}.", verifier.status));
    }
}

fn obligation_status(bound: bool, diagnostics: &[Diagnostic]) -> &'static str {
    if has(diagnostics, "out-of-scope") {
        "out-of-scope"
    } else if has(diagnostics, "blocked") {
        "blocked"
    } else if has(diagnostics, "contradiction") {
        "contradicted"
    } else if has(diagnostics, "duplicate-definition")
        || has(diagnostics, "residual-unknown")
        || has(diagnostics, "unavailable-authority")
    {
        "unknown"
    } else if !bound {
        "unowned"
    } else if diagnostics.is_empty() {
        "verified"
    } else {
        "implemented"
    }
}

fn apply_dependency_diagnostics(mut obligations: Vec<Obligation>, context: &EvaluationContext<'_>) -> Vec<Obligation> {
    for _ in 0..obligations.len() {
        let statuses: BTreeMap<String, &'static str> = obligations
            .iter()
            .map(|o| (o.candidate.obligation_id.clone(), o.status))
            .collect();
        let mut changed = false;
        for obligation in &mut obligations {
            let mut diagnostics = obligation.diagnostics.clone();
            for dependency in &obligation.candidate.dependency_obligation_ids {
                let missing = !context.candidates.contains(dependency);
                if missing || statuses.get(dependency) != Some(&"verified") {
                    diag(
                        &mut diagnostics,
                        if missing { "dependency-missing" } else { "dependency-open" },
                        format!(
                            "Dependency obligation is {}: {dependency}.",
                            if missing { "missing" } else { "not verified" }
                        ),
                    );
                }
            }
            let normalized = unique_diagnostics(diagnostics);
            let status = if (has(&normalized, "dependency-missing") || has(&normalized, "dependency-open"))
                && !["contradicted", "out-of-scope"].contains(&obligation.status)
            {
                "blocked"
            } else {
                obligation.status
            };
            changed |= status != obligation.status;
            obligation.status = status;
            obligation.diagnostics = normalized;
        }
        if !changed {
            break;
        }
    }
    obligations
}

fn obligation_value(o: &Obligation) -> Result<Value, JsError> {
    let c = &o.candidate;
    Ok(json!({
        "obligation_id": c.obligation_id,
        "obligation_version": c.obligation_version,
        "title": c.title,
        "origin": c.origin,
        "application_layer": c.application_layer,
        "family": c.family,
        "target": serde_json::to_value(&c.target)?,
        "authority_references": serde_json::to_value(&c.authority_references)?,
        "source_state": c.source_state,
        "observed_cases": serde_json::to_value(&o.observed_cases)?,
        "required": c.required,
        "required_case_kinds": c.required_case_kinds,
        "required_original_authority": c.required_original_authority,
        "required_fixture_authority": c.required_fixture_authority,
        "required_verifier_authority": c.required_verifier_authority,
        "requires_parser_type": c.requires_parser_type,
        "dependency_obligation_ids": c.dependency_obligation_ids,
        "residual_unknown_ids": c.residual_unknown_ids,
        "unavailable_authority": c.unavailable_authority,
        "required_next_evidence": c.required_next_evidence,
        "binding": serde_json::to_value(&o.binding)?,
        "status": o.status,
        "diagnostics": o.diagnostics.iter().map(|d| json!({ "code": d.code, "detail": d.detail })).collect::<Vec<_>>(),
    }))
}

fn ledger_status(obligations: &[Obligation]) -> &'static str {
    if obligations.is_empty() {
        return "unknown";
    }
    let open: Vec<&Obligation> = obligations
        .iter()
        .filter(|o| o.candidate.required && o.status != "verified")
        .collect();
    if open.iter().any(|o| o.status == "contradicted" || has(&o.diagnostics, "verifier-failed")) {
        "failed"
    } else if open.iter().any(|o| o.status == "unknown") {
        "unknown"
    } else if open.is_empty() {
        "ready"
    } else {
        "open"
    }
}

fn count_by(obligations: &[Obligation], keys: &[&str], value: impl Fn(&Obligation) -> String) -> Value {
    Value::Array(
        keys.iter()
            .map(|key| json!({ "key": key, "count": obligations.iter().filter(|o| value(o) == *key).count() }))
            .collect(),
    )
}

fn ids_with(obligations: &[Obligation], code: &str) -> Vec<String> {
    default_sorted_unique_keep(
        obligations
            .iter()
            .filter(|o| has(&o.diagnostics, code))
            .map(|o| o.candidate.obligation_id.clone())
            .collect(),
    )
}

/// `.sort()` without deduplication.
fn default_sorted_unique_keep(mut values: Vec<String>) -> Vec<String> {
    values.sort_by(|a, b| compare_unicode_code_points(a, b));
    values
}

fn edge_order(values: &mut [Value]) -> Result<(), JsError> {
    let mut keyed: Vec<(String, Value)> = values
        .iter()
        .map(|v| Ok((canonical(v)?, v.clone())))
        .collect::<Result<_, JsError>>()?;
    keyed.sort_by(|a, b| compare_unicode_code_points(&a.0, &b.0));
    for (slot, (_, value)) in values.iter_mut().zip(keyed) {
        *slot = value;
    }
    Ok(())
}

/// `build_reconstruction_obligation_ledger`: ledger Evidence plus the bundle records
/// REA records into the session (`recordSessionEvidenceSources`).
pub fn build_reconstruction_obligation_ledger(args: &Value) -> Result<(Evidence, Vec<Evidence>), JsError> {
    let object = args.as_object().ok_or_else(|| invalid("input must be an object"))?;
    if object
        .keys()
        .any(|k| !["evidence_bundle", "reviewed_obligations", "manifest"].contains(&k.as_str()))
    {
        return Err(invalid("build_reconstruction_obligation_ledger received an unexpected property"));
    }
    let bundle_value = object
        .get("evidence_bundle")
        .ok_or_else(|| invalid("build_reconstruction_obligation_ledger requires evidence_bundle"))?;
    let bundle: EvidenceBundle = parse_evidence_bundle(&serde_json::to_string(bundle_value)?)
        .map_err(|error| invalid(error.to_string()))?;
    let mut reviewed: Vec<Reviewed> = serde_json::from_value(
        object
            .get("reviewed_obligations")
            .cloned()
            .ok_or_else(|| invalid("build_reconstruction_obligation_ledger requires reviewed_obligations"))?,
    )
    .map_err(|error| invalid(format!("Invalid reviewed_obligations: {error}")))?;
    let mut manifest: Manifest = serde_json::from_value(
        object
            .get("manifest")
            .cloned()
            .ok_or_else(|| invalid("build_reconstruction_obligation_ledger requires manifest"))?,
    )
    .map_err(|error| invalid(format!("Invalid manifest: {error}")))?;
    for item in &mut reviewed {
        validate_reviewed(item)?;
    }
    for binding in &mut manifest.bindings {
        validate_binding(binding)?;
    }
    for contradiction in &manifest.contradictions {
        ensure(is_stable_id(&contradiction.obligation_id), "contradiction obligation_id is invalid")?;
        ids(&contradiction.evidence_ids, 2, "contradiction evidence_ids are invalid")?;
    }

    // deriveReconstructionObligationCandidates
    let records: BTreeMap<String, Evidence> =
        bundle.records.iter().map(|r| (r.evidence_id.clone(), r.clone())).collect();
    let mut candidates: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut generation_limitations: BTreeSet<String> = BTreeSet::new();
    for evidence in &bundle.records {
        derive_application_candidates(evidence, &records, &mut candidates, &mut generation_limitations);
        derive_process_candidate(evidence, &mut candidates, &mut generation_limitations);
    }
    for item in &reviewed {
        add_candidate(&mut candidates, reviewed_candidate(item, &records)?);
    }
    let mut candidates: Vec<Candidate> = candidates.into_values().collect();
    candidates.sort_by(|a, b| locale_compare(&a.obligation_id, &b.obligation_id));

    // evaluateReconstructionObligationLedger
    let candidate_ids: BTreeSet<String> = candidates.iter().map(|c| c.obligation_id.clone()).collect();
    let orphans = default_sorted_unique(
        manifest
            .bindings
            .iter()
            .map(|b| b.obligation_id.clone())
            .chain(manifest.contradictions.iter().map(|c| c.obligation_id.clone()))
            .filter(|id| !candidate_ids.contains(id)),
    );
    let mut bindings: BTreeMap<String, Vec<Binding>> = BTreeMap::new();
    for binding in &manifest.bindings {
        bindings.entry(binding.obligation_id.clone()).or_default().push(binding.clone());
    }
    let mut contradictions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for contradiction in &manifest.contradictions {
        contradictions
            .entry(contradiction.obligation_id.clone())
            .or_default()
            .extend(contradiction.evidence_ids.iter().cloned());
    }
    let context = EvaluationContext { candidates: candidate_ids, evidence: &records, bindings, contradictions };
    let obligations = apply_dependency_diagnostics(
        candidates.iter().map(|c| evaluate_obligation(c, &context)).collect(),
        &context,
    );
    let mut ownership: Vec<Value> = obligations
        .iter()
        .filter_map(|o| {
            o.binding.as_ref().map(|b| {
                json!({
                    "obligation_id": o.candidate.obligation_id,
                    "module_path": b.owner.module_path,
                    "symbol": b.owner.symbol,
                })
            })
        })
        .collect();
    edge_order(&mut ownership)?;
    let mut dependencies: Vec<Value> = obligations
        .iter()
        .flat_map(|o| {
            o.candidate.dependency_obligation_ids.iter().map(move |d| {
                json!({ "obligation_id": o.candidate.obligation_id, "depends_on_obligation_id": d })
            })
        })
        .collect();
    edge_order(&mut dependencies)?;
    let evidence_links = default_sorted_unique(
        obligations
            .iter()
            .flat_map(|o| o.candidate.authority_references.iter().map(|r| r.evidence_id.clone()))
            .chain(manifest.bindings.iter().flat_map(|b| {
                b.original_cases
                    .iter()
                    .map(|c| c.evidence_id.clone())
                    .chain(b.fixtures.iter().flat_map(|f| f.evidence_ids.iter().cloned()))
                    .chain(b.verifier.iter().map(|v| v.result_evidence_id.clone()))
            }))
            .chain(manifest.contradictions.iter().flat_map(|c| c.evidence_ids.iter().cloned())),
    );
    let mut limitations: Vec<String> = generation_limitations.into_iter().collect();
    if candidates.is_empty() {
        limitations.push("No reconstruction obligations were derived; closure cannot be claimed.".into());
    }
    if !orphans.is_empty() {
        limitations.push(format!("Manifest entries reference unknown obligations: {}.", orphans.join(", ")));
    }
    let limitations = default_sorted_unique(limitations);
    let obligation_values: Vec<Value> = obligations.iter().map(obligation_value).collect::<Result<_, _>>()?;
    let required_open = obligations
        .iter()
        .filter(|o| o.candidate.required && o.status != "verified")
        .count();
    let semantic = json!({
        "coverage": { "status": if limitations.is_empty() { "complete" } else { "partial" } },
        "summary": {
            "total": obligations.len(),
            "required": obligations.iter().filter(|o| o.candidate.required).count(),
            "verified": obligations.iter().filter(|o| o.status == "verified").count(),
            "required_open": required_open,
            "by_status": count_by(&obligations, &STATUSES, |o| o.status.to_string()),
            "by_application_layer": count_by(&obligations, &LAYERS, |o| o.candidate.application_layer.clone()),
            "by_evidence_authority": count_by(
                &obligations,
                &["candidate", "observed", "reviewed", "unknown"],
                |o| o.candidate.source_state.clone(),
            ),
        },
        "reports": {
            "missing_owner_obligation_ids": ids_with(&obligations, "missing-owner"),
            "missing_verifier_obligation_ids": ids_with(&obligations, "missing-verifier"),
            "contradicted_obligation_ids": ids_with(&obligations, "contradiction"),
            "residual_unknown_ids": default_sorted_unique(
                obligations.iter().flat_map(|o| o.candidate.residual_unknown_ids.iter().cloned()),
            ),
        },
        "ownership_graph": ownership,
        "dependency_graph": dependencies,
        "obligations": obligation_values,
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let evaluated = ledger_status(&obligations);
    let status = if evaluated == "failed" {
        "failed"
    } else if !limitations.is_empty() {
        "unknown"
    } else {
        evaluated
    };
    let mut closure_input = semantic.as_object().cloned().unwrap_or_default();
    closure_input.insert("schema".into(), json!("ReconstructionObligationClosure"));
    closure_input.insert("status".into(), json!(status));
    let closure_digest = digest(&Value::Object(closure_input))?;
    let ledger_id = format!(
        "rol_{}",
        digest(&json!({
            "schema": "ReconstructionObligationLedger",
            "evidence_ids": bundle.records.iter().map(|r| r.evidence_id.clone()).collect::<Vec<_>>(),
            "obligation_ids": obligations.iter().map(|o| o.candidate.obligation_id.clone()).collect::<Vec<_>>(),
            "closure_digest": closure_digest,
        }))?
    );
    let mut ledger = semantic.as_object().cloned().unwrap_or_default();
    ledger.insert("schema".into(), json!("ReconstructionObligationLedger"));
    ledger.insert("ledger_id".into(), json!(ledger_id));
    ledger.insert("closure_digest".into(), json!(closure_digest));
    ledger.insert("status".into(), json!(status));
    let ledger_links = evidence_links_of(&ledger);
    let mut evidence_limitations = vec![MISSING_SUBJECT.to_string()];
    evidence_limitations.extend(limitations.iter().cloned());
    let evidence = create_evidence(
        None,
        EvidenceProvider {
            id: "rea-javascript-application-workflows".to_string(),
            name: "REA JavaScript application workflows".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.reconstruction-obligation-ledger".to_string()),
            operation: "build_reconstruction_obligation_ledger".to_string(),
            parameters: json!({ "ledger_id": ledger_id, "closure_digest": closure_digest }),
            normalized_result: Value::Object(ledger),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(evidence_limitations),
            locations: None,
            evidence_links: Some(ledger_links),
        },
    )?;
    Ok((evidence, bundle.records))
}

fn evidence_links_of(ledger: &serde_json::Map<String, Value>) -> Vec<String> {
    ledger
        .get("evidence_links")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}
