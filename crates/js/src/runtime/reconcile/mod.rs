//! `reconcile_javascript_runtime` (port of REA
//! application/javascript/JavaScriptRuntimeReconciliation{Service,Evidence}.ts
//! and domain/javascript/javascriptRuntimeReconciliation.ts).

mod entities;
mod input;
mod matching;
mod paths;
mod project;

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
};

use crate::error::JsError;

const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

/// Derive a combined application graph from verified static and passive-runtime Evidence.
pub fn reconcile_javascript_runtime(args: &Value) -> Result<Evidence, JsError> {
    let parsed = input::parse_reconciliation_input(args)?;
    let runtime = entities::project_runtime_captures(&parsed.captures)?;
    let candidates = matching::collect_static_candidates(&parsed.layers);
    let matched = matching::reconcile_runtime_entities(&runtime.entities, &parsed.captures, &candidates, &parsed.layers)?;
    let load_states = project::classify_static_load_states(
        &parsed.layers,
        &parsed.captures,
        &runtime,
        &matched.items,
        runtime.omitted_entities == 0 && matched.omitted_items == 0,
    );
    let (graph, omitted_graph_items) =
        project::build_reconciled_graph(&parsed.layers, &parsed.captures, &runtime, &matched.edges, matched.omitted_items)?;
    let result = project::create_reconciliation_result(
        &parsed.layers,
        &parsed.captures,
        &runtime,
        &matched,
        load_states,
        graph,
        omitted_graph_items,
    )?;
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    };
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(strings(&result["limitations"]));
    let evidence_links = strings(&result["evidence_links"]);
    create_evidence(
        None,
        EvidenceProvider {
            id: "rea-javascript-runtime-reconciliation".to_string(),
            name: "REA JavaScript runtime reconciliation".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.javascript-runtime-reconciliation".to_string()),
            operation: "reconcile_javascript_runtime".to_string(),
            parameters: json!({
                "static_layers": parsed.parameter_layers,
                "runtime_evidence_ids": parsed.runtime_evidence_ids,
            }),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: Some(vec![]),
            evidence_links: Some(evidence_links),
        },
    )
    .map_err(JsError::from)
}
