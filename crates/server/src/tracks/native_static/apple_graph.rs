//! `project_apple_application_graph`: Apple application inventory projection
//! (REA `application/apple/AppleApplicationService.ts`).

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, EvidenceSubject,
};
use tracewise_native::apple_app::{parse_artifact_inventory_evidence, project_apple_application};
use tracewise_native::NativeError;

use super::common::{error_result, error_text_result};
use super::validate::{validate, Field, Kind};
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

const TOOL: &str = "project_apple_application_graph";

/// `APPLE_APPLICATION_PROVIDER` of REA (`application/InvestigationProviders.ts`).
fn apple_application_provider() -> EvidenceProvider {
    EvidenceProvider {
        id: "rea-apple-application".to_string(),
        name: "REA Apple application workflows".to_string(),
        version: Some("1".to_string()),
    }
}

pub fn project_apple_application_graph(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    if let Err(message) = validate(
        TOOL,
        args,
        &[Field { name: "inventory_evidence", kind: Kind::EvidenceList, required: true }],
    ) {
        return Ok(error_text_result(message));
    }
    let mut inputs: Vec<Evidence> = Vec::new();
    for item in args["inventory_evidence"].as_array().cloned().unwrap_or_default() {
        match serde_json::from_value::<Evidence>(item) {
            Ok(evidence) => inputs.push(evidence),
            Err(error) => {
                return Ok(error_result(&NativeError::input(
                    TOOL,
                    Vec::new(),
                    format!("A nested value failed validation at its root: {error}"),
                )))
            }
        }
    }
    let parsed = match parse_artifact_inventory_evidence(&inputs) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(error_result(&error)),
    };
    let projection = match project_apple_application(&parsed) {
        Ok(projection) => projection,
        Err(error) => return Ok(error_result(&error)),
    };
    // Subject: the first supplied Evidence' subject with the projection's root digest.
    let subject = inputs[0].subject.as_ref().map(|subject| {
        let name = subject
            .local_path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .unwrap_or("artifact")
            .to_string();
        EvidenceSubject {
            name,
            digest: DigestSha256 { sha256: projection.root_sha256.clone() },
            format: subject.format.clone(),
            architecture: None,
            local_path: subject.local_path.clone(),
        }
    });
    let evidence = create_evidence(
        subject,
        apple_application_provider(),
        EvidenceObservation {
            predicate_type: Some("rea.apple-application-graph".to_string()),
            operation: TOOL.to_string(),
            parameters: json!({ "inventory_evidence_ids": projection.source_evidence_ids }),
            normalized_result: projection.result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(projection.limitations),
            locations: None,
            evidence_links: Some(projection.source_evidence_ids),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}
