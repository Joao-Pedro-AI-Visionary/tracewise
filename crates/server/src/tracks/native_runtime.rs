//! Dispatch for the native runtime tools (6): `observe_native_ui`,
//! `capture_native_ui_scenario`, `observe_native_calls`,
//! `trace_native_ui_action`, `inspect_firmware_regions` and `extract_firmware`.
//!
//! The first three drive macOS Accessibility and LLDB. REA admits the
//! arguments, requires an open target, then asks the session's provider set for
//! the capability; on every other host that set answers `unsupported_host`
//! (`Native macOS utilities require macOS.`). That is the behaviour reproduced
//! here. The macOS bridges (Swift Accessibility helpers, the LLDB call tracer)
//! are not ported: on a macOS host the same error is returned with a reason
//! that says so, instead of pretending to observe anything.

use std::collections::HashMap;

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::Value;
use tracewise_device::firmware::{self, FIRMWARE_TOOLS};
use tracewise_device::ui_trace::{self, AnalysisPort, PortExecution, TraceInput};
use tracewise_device::native::{self, composite_provider_id, HOST_GATED_TOOLS};
use tracewise_device::ToolError;
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, EvidenceConfidence, EvidenceLocation, EvidenceObservation, EvidenceProvider,
    EvidenceSubject,
};

use crate::handlers::remember_evidence;
use crate::session::BinarySession;

pub(crate) fn error_result(error: &ToolError) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(error.error_body().to_string())]))
}

pub(crate) fn text_error(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(text)]))
}

fn target_open(session: &BinarySession) -> bool {
    session.active_target.lock().expect("active target").is_some()
}

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    Some(match name {
        n if HOST_GATED_TOOLS.contains(&n) => host_gated(session, n, args),
        "trace_native_ui_action" => trace_native_ui_action(session, name, args).await,
        n if FIRMWARE_TOOLS.contains(&n) => firmware_tool(session, n, args).await,
        _ => return None,
    })
}

fn host_gated(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    if let Err(text) = native::validate(name, args) {
        return text_error(text);
    }
    if !target_open(session) {
        return error_result(&ToolError::NoBinaryOpen);
    }
    let provider_id = composite_provider_id(&[]);
    if std::env::consts::OS == "macos" {
        // Not ported: the Accessibility/LLDB bridges only exist on macOS.
        return error_result(&ToolError::CapabilityUnavailable {
            provider_id,
            operation: name.to_string(),
            reason: "The macOS Accessibility and LLDB bridges are not ported to tracewise yet.".to_string(),
            user_message: None,
        });
    }
    error_result(&native::host_unsupported(name, &provider_id))
}

/// REA's `AnalysisOperationPort` over the sibling tools: every operation the
/// workflow needs is also a tool of this server, answered with Evidence.
#[derive(Clone)]
struct SiblingToolPort {
    session: BinarySession,
}

impl AnalysisPort for SiblingToolPort {
    fn execute(
        &self,
        operation: &str,
        parameters: Value,
    ) -> impl std::future::Future<Output = Result<PortExecution, ToolError>> + Send {
        let session = self.session.clone();
        let operation = operation.to_string();
        async move {
            // The operations the workflow needs live in the native static track
            // (`decode_interface_builder`) and the engines track (everything
            // else). Asking those two directly, not the whole router, avoids an
            // async cycle.
            let dispatch = |operation: String, parameters: Value| {
                let session = session.clone();
                async move {
                    let mut answered = super::native_static::dispatch(&session, &operation, &parameters).await;
                    if answered.is_none() {
                        answered = super::engines::dispatch(&session, &operation, &parameters).await;
                    }
                    answered
                }
            };
            call_sibling_via(dispatch, &operation, parameters).await
        }
    }
}

/// Run one operation through `dispatch` and translate the tool result into the
/// port contract: Evidence becomes a [`PortExecution`], an `isError` result keeps
/// REA's projected body, anything else is a protocol failure.
#[allow(clippy::result_large_err)] // ToolError carries a full REA error payload on the error path only
async fn call_sibling_via<D, F>(
    dispatch: D,
    operation: &str,
    parameters: Value,
) -> Result<PortExecution, ToolError>
where
    D: Fn(String, Value) -> F,
    F: std::future::Future<Output = Option<Result<CallToolResult, McpError>>>,
{
    let Some(outcome) = dispatch(operation.to_string(), parameters).await else {
        return Err(ToolError::CapabilityUnavailable {
            provider_id: composite_provider_id(&[]),
            operation: operation.to_string(),
            reason: "operation is not declared by this provider set".to_string(),
            user_message: None,
        });
    };
    let result = match outcome {
        Ok(result) => result,
        Err(error) => return Err(ToolError::protocol(format!("{operation}: {}", error.message))),
    };
    let text = result.content.first().and_then(|c| c.as_text()).map(|t| t.text.clone()).unwrap_or_default();
    if result.is_error == Some(true) {
        return Err(match serde_json::from_str::<Value>(&text) {
            Ok(body) if body.get("error").map(Value::is_object).unwrap_or(false) => {
                ToolError::Projected { error: body["error"].clone() }
            }
            _ => ToolError::protocol(text),
        });
    }
    let evidence = result
        .structured_content
        .ok_or_else(|| ToolError::protocol(format!("{operation} returned no structured content")))?;
    Ok(PortExecution {
        result: evidence["normalized_result"].clone(),
        provider: evidence["provider"].clone(),
        subject_sha256: evidence["subject"]["digest"]["sha256"].as_str().map(str::to_string),
        analysis_profile_digest: evidence["analysis_profile"]["digest"].as_str().map(str::to_string),
    })
}

/// REA `createWorkflowEvidence`: a derived record of the composed workflow,
/// bound to the active target.
pub(crate) fn workflow_evidence(
    target: EvidenceSubject,
    operation: &str,
    parameters: serde_json::Map<String, Value>,
    result: Value,
) -> Result<tracewise_domain::evidence::Evidence, tracewise_domain::error::DomainError> {
    create_evidence(
        Some(target),
        EvidenceProvider {
            id: "rea-workflow".to_string(),
            name: "REA composed investigation workflow".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: None,
            operation: operation.to_string(),
            parameters: Value::Object(parameters),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: None,
            environment: None,
            limitations: Some(vec!["Derived by an REA composed workflow.".to_string()]),
            locations: Some(Vec::new()),
            evidence_links: Some(Vec::new()),
        },
    )
}

/// `trace_native_ui_action`: UI action to native handler to bounded call references.
async fn trace_native_ui_action(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let input = match native::validate(name, args) {
        Ok(input) => input,
        Err(text) => return text_error(text),
    };
    let target = session.active_target.lock().expect("active target").clone();
    let Some(target) = target else {
        return error_result(&ToolError::NoBinaryOpen);
    };
    let port = SiblingToolPort { session: session.clone() };
    let trace = match ui_trace::trace_native_ui_action(&port, &TraceInput::from_validated(&input)).await {
        Ok(trace) => trace,
        Err(error) => return error_result(&error),
    };
    let evidence = workflow_evidence(target, name, input, trace)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

/// `inspect_firmware_regions` / `extract_firmware`: Binwalk and Unblob supplied
/// by the caller (`REA_BINWALK_COMMAND`, `REA_UNBLOB_COMMAND`).
async fn firmware_tool(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let input = match firmware::validate(name, args) {
        Ok(input) => input,
        Err(text) => return text_error(text),
    };
    let environment: HashMap<String, String> = std::env::vars().collect();
    let execution = match firmware::execute(name, &input, &environment).await {
        Ok(execution) => execution,
        Err(error) => return error_result(&error),
    };
    let subject = EvidenceSubject {
        name: match execution.subject_path.rsplit('/').next() {
            Some(last) if !last.is_empty() => last.to_string(),
            _ => "artifact".to_string(),
        },
        digest: DigestSha256 { sha256: execution.subject_sha256.clone() },
        format: "file".to_string(),
        architecture: None,
        local_path: execution.subject_path.clone(),
    };
    let evidence = create_evidence(
        Some(subject),
        EvidenceProvider {
            id: execution.provider_id.to_string(),
            name: execution.provider_name.to_string(),
            version: Some(execution.provider_version.clone()),
        },
        EvidenceObservation {
            predicate_type: None,
            operation: name.to_string(),
            parameters: Value::Object(input),
            normalized_result: execution.result,
            raw_result: Some(execution.raw_result),
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: None,
            environment: None,
            limitations: Some(execution.limitations),
            locations: Some(vec![EvidenceLocation::FileOffsetRange {
                start: execution.location_start,
                end: execution.location_end,
            }]),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A port that answers like REA's `EnhancedNativeInvestigation` fixture.
    struct Fixture;

    impl AnalysisPort for Fixture {
        fn execute(
            &self,
            operation: &str,
            parameters: Value,
        ) -> impl std::future::Future<Output = Result<PortExecution, ToolError>> + Send {
            let target = "a".repeat(64);
            let evidence = json!([{
                "kind": "interface_builder_resource", "description": "Fixture UI archive",
                "location": { "address": null, "file_offset": null }, "artifact_path": null, "artifact_sha256": null,
            }]);
            let node = |id: &str, kind: &str, name: &str, attributes: Value| {
                json!({ "id": id, "kind": kind, "name": name, "location": null, "attributes": attributes, "evidence": evidence })
            };
            let edge = |id: &str, from: &str, to: &str| {
                json!({ "id": id, "from": from, "to": to, "relation": "target_action", "resolution": "observed",
                        "evidence": evidence, "limitations": [] })
            };
            let outcome = match operation {
                "decode_interface_builder" => Ok(json!({
                    "target_sha256": target,
                    "documents": [],
                    "graph": {
                        "target_sha256": target,
                        "provider": { "id": "fixture", "version": "1", "tool_version": "fixture" },
                        "nodes": [
                            node("action", "action", "buildTapped:", json!({"selector": "buildTapped:"})),
                            node("controller", "view_controller", "BuildViewController", json!({"class_name": "BuildViewController"})),
                            node("selector", "objc_selector", "buildTapped:", json!({})),
                        ],
                        "edges": [edge("action-selector", "action", "selector"), edge("action-controller", "action", "controller")],
                        "coverage": [],
                        "truncated": false,
                    },
                    "limitations": [],
                })),
                "list_names" => Ok(json!([{ "address": "0x1000", "name": "-[BuildViewController buildTapped:]" }])),
                "procedure_callees" => Ok(json!(if parameters["procedure"] == "0x1000" { json!(["0x2000"]) } else { json!([]) })),
                _ => Err(ToolError::CapabilityUnavailable {
                    provider_id: "fixture".to_string(),
                    operation: operation.to_string(),
                    reason: "not in fixture".to_string(),
                    user_message: None,
                }),
            };
            std::future::ready(outcome.map(|result| PortExecution {
                result,
                provider: json!({ "id": "fixture", "name": "Fixture", "version": "1" }),
                subject_sha256: Some(target),
                analysis_profile_digest: None,
            }))
        }
    }

    #[tokio::test]
    async fn workflow_evidence_validates_against_the_catalog_schema() {
        let input = native::validate("trace_native_ui_action", &json!({"action": "buildTapped:"})).unwrap();
        let trace = ui_trace::trace_native_ui_action(&Fixture, &TraceInput::from_validated(&input)).await.unwrap();
        let target = EvidenceSubject {
            name: "Fixture.app".to_string(),
            digest: DigestSha256 { sha256: "a".repeat(64) },
            format: "mach-o".to_string(),
            architecture: Some("arm64".to_string()),
            local_path: "/fixture.app".to_string(),
        };
        let evidence = workflow_evidence(target, "trace_native_ui_action", input, trace).unwrap();
        let structured = serde_json::to_value(&evidence).unwrap();
        let tools: Value = serde_json::from_str(tracewise_contracts::PHASE6_TOOLS_JSON).unwrap();
        let schema = tools["tools"].as_array().unwrap().iter().find(|t| t["name"] == "trace_native_ui_action").unwrap()["outputSchema"].clone();
        let validator = jsonschema::validator_for(&schema).unwrap();
        if let Err(error) = validator.validate(&structured) {
            panic!("outputSchema: {error}");
        }
        assert_eq!(structured["provider"]["id"], "rea-workflow");
        assert_eq!(structured["confidence"], "derived");
        assert_eq!(structured["normalized_result"]["start"], "action");
    }

    type Outcome = Option<Result<CallToolResult, McpError>>;

    /// Scripted sibling dispatch for `call_sibling_via`.
    fn scripted(outcome: fn() -> Outcome) -> impl Fn(String, Value) -> std::future::Ready<Outcome> {
        move |_operation, _parameters| std::future::ready(outcome())
    }

    #[tokio::test]
    async fn sibling_tool_errors_pass_through_call_sibling() {
        let projected = scripted(|| {
            Some(Ok(CallToolResult::error(vec![Content::text(
                json!({"error": {"code": "provider_unavailable", "message": "no engine", "details": {"operation": "list_names"}}}).to_string(),
            )])))
        });
        let error = call_sibling_via(projected, "list_names", json!({})).await.unwrap_err();
        assert_eq!(
            error.project(),
            json!({"code": "provider_unavailable", "message": "no engine", "details": {"operation": "list_names"}}),
            "an isError result keeps its projected body verbatim"
        );
        assert_eq!(error.user_message_text(), "no engine");

        let plain = scripted(|| Some(Ok(CallToolResult::error(vec![Content::text("Input validation error: nope".to_string())]))));
        let error = call_sibling_via(plain, "list_names", json!({})).await.unwrap_err();
        assert_eq!(error.project()["code"], "unreadable_output", "plain text is a protocol failure, not a projected error");

        let missing = scripted(|| None);
        let error = call_sibling_via(missing, "list_names", json!({})).await.unwrap_err();
        assert_eq!(error.project()["code"], "capability_unavailable");

        let success = scripted(|| {
            Some(Ok(CallToolResult::structured(json!({
                "normalized_result": ["0x1"], "provider": {"id": "p", "name": "P", "version": "1"},
                "subject": {"digest": {"sha256": "a".repeat(64)}}, "analysis_profile": null,
            }))))
        });
        let execution = call_sibling_via(success, "list_names", json!({})).await.unwrap();
        assert_eq!(execution.result, json!(["0x1"]));
        assert_eq!(execution.subject_sha256.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(execution.provider["id"], "p");
    }

    #[tokio::test]
    async fn a_sibling_that_fails_at_the_protocol_level_is_a_protocol_failure() {
        // No special answers for any message: whatever the sibling reports is reported as is.
        let broken = scripted(|| Some(Err(McpError::invalid_request("boom".to_string(), None))));
        for operation in ["list_names", "inspect_native_dispatch_metadata"] {
            let error = call_sibling_via(&broken, operation, json!({})).await.unwrap_err();
            assert_eq!(error.project()["code"], "unreadable_output", "{operation}");
        }
    }
}
