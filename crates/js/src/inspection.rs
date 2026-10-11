use crate::digest::digest_canonical_value;
use crate::types::ArtifactInventoryResult;
use crate::unicode::unique_sorted;
use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;
use tracewise_domain::error::DomainError;

pub fn create_artifact_inspection(inventory_evidence: &Evidence) -> Result<Value, DomainError> {
    if inventory_evidence.operation != "inventory_artifact" {
        return Err(DomainError::Canonicalization(
            "Artifact inspection substep requires inventory_artifact Evidence".to_string(),
        ));
    }
    let inventory: ArtifactInventoryResult =
        serde_json::from_value(inventory_evidence.normalized_result.clone())?;
    let evidence_id = inventory_evidence.evidence_id.clone();
    let observations = all_observations(&inventory, &evidence_id)?;
    let hypotheses = all_hypotheses(&inventory, &evidence_id)?;
    let next_probes = probes_for(&inventory);
    let branches = all_unexplored_branches(&inventory, &evidence_id, &next_probes)?;
    let contradictions = contradictions_list(&inventory, &evidence_id)?;
    let mut lim = inventory.limitations.clone();
    lim.push(
        "Inspection derives bounded static hypotheses and next probes; it does not execute the artifact or claim format-specific semantics.".to_string(),
    );
    let limitations = unique_sorted(&lim);
    let substep_semantic = json!({
        "operation": "inventory_artifact",
        "evidence_id": evidence_id,
    });
    let substep_id = format!(
        "ais_{}",
        digest_canonical_value(&substep_semantic)?
    );
    let inventory_ev_val = serde_json::to_value(inventory_evidence)?;
    let semantic_without_id = json!({
        "subject": {
            "manifest_id": inventory.manifest.manifest_id,
            "root_artifact_id": inventory.manifest.root_artifact_id,
            "root_sha256": inventory.manifest.root_sha256,
            "root_format": inventory.manifest.root_format,
        },
        "substeps": [{
            "substep_id": substep_id,
            "operation": "inventory_artifact",
            "status": "completed",
            "evidence_id": evidence_id,
            "evidence": inventory_ev_val,
        }],
        "observations": observations,
        "hypotheses": hypotheses,
        "contradictions": contradictions,
        "unexplored_branches": branches,
        "next_probes": next_probes,
        "coverage": {
            "status": "complete-within-substeps",
            "substeps_completed": 1,
            "observations_retained": observations.len(),
            "observations_omitted": 0,
            "hypotheses_retained": hypotheses.len(),
            "hypotheses_omitted": 0,
            "unexplored_branches_retained": branches.len(),
            "unexplored_branches_omitted": 0,
            "next_probes_retained": next_probes.len(),
            "next_probes_omitted": 0,
        },
        "evidence_links": [evidence_id],
        "limitations": limitations,
    });
    let inspection_id = format!(
        "ai_{}",
        digest_canonical_value(&semantic_without_id)?
    );
    let mut result = semantic_without_id.as_object().unwrap().clone();
    result.insert("inspection_id".to_string(), Value::String(inspection_id));
    Ok(Value::Object(result))
}

fn all_observations(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
) -> Result<Vec<Value>, DomainError> {
    let mut out = vec![observation(
        "root-manifest",
        &inventory.manifest.root_artifact_id,
        &inventory.manifest,
        evidence_id,
    )?];
    for c in &inventory.integrity_contradictions {
        out.push(observation(
            "integrity",
            &c.contradiction_id,
            c,
            evidence_id,
        )?);
    }
    Ok(out)
}

fn observation(
    kind: &str,
    subject: &str,
    value: &impl serde::Serialize,
    evidence_id: &str,
) -> Result<Value, DomainError> {
    let semantic = json!({
        "kind": kind,
        "subject": subject,
        "value": value,
        "evidence_id": evidence_id,
    });
    Ok(json!({
        "observation_id": format!("aio_{}", digest_canonical_value(&semantic)?),
        "kind": kind,
        "subject": subject,
        "value": value,
        "evidence_id": evidence_id,
    }))
}

fn all_hypotheses(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
) -> Result<Vec<Value>, DomainError> {
    let statements: Vec<&str> = if inventory.manifest.root_format == "pe" {
        vec!["The PE artifact may contain managed CLI metadata or native code; inventory bytes alone do not distinguish them."]
    } else if inventory.manifest.root_format == "asar"
        || inventory.manifest.root_format == "javascript-bundle"
    {
        vec!["The artifact may contain a recoverable JavaScript application graph."]
    } else {
        vec![]
    };
    let mut out = Vec::new();
    for statement in statements {
        let semantic = json!({
            "statement": statement,
            "confidence": "low",
            "basis_evidence_ids": [evidence_id],
            "limitation": "Format classification proposes a bounded follow-up; it is not semantic proof.",
        });
        out.push(json!({
            "hypothesis_id": format!("aih_{}", digest_canonical_value(&semantic)?),
            "statement": statement,
            "confidence": "low",
            "basis_evidence_ids": [evidence_id],
            "limitation": "Format classification proposes a bounded follow-up; it is not semantic proof.",
        }));
    }
    Ok(out)
}

fn contradictions_list(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
) -> Result<Vec<Value>, DomainError> {
    let mut out = Vec::new();
    for value in &inventory.integrity_contradictions {
        let semantic = json!({
            "statement": format!("Declared integrity for {} contradicts observed bytes.", value.logical_path),
            "occurrence_id": value.occurrence_id,
            "declared_sha256": value.declared_sha256,
            "observed_sha256": value.observed_sha256,
            "evidence_id": evidence_id,
        });
        out.push(json!({
            "contradiction_id": format!("aic_{}", digest_canonical_value(&semantic)?),
            "statement": semantic["statement"],
            "occurrence_id": value.occurrence_id,
            "declared_sha256": value.declared_sha256,
            "observed_sha256": value.observed_sha256,
            "evidence_id": evidence_id,
        }));
    }
    Ok(out)
}

fn probes_for(inventory: &ArtifactInventoryResult) -> Vec<Value> {
    let format = &inventory.manifest.root_format;
    if ["asar", "javascript-bundle", "directory"].contains(&format.as_str()) {
        return vec![json!({
            "operation": "analyze_javascript_application",
            "rationale": "Recover bounded JavaScript modules, source maps, Electron boundaries, and application relationships.",
            "authority": "ast-static-analysis",
        })];
    }
    if format == "pe" {
        return vec![
            json!({
                "operation": "inspect_managed_artifact",
                "rationale": "Check execution-free CLI metadata before choosing a deep native provider.",
                "authority": "managed-static-analysis",
            }),
            json!({
                "operation": "open_binary",
                "rationale": "Open as native code only when managed inspection reports a native or mixed boundary.",
                "authority": "native-analysis-provider",
            }),
        ];
    }
    if ["mach-o", "mach-o-universal", "elf"].contains(&format.as_str()) {
        return vec![json!({
            "operation": "open_binary",
            "rationale": "Bind one deep native provider before function-level analysis.",
            "authority": "native-analysis-provider",
        })];
    }
    if format == "plist" {
        return vec![json!({
            "operation": "inspect_plist",
            "rationale": "Parse property-list values without executing the artifact.",
            "authority": "artifact-bytes",
        })];
    }
    vec![]
}

fn all_unexplored_branches(
    inventory: &ArtifactInventoryResult,
    evidence_id: &str,
    next_probes: &[Value],
) -> Result<Vec<Value>, DomainError> {
    let mut branches = Vec::new();
    for probe in next_probes {
        branches.push(branch(
            "format-specific-analysis-required",
            format!(
                "{} was not run by provider-neutral artifact inspection.",
                probe["operation"].as_str().unwrap_or("")
            ),
            Some(probe.clone()),
            evidence_id,
        )?);
    }
    if inventory.manifest.root_format == "unknown" {
        branches.push(branch(
            "unknown-format",
            "Artifact bytes did not match an admitted format classifier.".to_string(),
            None,
            evidence_id,
        )?);
    }
    Ok(branches)
}

fn branch(
    reason: &str,
    detail: String,
    next_probe: Option<Value>,
    evidence_id: &str,
) -> Result<Value, DomainError> {
    let semantic = json!({
        "reason": reason,
        "detail": detail,
        "next_probe": next_probe,
        "evidence_id": evidence_id,
    });
    Ok(json!({
        "branch_id": format!("aib_{}", digest_canonical_value(&semantic)?),
        "reason": reason,
        "detail": detail,
        "next_probe": next_probe,
        "evidence_id": evidence_id,
    }))
}
