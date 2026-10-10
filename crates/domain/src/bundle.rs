use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json;
use crate::error::{BundleError, DomainError};
use crate::evidence::{DigestSha256, Evidence, EvidenceAuthority, EvidenceProvider, ExecutionEnvironment};
use crate::unknown::ResidualUnknown;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub digest: DigestSha256,
    pub format: String,
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioManifest {
    pub evidence_id: String,
    pub operation: String,
    pub authority: EvidenceAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureManifest {
    pub evidence_id: String,
    pub predicate_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub artifacts: Vec<ArtifactManifest>,
    pub providers: Vec<EvidenceProvider>,
    pub environments: Vec<ExecutionEnvironment>,
    pub scenarios: Vec<ScenarioManifest>,
    pub captures: Vec<CaptureManifest>,
    pub unknowns: Vec<ResidualUnknown>,
    pub records: Vec<Evidence>,
}

fn unique_sorted<T: Serialize + Clone>(items: &[T]) -> Vec<T> {
    let mut map: BTreeMap<String, T> = BTreeMap::new();
    for item in items {
        if let Ok(key) = serde_json::to_string(item) {
            map.entry(key).or_insert_with(|| item.clone());
        }
    }
    map.into_values().collect()
}

pub fn create_evidence_bundle(
    records: &[Evidence],
    unknowns: &[ResidualUnknown],
) -> EvidenceBundle {
    let mut sorted_records = records.to_vec();
    sorted_records.sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));

    let artifacts: Vec<ArtifactManifest> = sorted_records
        .iter()
        .filter_map(|ev| {
            ev.subject.as_ref().map(|s| ArtifactManifest {
                digest: s.digest.clone(),
                format: s.format.clone(),
                architecture: s.architecture.clone(),
            })
        })
        .collect();
    let artifacts = unique_sorted(&artifacts);

    let providers: Vec<EvidenceProvider> = sorted_records
        .iter()
        .map(|ev| ev.provider.clone())
        .collect();
    let providers = unique_sorted(&providers);

    let environments: Vec<ExecutionEnvironment> = sorted_records
        .iter()
        .filter_map(|ev| ev.environment.clone())
        .collect();
    let environments = unique_sorted(&environments);

    let scenarios: Vec<ScenarioManifest> = sorted_records
        .iter()
        .filter_map(|ev| {
            if ev.authority == EvidenceAuthority::ControlledReplay {
                Some(ScenarioManifest {
                    evidence_id: ev.evidence_id.clone(),
                    operation: ev.operation.clone(),
                    authority: ev.authority,
                })
            } else {
                None
            }
        })
        .collect();

    let captures: Vec<CaptureManifest> = sorted_records
        .iter()
        .filter_map(|ev| {
            if ev.predicate_type == "rea.process-capture" {
                Some(CaptureManifest {
                    evidence_id: ev.evidence_id.clone(),
                    predicate_type: ev.predicate_type.clone(),
                })
            } else {
                None
            }
        })
        .collect();

    let mut sorted_unknowns = unknowns.to_vec();
    sorted_unknowns.sort_by(|a, b| {
        a.unknown_id
            .cmp(&b.unknown_id)
            .then(a.revision.cmp(&b.revision))
    });

    EvidenceBundle {
        artifacts,
        providers,
        environments,
        scenarios,
        captures,
        unknowns: sorted_unknowns,
        records: sorted_records,
    }
}

pub fn parse_evidence_bundle(input: &str) -> Result<EvidenceBundle, DomainError> {
    let bundle: EvidenceBundle = serde_json::from_str(input)?;

    // 1. Verify all evidence records
    let mut record_ids = BTreeSet::new();
    let mut evidence_by_id = BTreeMap::new();
    for record in &bundle.records {
        record.verify()?;
        if !record_ids.insert(record.evidence_id.clone()) {
            return Err(BundleError::DuplicateRecordId(record.evidence_id.clone()).into());
        }
        evidence_by_id.insert(record.evidence_id.clone(), record);
    }

    // 2. Validate unknown histories
    let mut histories: BTreeMap<String, Vec<&ResidualUnknown>> = BTreeMap::new();
    for unknown in &bundle.unknowns {
        unknown.validate_invariants()?;
        histories
            .entry(unknown.unknown_id.clone())
            .or_default()
            .push(unknown);
    }

    let mut unknown_heads = BTreeMap::new();
    for (id, mut history) in histories {
        history.sort_by_key(|u| u.revision);
        for (index, revision) in history.iter().enumerate() {
            let expected_rev = (index + 1) as u64;
            if revision.revision != expected_rev {
                return Err(BundleError::RevisionHistoryGap(id.clone()).into());
            }
            if index > 0 {
                let prev = history[index - 1];
                if revision.previous_revision_digest.as_deref() != Some(&prev.revision_digest) {
                    return Err(BundleError::BrokenRevisionChain(id.clone()).into());
                }
            }
        }
        if let Some(last) = history.last() {
            unknown_heads.insert(id.clone(), *last);
        }
    }

    // 3. Verify references and resolution qualification
    for unknown in &bundle.unknowns {
        // Referenced evidence IDs
        let mut refs = Vec::new();
        refs.extend(unknown.supporting_evidence_ids.iter());
        refs.extend(unknown.contradicting_evidence_ids.iter());
        refs.extend(unknown.mutation_evidence_ids.iter());
        if let Some(ref res) = unknown.resolution {
            refs.extend(res.evidence_ids.iter());
        }
        for ev_id in refs {
            if !evidence_by_id.contains_key(ev_id) {
                return Err(BundleError::MissingEvidence(ev_id.clone()).into());
            }
        }

        // Referenced unknown IDs
        for rel in &unknown.relationships {
            if !unknown_heads.contains_key(&rel.unknown_id) {
                return Err(BundleError::MissingUnknown(rel.unknown_id.clone()).into());
            }
        }

        // Verified resolution check
        if let Some(ref res) = unknown.resolution {
            if res.disposition == crate::unknown::ResolutionDisposition::Verified {
                if !unknown.contradicting_evidence_ids.is_empty() {
                    return Err(BundleError::RetainsContradictingEvidence(
                        unknown.unknown_id.clone(),
                    )
                    .into());
                }
                let mut qualifies = false;
                for ev_id in &res.evidence_ids {
                    if let Some(ev) = evidence_by_id.get(ev_id) {
                        if unknown.supporting_evidence_ids.contains(ev_id)
                            && ev.predicate_type != "rea.residual-unknown-mutation"
                            && evidence_qualifies(unknown, ev)
                        {
                            qualifies = true;
                            break;
                        }
                    }
                }
                if !qualifies {
                    return Err(BundleError::NoQualifyingResolutionEvidence(
                        unknown.unknown_id.clone(),
                    )
                    .into());
                }
            }
        }
    }

    // 4. Reject dependency cycles in heads
    reject_dependency_cycles(&unknown_heads)?;

    // 5. Verify canonical manifest arrays
    let canonical = create_evidence_bundle(&bundle.records, &bundle.unknowns);
    if canonical_json(&bundle)? != canonical_json(&canonical)? {
        return Err(BundleError::ManifestsNotCanonical.into());
    }

    Ok(bundle)
}

fn evidence_qualifies(unknown: &ResidualUnknown, evidence: &Evidence) -> bool {
    if let Some(req_auth) = unknown.required_authority {
        if evidence.authority != req_auth {
            return false;
        }
    }
    if evidence.confidence < unknown.required_confidence {
        return false;
    }
    if let Some(ref req_env) = unknown.required_environment {
        let Some(ref ev_env) = evidence.environment else {
            return false;
        };
        if let Some(ref id) = req_env.id {
            if &ev_env.id != id {
                return false;
            }
        }
        if let Some(ref plat) = req_env.platform {
            if &ev_env.platform != plat {
                return false;
            }
        }
        if let Some(ref arch) = req_env.architecture {
            if &ev_env.architecture != arch {
                return false;
            }
        }
        if let Some(iso) = req_env.isolation {
            if ev_env.isolation != iso {
                return false;
            }
        }
    }
    true
}

fn reject_dependency_cycles(heads: &BTreeMap<String, &ResidualUnknown>) -> Result<(), BundleError> {
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();

    fn dfs<'a>(
        node: &'a str,
        heads: &BTreeMap<String, &'a ResidualUnknown>,
        visited: &mut BTreeSet<&'a str>,
        active: &mut BTreeSet<&'a str>,
    ) -> Result<(), BundleError> {
        visited.insert(node);
        active.insert(node);

        if let Some(unknown) = heads.get(node) {
            for rel in &unknown.relationships {
                if rel.rel_type == crate::unknown::RelationshipType::DependsOn {
                    let dep = rel.unknown_id.as_str();
                    if active.contains(dep) {
                        return Err(BundleError::CycleDetected);
                    }
                    if !visited.contains(dep) {
                        dfs(dep, heads, visited, active)?;
                    }
                }
            }
        }

        active.remove(node);
        Ok(())
    }

    for id in heads.keys() {
        if !visited.contains(id.as_str()) {
            dfs(id.as_str(), heads, &mut visited, &mut active)?;
        }
    }

    Ok(())
}
