use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::bundle::EvidenceBundle;
use crate::canonical::canonical_sha256;
use crate::error::{BundleError, DomainError};
use crate::unknown::ResidualUnknown;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPair {
    pub left_evidence_id: String,
    pub right_evidence_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComparisonStatus {
    Unchanged,
    Changed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleChangeClassification {
    Added,
    Removed,
    Changed,
    Unknown,
    HistoryAdvanced,
    HistoryDiverged,
}

impl BundleChangeClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
            Self::Unknown => "unknown",
            Self::HistoryAdvanced => "history_advanced",
            Self::HistoryDiverged => "history_diverged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleChangeConclusionKind {
    ObservedChange,
    Contradiction,
    UnresolvedBranch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleChange {
    pub entity: String,
    pub key: String,
    pub classification: BundleChangeClassification,
    pub conclusion_kind: BundleChangeConclusionKind,
    pub left_evidence_ids: Vec<String>,
    pub right_evidence_ids: Vec<String>,
    pub left_digest: Option<String>,
    pub right_digest: Option<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleComparisonSummary {
    pub records_unchanged: usize,
    pub records_added: usize,
    pub records_removed: usize,
    pub records_changed: usize,
    pub unknowns_unchanged: usize,
    pub unknowns_added: usize,
    pub unknowns_removed: usize,
    pub unknowns_advanced: usize,
    pub unknowns_diverged: usize,
    pub unresolved: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleComparisonResult {
    pub status: ComparisonStatus,
    pub left_bundle_sha256: String,
    pub right_bundle_sha256: String,
    pub summary: BundleComparisonSummary,
    pub changes: Vec<BundleChange>,
    pub limitations: Vec<String>,
}

pub fn compare_bundles(
    left: &EvidenceBundle,
    right: &EvidenceBundle,
    record_pairs: &[RecordPair],
) -> Result<BundleComparisonResult, DomainError> {
    let left_digest = canonical_sha256(left)?;
    let right_digest = canonical_sha256(right)?;

    let record_res = compare_records(left, right, record_pairs)?;
    let unknown_res = compare_unknowns(left, right);

    let mut changes = record_res.changes;
    changes.extend(unknown_res.changes);
    changes.sort_by(|a, b| {
        (
            a.entity.as_str(),
            a.key.as_str(),
            a.classification.as_str(),
            a.left_digest.as_deref().unwrap_or(""),
            a.right_digest.as_deref().unwrap_or(""),
        )
            .cmp(&(
                b.entity.as_str(),
                b.key.as_str(),
                b.classification.as_str(),
                b.left_digest.as_deref().unwrap_or(""),
                b.right_digest.as_deref().unwrap_or(""),
            ))
    });

    let unresolved = changes
        .iter()
        .filter(|c| c.conclusion_kind != BundleChangeConclusionKind::ObservedChange)
        .count();

    let status = if left_digest == right_digest && changes.is_empty() {
        ComparisonStatus::Unchanged
    } else if unresolved > 0 {
        ComparisonStatus::Unknown
    } else {
        ComparisonStatus::Changed
    };

    let limitations = if changes.iter().any(|c| !c.limitations.is_empty()) {
        vec!["EvidenceBundle has no inventory completeness marker; one-sided membership remains unknown.".to_string()]
    } else {
        Vec::new()
    };

    Ok(BundleComparisonResult {
        status,
        left_bundle_sha256: left_digest,
        right_bundle_sha256: right_digest,
        summary: BundleComparisonSummary {
            records_unchanged: record_res.unchanged,
            records_added: 0,
            records_removed: 0,
            records_changed: record_res.changed,
            unknowns_unchanged: unknown_res.unchanged,
            unknowns_added: 0,
            unknowns_removed: 0,
            unknowns_advanced: unknown_res.advanced,
            unknowns_diverged: unknown_res.diverged,
            unresolved,
        },
        changes,
        limitations,
    })
}

struct RecordComparisonOutput {
    changes: Vec<BundleChange>,
    unchanged: usize,
    changed: usize,
}

fn compare_records(
    left: &EvidenceBundle,
    right: &EvidenceBundle,
    pairs: &[RecordPair],
) -> Result<RecordComparisonOutput, DomainError> {
    let left_ids: BTreeSet<&str> = left.records.iter().map(|r| r.evidence_id.as_str()).collect();
    let right_ids: BTreeSet<&str> = right.records.iter().map(|r| r.evidence_id.as_str()).collect();

    let mut paired_left = BTreeSet::new();
    let mut paired_right = BTreeSet::new();
    let mut changes = Vec::new();
    let mut changed = 0;

    for pair in pairs {
        if !left_ids.contains(pair.left_evidence_id.as_str()) {
            return Err(BundleError::MissingPairEvidence(pair.left_evidence_id.clone()).into());
        }
        if !right_ids.contains(pair.right_evidence_id.as_str()) {
            return Err(BundleError::MissingPairEvidence(pair.right_evidence_id.clone()).into());
        }
        if !paired_left.insert(pair.left_evidence_id.as_str())
            || !paired_right.insert(pair.right_evidence_id.as_str())
        {
            return Err(BundleError::PairsNotOneToOne.into());
        }

        if pair.left_evidence_id != pair.right_evidence_id {
            changed += 1;
            changes.push(BundleChange {
                entity: "evidence".to_string(),
                key: format!("pair:{}:{}", pair.left_evidence_id, pair.right_evidence_id),
                classification: BundleChangeClassification::Changed,
                conclusion_kind: BundleChangeConclusionKind::ObservedChange,
                left_evidence_ids: vec![pair.left_evidence_id.clone()],
                right_evidence_ids: vec![pair.right_evidence_id.clone()],
                left_digest: Some(pair.left_evidence_id[3..].to_string()),
                right_digest: Some(pair.right_evidence_id[3..].to_string()),
                limitations: Vec::new(),
            });
        }
    }

    let common: Vec<&str> = left_ids
        .iter()
        .copied()
        .filter(|id| right_ids.contains(id) && !paired_left.contains(id) && !paired_right.contains(id))
        .collect();

    let removed: Vec<&str> = left_ids
        .iter()
        .copied()
        .filter(|id| !paired_left.contains(id) && (!right_ids.contains(id) || paired_right.contains(id)))
        .collect();

    let added: Vec<&str> = right_ids
        .iter()
        .copied()
        .filter(|id| !paired_right.contains(id) && (!left_ids.contains(id) || paired_left.contains(id)))
        .collect();

    for id in removed {
        changes.push(BundleChange {
            entity: "evidence".to_string(),
            key: id.to_string(),
            classification: BundleChangeClassification::Unknown,
            conclusion_kind: BundleChangeConclusionKind::UnresolvedBranch,
            left_evidence_ids: vec![id.to_string()],
            right_evidence_ids: Vec::new(),
            left_digest: Some(id[3..].to_string()),
            right_digest: None,
            limitations: vec!["EvidenceBundle has no inventory completeness marker; one-sided membership may reflect incomplete capture.".to_string()],
        });
    }

    for id in added {
        changes.push(BundleChange {
            entity: "evidence".to_string(),
            key: id.to_string(),
            classification: BundleChangeClassification::Unknown,
            conclusion_kind: BundleChangeConclusionKind::UnresolvedBranch,
            left_evidence_ids: Vec::new(),
            right_evidence_ids: vec![id.to_string()],
            left_digest: None,
            right_digest: Some(id[3..].to_string()),
            limitations: vec!["EvidenceBundle has no inventory completeness marker; one-sided membership may reflect incomplete capture.".to_string()],
        });
    }

    let unchanged = common.len() + pairs.len() - changed;

    Ok(RecordComparisonOutput {
        changes,
        unchanged,
        changed,
    })
}

struct UnknownComparisonOutput {
    changes: Vec<BundleChange>,
    unchanged: usize,
    advanced: usize,
    diverged: usize,
}

fn compare_unknowns(left: &EvidenceBundle, right: &EvidenceBundle) -> UnknownComparisonOutput {
    let left_histories = group_histories(&left.unknowns);
    let right_histories = group_histories(&right.unknowns);

    let mut all_ids = BTreeSet::new();
    all_ids.extend(left_histories.keys().cloned());
    all_ids.extend(right_histories.keys().cloned());

    let mut changes = Vec::new();
    let mut unchanged = 0;
    let mut advanced = 0;
    let mut diverged = 0;

    for id in all_ids {
        let left_history = left_histories.get(&id);
        let right_history = right_histories.get(&id);

        match (left_history, right_history) {
            (Some(lh), Some(rh)) => {
                let left_digests: Vec<&str> = lh.iter().map(|u| u.revision_digest.as_str()).collect();
                let right_digests: Vec<&str> = rh.iter().map(|u| u.revision_digest.as_str()).collect();

                if left_digests == right_digests {
                    unchanged += 1;
                } else if is_prefix(&left_digests, &right_digests) || is_prefix(&right_digests, &left_digests) {
                    advanced += 1;
                    changes.push(unknown_change(
                        &id,
                        BundleChangeClassification::HistoryAdvanced,
                        Some(lh),
                        Some(rh),
                    ));
                } else {
                    diverged += 1;
                    changes.push(unknown_change(
                        &id,
                        BundleChangeClassification::HistoryDiverged,
                        Some(lh),
                        Some(rh),
                    ));
                }
            }
            (Some(lh), None) => {
                changes.push(unknown_change(
                    &id,
                    BundleChangeClassification::Unknown,
                    Some(lh),
                    None,
                ));
            }
            (None, Some(rh)) => {
                changes.push(unknown_change(
                    &id,
                    BundleChangeClassification::Unknown,
                    None,
                    Some(rh),
                ));
            }
            (None, None) => {}
        }
    }

    UnknownComparisonOutput {
        changes,
        unchanged,
        advanced,
        diverged,
    }
}

fn group_histories(unknowns: &[ResidualUnknown]) -> BTreeMap<String, Vec<&ResidualUnknown>> {
    let mut map: BTreeMap<String, Vec<&ResidualUnknown>> = BTreeMap::new();
    for u in unknowns {
        map.entry(u.unknown_id.clone()).or_default().push(u);
    }
    for history in map.values_mut() {
        history.sort_by_key(|u| u.revision);
    }
    map
}

fn is_prefix(shorter: &[&str], longer: &[&str]) -> bool {
    shorter.len() < longer.len() && longer.starts_with(shorter)
}

fn history_evidence_ids(history: &[&ResidualUnknown]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for u in history {
        set.extend(u.supporting_evidence_ids.iter().cloned());
        set.extend(u.contradicting_evidence_ids.iter().cloned());
        set.extend(u.mutation_evidence_ids.iter().cloned());
        if let Some(ref res) = u.resolution {
            set.extend(res.evidence_ids.iter().cloned());
        }
    }
    set.into_iter().collect()
}

fn unknown_change(
    id: &str,
    classification: BundleChangeClassification,
    left: Option<&Vec<&ResidualUnknown>>,
    right: Option<&Vec<&ResidualUnknown>>,
) -> BundleChange {
    let conclusion_kind = match classification {
        BundleChangeClassification::HistoryDiverged => BundleChangeConclusionKind::Contradiction,
        BundleChangeClassification::HistoryAdvanced => BundleChangeConclusionKind::ObservedChange,
        _ => BundleChangeConclusionKind::UnresolvedBranch,
    };

    let limitations = if left.is_none() || right.is_none() {
        vec!["EvidenceBundle has no inventory completeness marker; one-sided history membership remains unknown.".to_string()]
    } else {
        Vec::new()
    };

    BundleChange {
        entity: "residual_unknown".to_string(),
        key: id.to_string(),
        classification,
        conclusion_kind,
        left_evidence_ids: left.map(|h| history_evidence_ids(h)).unwrap_or_default(),
        right_evidence_ids: right.map(|h| history_evidence_ids(h)).unwrap_or_default(),
        left_digest: left.and_then(|h| h.last().map(|u| u.revision_digest.clone())),
        right_digest: right.and_then(|h| h.last().map(|u| u.revision_digest.clone())),
        limitations,
    }
}
