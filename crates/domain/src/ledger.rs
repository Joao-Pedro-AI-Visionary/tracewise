use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bundle::{create_evidence_bundle, EvidenceBundle};
use crate::error::{DomainError, EvidenceError, UnknownError};
use crate::evidence::Evidence;
use crate::unknown::{
    create_residual_unknown, update_residual_unknown, RecordUnknownInput, ResidualUnknown,
    ResolutionDisposition, UnknownSeverity, UnknownStatus, UpdateUnknownInput,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    Added,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDelta {
    pub records_added: usize,
    pub unknowns_added: usize,
    pub changed: bool,
    pub metadata_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnknownResolutionVerification {
    pub valid: bool,
    pub truth_verified: bool,
    pub unknown: ResidualUnknown,
}

#[derive(Debug, Default, Clone)]
pub struct EvidenceLedger {
    records: BTreeMap<String, Evidence>,
    unknown_revisions: BTreeMap<String, ResidualUnknown>,
    unknown_heads: BTreeMap<String, ResidualUnknown>,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, evidence: Evidence) -> Result<RecordResult, EvidenceError> {
        evidence.verify()?;
        if let Some(existing) = self.records.get(&evidence.evidence_id) {
            if existing.records_agree(&evidence) {
                return Ok(RecordResult::Duplicate);
            } else {
                return Err(EvidenceError::TamperedId {
                    expected: existing.evidence_id.clone(),
                    actual: evidence.evidence_id,
                });
            }
        }
        self.records.insert(evidence.evidence_id.clone(), evidence);
        Ok(RecordResult::Added)
    }

    pub fn import(&mut self, bundle: &EvidenceBundle) -> Result<ImportDelta, DomainError> {
        let mut pending_records = self.records.clone();
        let mut metadata_changed = false;
        let mut records_added = 0;

        for record in &bundle.records {
            record.verify()?;
            if let Some(existing) = pending_records.get(&record.evidence_id) {
                if !existing.records_agree(record) {
                    return Err(EvidenceError::TamperedId {
                        expected: existing.evidence_id.clone(),
                        actual: record.evidence_id.clone(),
                    }
                    .into());
                }
                if crate::canonical::canonical_json(existing)? != crate::canonical::canonical_json(record)? {
                    metadata_changed = true;
                    pending_records.insert(record.evidence_id.clone(), record.clone());
                }
            } else {
                pending_records.insert(record.evidence_id.clone(), record.clone());
                records_added += 1;
            }
        }

        let mut pending_unknowns = self.unknown_revisions.clone();
        let mut unknowns_added = 0;

        for unknown in &bundle.unknowns {
            unknown.validate_invariants()?;
            let key = format!("{}:{}", unknown.unknown_id, unknown.revision);
            if let Some(existing) = pending_unknowns.get(&key) {
                if existing.revision_digest != unknown.revision_digest {
                    return Err(UnknownError::RevisionDigestMismatch.into());
                }
            } else {
                pending_unknowns.insert(key, unknown.clone());
                unknowns_added += 1;
            }
        }

        // Validate complete bundle
        let candidate_records: Vec<Evidence> = pending_records.values().cloned().collect();
        let candidate_unknowns: Vec<ResidualUnknown> = pending_unknowns.values().cloned().collect();
        let candidate_bundle = create_evidence_bundle(&candidate_records, &candidate_unknowns);
        let candidate_json = crate::canonical::canonical_json(&candidate_bundle)?;
        let _ = crate::bundle::parse_evidence_bundle(&candidate_json)?;

        // Commit
        self.records = pending_records;
        self.unknown_revisions = pending_unknowns;
        self.unknown_heads.clear();
        for unknown in self.unknown_revisions.values() {
            let head = self.unknown_heads.get(&unknown.unknown_id);
            if head.is_none() || head.unwrap().revision < unknown.revision {
                self.unknown_heads.insert(unknown.unknown_id.clone(), unknown.clone());
            }
        }

        Ok(ImportDelta {
            records_added,
            unknowns_added,
            changed: records_added > 0 || unknowns_added > 0 || metadata_changed,
            metadata_changed,
        })
    }

    pub fn export(&self) -> EvidenceBundle {
        let records: Vec<Evidence> = self.records.values().cloned().collect();
        let unknowns: Vec<ResidualUnknown> = self.unknown_revisions.values().cloned().collect();
        create_evidence_bundle(&records, &unknowns)
    }

    pub fn record_unknown(
        &mut self,
        input: &RecordUnknownInput,
        mutation_evidence: Evidence,
    ) -> Result<ResidualUnknown, DomainError> {
        mutation_evidence.verify()?;
        let scope_digest = mutation_evidence
            .subject
            .as_ref()
            .map(|s| s.digest.sha256.clone());
        let unknown = create_residual_unknown(input, &mutation_evidence.evidence_id, scope_digest)?;

        if self.unknown_heads.contains_key(&unknown.unknown_id) {
            return Err(UnknownError::AlreadyExists(unknown.unknown_id).into());
        }

        self.records
            .insert(mutation_evidence.evidence_id.clone(), mutation_evidence);
        let key = format!("{}:{}", unknown.unknown_id, unknown.revision);
        self.unknown_revisions.insert(key, unknown.clone());
        self.unknown_heads
            .insert(unknown.unknown_id.clone(), unknown.clone());

        Ok(unknown)
    }

    pub fn update_unknown(
        &mut self,
        input: &UpdateUnknownInput,
        mutation_evidence: Evidence,
    ) -> Result<ResidualUnknown, DomainError> {
        mutation_evidence.verify()?;
        let current = self
            .unknown_heads
            .get(&input.unknown_id)
            .ok_or_else(|| UnknownError::NotFound(input.unknown_id.clone()))?;

        let updated = update_residual_unknown(current, input, &mutation_evidence.evidence_id)?;

        self.records
            .insert(mutation_evidence.evidence_id.clone(), mutation_evidence);
        let key = format!("{}:{}", updated.unknown_id, updated.revision);
        self.unknown_revisions.insert(key, updated.clone());
        self.unknown_heads
            .insert(updated.unknown_id.clone(), updated.clone());

        Ok(updated)
    }

    pub fn list_unknowns(
        &self,
        status: Option<UnknownStatus>,
        severity: Option<UnknownSeverity>,
        domain: Option<&str>,
    ) -> Vec<ResidualUnknown> {
        let mut list: Vec<ResidualUnknown> = self
            .unknown_heads
            .values()
            .filter(|u| {
                if let Some(st) = status {
                    if u.status != st {
                        return false;
                    }
                }
                if let Some(sev) = severity {
                    if u.severity != sev {
                        return false;
                    }
                }
                if let Some(dom) = domain {
                    if u.domain != dom {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        list.sort_by(|a, b| a.unknown_id.cmp(&b.unknown_id));
        list
    }

    pub fn verify_unknown_resolution(
        &self,
        unknown_id: &str,
    ) -> Result<UnknownResolutionVerification, UnknownError> {
        let unknown = self
            .unknown_heads
            .get(unknown_id)
            .ok_or_else(|| UnknownError::NotFound(unknown_id.to_string()))?;

        Ok(UnknownResolutionVerification {
            valid: unknown.status == UnknownStatus::Resolved,
            truth_verified: unknown
                .resolution
                .as_ref()
                .map(|r| r.disposition == ResolutionDisposition::Verified)
                .unwrap_or(false),
            unknown: unknown.clone(),
        })
    }

    pub fn has(&self, evidence_id: &str) -> bool {
        self.records.contains_key(evidence_id)
    }

    pub fn get(&self, evidence_id: &str) -> Option<&Evidence> {
        self.records.get(evidence_id)
    }

    pub fn clear(&mut self) {
        self.records.clear();
        self.unknown_revisions.clear();
        self.unknown_heads.clear();
    }
}
