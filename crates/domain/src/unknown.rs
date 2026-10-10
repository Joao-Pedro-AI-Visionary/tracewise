use std::collections::BTreeSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::canonical::canonical_sha256;
use crate::error::{DomainError, UnknownError};
use crate::evidence::{EvidenceAuthority, EvidenceConfidence, IsolationLevel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnknownStatus {
    Open,
    Investigating,
    Blocked,
    Contradicted,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnknownSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRequirement {
    pub id: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub isolation: Option<IsolationLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub operation: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationshipType {
    DependsOn,
    RelatedTo,
    Contradicts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    #[serde(rename = "type")]
    pub rel_type: RelationshipType,
    pub unknown_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionDisposition {
    Verified,
    Withdrawn,
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    pub disposition: ResolutionDisposition,
    pub rationale: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualUnknown {
    pub unknown_id: String,
    pub revision: u64,
    pub previous_revision_digest: Option<String>,
    pub revision_digest: String,
    pub scope_digest: Option<String>,
    pub question: String,
    pub status: UnknownStatus,
    pub severity: UnknownSeverity,
    pub domain: String,
    pub supporting_evidence_ids: Vec<String>,
    pub contradicting_evidence_ids: Vec<String>,
    pub required_authority: Option<EvidenceAuthority>,
    pub required_confidence: EvidenceConfidence,
    pub required_environment: Option<EnvironmentRequirement>,
    pub recommended_probes: Vec<Probe>,
    pub relationships: Vec<Relationship>,
    pub resolution: Option<Resolution>,
    pub mutation_evidence_ids: Vec<String>,
}

#[derive(Serialize)]
struct UnknownIdentity<'a> {
    domain: &'a str,
    question: &'a str,
    scope_digest: &'a Option<String>,
}

#[derive(Serialize)]
struct RevisionRecord<'a> {
    unknown_id: &'a str,
    revision: u64,
    previous_revision_digest: &'a Option<String>,
    scope_digest: &'a Option<String>,
    question: &'a str,
    status: &'a UnknownStatus,
    severity: &'a UnknownSeverity,
    domain: &'a str,
    supporting_evidence_ids: &'a [String],
    contradicting_evidence_ids: &'a [String],
    required_authority: &'a Option<EvidenceAuthority>,
    required_confidence: &'a EvidenceConfidence,
    required_environment: &'a Option<EnvironmentRequirement>,
    recommended_probes: &'a [Probe],
    relationships: &'a [Relationship],
    resolution: &'a Option<Resolution>,
    mutation_evidence_ids: &'a [String],
}

impl ResidualUnknown {
    pub fn compute_revision_digest(&self) -> Result<String, DomainError> {
        let record = RevisionRecord {
            unknown_id: &self.unknown_id,
            revision: self.revision,
            previous_revision_digest: &self.previous_revision_digest,
            scope_digest: &self.scope_digest,
            question: &self.question,
            status: &self.status,
            severity: &self.severity,
            domain: &self.domain,
            supporting_evidence_ids: &self.supporting_evidence_ids,
            contradicting_evidence_ids: &self.contradicting_evidence_ids,
            required_authority: &self.required_authority,
            required_confidence: &self.required_confidence,
            required_environment: &self.required_environment,
            recommended_probes: &self.recommended_probes,
            relationships: &self.relationships,
            resolution: &self.resolution,
            mutation_evidence_ids: &self.mutation_evidence_ids,
        };
        canonical_sha256(&record)
    }

    pub fn validate_invariants(&self) -> Result<(), UnknownError> {
        // Revision digest check
        let computed = self
            .compute_revision_digest()
            .map_err(|e| UnknownError::Integrity(e.to_string()))?;
        if computed != self.revision_digest {
            return Err(UnknownError::RevisionDigestMismatch);
        }

        // First revision has no predecessor
        if (self.revision == 1) != self.previous_revision_digest.is_none() {
            return Err(UnknownError::FirstRevisionPredecessorMismatch);
        }

        // Resolved status requires resolution
        if (self.status == UnknownStatus::Resolved) != self.resolution.is_some() {
            return Err(UnknownError::UnresolvedCarriesResolution);
        }

        // Contradicted requires contradicting evidence
        if self.status == UnknownStatus::Contradicted && self.contradicting_evidence_ids.is_empty() {
            return Err(UnknownError::ContradictionRequiresEvidence);
        }

        // Self relationships rejected
        for rel in &self.relationships {
            if rel.unknown_id == self.unknown_id {
                return Err(UnknownError::SelfRelationship(self.unknown_id.clone()));
            }
        }

        // Unique relationships check
        let mut rel_keys = BTreeSet::new();
        for rel in &self.relationships {
            let key = (rel.rel_type, &rel.unknown_id);
            if !rel_keys.insert(key) {
                return Err(UnknownError::DuplicateRelationships);
            }
        }

        // Supporting and contradicting must not overlap
        let supp_set: BTreeSet<&str> = self.supporting_evidence_ids.iter().map(|s| s.as_str()).collect();
        for id in &self.contradicting_evidence_ids {
            if supp_set.contains(id.as_str()) {
                return Err(UnknownError::SimultaneousSupportAndContradict);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RecordUnknownInput {
    pub question: String,
    pub severity: UnknownSeverity,
    pub domain: String,
    #[serde(default)]
    pub supporting_evidence_ids: Vec<String>,
    #[serde(default)]
    pub contradicting_evidence_ids: Vec<String>,
    pub required_authority: Option<EvidenceAuthority>,
    pub required_confidence: EvidenceConfidence,
    pub required_environment: Option<EnvironmentRequirement>,
    pub recommended_probes: Vec<Probe>,
    pub relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateUnknownInput {
    pub unknown_id: String,
    pub expected_revision: u64,
    pub status: UnknownStatus,
    pub severity: UnknownSeverity,
    pub supporting_evidence_ids: Vec<String>,
    pub contradicting_evidence_ids: Vec<String>,
    pub required_authority: Option<EvidenceAuthority>,
    pub required_confidence: EvidenceConfidence,
    pub required_environment: Option<EnvironmentRequirement>,
    pub recommended_probes: Vec<Probe>,
    pub relationships: Vec<Relationship>,
    pub resolution: Option<Resolution>,
}

pub fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for v in values {
        set.insert(v.clone());
    }
    set.into_iter().collect()
}

pub fn sorted_relationships(values: &[Relationship]) -> Vec<Relationship> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| (a.rel_type, &a.unknown_id).cmp(&(b.rel_type, &b.unknown_id)));
    sorted
}

fn collapse_whitespace(text: &str) -> String {
    let re = Regex::new(r"\s+").unwrap();
    re.replace_all(text, " ").to_string()
}

pub fn create_residual_unknown(
    input: &RecordUnknownInput,
    mutation_evidence_id: &str,
    scope_digest: Option<String>,
) -> Result<ResidualUnknown, DomainError> {
    let question = collapse_whitespace(&input.question);
    let identity = UnknownIdentity {
        domain: &input.domain,
        question: &question,
        scope_digest: &scope_digest,
    };
    let hash = canonical_sha256(&identity)?;
    let unknown_id = format!("unk_{hash}");

    let status = if !input.contradicting_evidence_ids.is_empty() {
        UnknownStatus::Contradicted
    } else {
        UnknownStatus::Open
    };

    let mut unknown = ResidualUnknown {
        unknown_id,
        revision: 1,
        previous_revision_digest: None,
        revision_digest: String::new(),
        scope_digest,
        question,
        status,
        severity: input.severity,
        domain: input.domain.clone(),
        supporting_evidence_ids: sorted_unique(&input.supporting_evidence_ids),
        contradicting_evidence_ids: sorted_unique(&input.contradicting_evidence_ids),
        required_authority: input.required_authority,
        required_confidence: input.required_confidence,
        required_environment: input.required_environment.clone(),
        recommended_probes: input.recommended_probes.clone(),
        relationships: sorted_relationships(&input.relationships),
        resolution: None,
        mutation_evidence_ids: vec![mutation_evidence_id.to_string()],
    };

    unknown.revision_digest = unknown.compute_revision_digest()?;
    unknown.validate_invariants()?;
    Ok(unknown)
}

pub fn update_residual_unknown(
    current: &ResidualUnknown,
    input: &UpdateUnknownInput,
    mutation_evidence_id: &str,
) -> Result<ResidualUnknown, DomainError> {
    if current.unknown_id != input.unknown_id {
        return Err(UnknownError::NotFound(input.unknown_id.clone()).into());
    }
    if current.revision != input.expected_revision {
        return Err(UnknownError::RevisionConflict {
            expected: input.expected_revision,
            actual: current.revision,
        }
        .into());
    }

    let mut mutation_ids = current.mutation_evidence_ids.clone();
    mutation_ids.push(mutation_evidence_id.to_string());

    let mut updated = ResidualUnknown {
        unknown_id: current.unknown_id.clone(),
        revision: current.revision + 1,
        previous_revision_digest: Some(current.revision_digest.clone()),
        revision_digest: String::new(),
        scope_digest: current.scope_digest.clone(),
        question: current.question.clone(),
        status: input.status,
        severity: input.severity,
        domain: current.domain.clone(),
        supporting_evidence_ids: sorted_unique(&input.supporting_evidence_ids),
        contradicting_evidence_ids: sorted_unique(&input.contradicting_evidence_ids),
        required_authority: input.required_authority,
        required_confidence: input.required_confidence,
        required_environment: input.required_environment.clone(),
        recommended_probes: input.recommended_probes.clone(),
        relationships: sorted_relationships(&input.relationships),
        resolution: input.resolution.clone(),
        mutation_evidence_ids: sorted_unique(&mutation_ids),
    };

    updated.revision_digest = updated.compute_revision_digest()?;
    updated.validate_invariants()?;
    Ok(updated)
}
