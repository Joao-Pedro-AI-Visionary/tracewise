use serde::{Deserialize, Serialize};

use crate::canonical::canonical_sha256;
use crate::error::{DomainError, EvidenceError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestSha256 {
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSubject {
    pub name: String,
    pub digest: DigestSha256,
    pub format: String,
    pub architecture: Option<String>,
    pub local_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProvider {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedProviderIdentity {
    pub id: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisProfile {
    pub provider: CommittedProviderIdentity,
    pub parameters: serde_json::Value,
    pub digest: String,
}

impl AnalysisProfile {
    pub fn compute_digest(&self) -> Result<String, DomainError> {
        let unsigned = serde_json::json!({
            "provider": self.provider,
            "parameters": self.parameters,
        });
        crate::canonical::canonical_sha256(&unsigned)
    }

    pub fn verify(&self) -> Result<(), EvidenceError> {
        let computed = self
            .compute_digest()
            .map_err(|e| EvidenceError::InvalidField(e.to_string()))?;
        if computed != self.digest {
            return Err(EvidenceError::ProfileDigestMismatch {
                expected: self.digest.clone(),
                actual: computed,
            });
        }
        Ok(())
    }
}

pub fn create_analysis_profile(
    provider: CommittedProviderIdentity,
    parameters: serde_json::Value,
) -> Result<AnalysisProfile, DomainError> {
    let unsigned = serde_json::json!({
        "provider": provider,
        "parameters": parameters,
    });
    let digest = crate::canonical::canonical_sha256(&unsigned)?;
    Ok(AnalysisProfile {
        provider,
        parameters,
        digest,
    })
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceConfidence {
    Observed,
    Derived,
    Inferred,
}

impl PartialOrd for EvidenceConfidence {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvidenceConfidence {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rank = |c: &EvidenceConfidence| match c {
            EvidenceConfidence::Inferred => 1,
            EvidenceConfidence::Derived => 2,
            EvidenceConfidence::Observed => 3,
        };
        rank(self).cmp(&rank(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceAuthority {
    ShippedArtifact,
    ControlledReplay,
    HistoricalReference,
    ExternalService,
    AnalystInference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationLevel {
    None,
    Process,
    Container,
    VirtualMachine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    pub id: String,
    pub platform: String,
    pub architecture: String,
    pub isolation: IsolationLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EvidenceLocation {
    Address { address: String },
    AddressRange { start: String, end: String },
    ArtifactPath { path: String },
    FileOffset { offset: u64 },
    FileOffsetRange { start: u64, end: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: String,
    pub subject: Option<EvidenceSubject>,
    pub provider: EvidenceProvider,
    pub analysis_profile: Option<serde_json::Value>,
    pub predicate_type: String,
    pub operation: String,
    pub parameters: serde_json::Value,
    pub raw_result: Option<serde_json::Value>,
    pub normalized_result: serde_json::Value,
    pub confidence: EvidenceConfidence,
    pub authority: EvidenceAuthority,
    pub environment: Option<ExecutionEnvironment>,
    pub limitations: Vec<String>,
    pub locations: Vec<EvidenceLocation>,
    pub evidence_links: Vec<String>,
}

#[derive(Serialize)]
struct SubjectProjection<'a> {
    digest: &'a DigestSha256,
    format: &'a str,
    architecture: &'a Option<String>,
}

#[derive(Serialize)]
struct SemanticProjection<'a> {
    subject: Option<SubjectProjection<'a>>,
    provider: &'a EvidenceProvider,
    analysis_profile: &'a Option<serde_json::Value>,
    predicate_type: &'a str,
    operation: &'a str,
    parameters: &'a serde_json::Value,
    raw_result: &'a Option<serde_json::Value>,
    normalized_result: &'a serde_json::Value,
    confidence: &'a EvidenceConfidence,
    authority: &'a EvidenceAuthority,
    environment: &'a Option<ExecutionEnvironment>,
    limitations: &'a [String],
    locations: &'a [EvidenceLocation],
    evidence_links: &'a [String],
}

impl Evidence {
    pub fn compute_id(&self) -> Result<String, DomainError> {
        let projection = SemanticProjection {
            subject: self.subject.as_ref().map(|s| SubjectProjection {
                digest: &s.digest,
                format: &s.format,
                architecture: &s.architecture,
            }),
            provider: &self.provider,
            analysis_profile: &self.analysis_profile,
            predicate_type: &self.predicate_type,
            operation: &self.operation,
            parameters: &self.parameters,
            raw_result: &self.raw_result,
            normalized_result: &self.normalized_result,
            confidence: &self.confidence,
            authority: &self.authority,
            environment: &self.environment,
            limitations: &self.limitations,
            locations: &self.locations,
            evidence_links: &self.evidence_links,
        };
        let hash = canonical_sha256(&projection)?;
        Ok(format!("ev_{hash}"))
    }

    pub fn verify(&self) -> Result<(), EvidenceError> {
        if !self.evidence_id.starts_with("ev_") || self.evidence_id.len() != 67 {
            return Err(EvidenceError::InvalidId(self.evidence_id.clone()));
        }
        let hex_part = &self.evidence_id[3..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err(EvidenceError::InvalidId(self.evidence_id.clone()));
        }

        // Validate analysis profile provider and digest if present
        if let Some(ref profile_val) = self.analysis_profile {
            let profile: AnalysisProfile = serde_json::from_value(profile_val.clone())
                .map_err(|e| EvidenceError::InvalidField(format!("Invalid analysis_profile: {e}")))?;
            if profile.provider.id != self.provider.id
                || profile.provider.name != self.provider.name
                || self.provider.version.as_deref() != Some(profile.provider.version.as_str())
            {
                return Err(EvidenceError::ProfileProviderMismatch {
                    profile: format!("{}:{}", profile.provider.id, profile.provider.name),
                    provider: format!("{}:{}", self.provider.id, self.provider.name),
                });
            }
            profile.verify()?;
        }


        let computed = self.compute_id().map_err(|e| EvidenceError::InvalidField(e.to_string()))?;
        if computed != self.evidence_id {
            return Err(EvidenceError::TamperedId {
                expected: computed,
                actual: self.evidence_id.clone(),
            });
        }

        Ok(())
    }

    /// Checks if two evidence records agree semantically (disregarding display fields name/local_path).
    pub fn records_agree(&self, other: &Evidence) -> bool {
        let left_normalized = self.without_local_path();
        let right_normalized = other.without_local_path();
        match (
            crate::canonical::canonical_json(&left_normalized),
            crate::canonical::canonical_json(&right_normalized),
        ) {
            (Ok(left_json), Ok(right_json)) => left_json == right_json,
            _ => false,
        }
    }

    fn without_local_path(&self) -> Evidence {
        let mut cloned = self.clone();
        if let Some(ref mut s) = cloned.subject {
            s.name = "<non-identity-name>".to_string();
            s.local_path = "<non-identity-local-path>".to_string();
        }
        cloned
    }
}

pub struct EvidenceObservation {
    pub predicate_type: Option<String>,
    pub operation: String,
    pub parameters: serde_json::Value,
    pub normalized_result: serde_json::Value,
    pub raw_result: Option<serde_json::Value>,
    pub analysis_profile: Option<serde_json::Value>,
    pub confidence: Option<EvidenceConfidence>,
    pub authority: Option<EvidenceAuthority>,
    pub environment: Option<ExecutionEnvironment>,
    pub limitations: Option<Vec<String>>,
    pub locations: Option<Vec<EvidenceLocation>>,
    pub evidence_links: Option<Vec<String>>,
}

pub fn create_evidence(
    subject: Option<EvidenceSubject>,
    provider: EvidenceProvider,
    observation: EvidenceObservation,
) -> Result<Evidence, DomainError> {
    let mut evidence = Evidence {
        evidence_id: String::new(),
        subject,
        provider,
        analysis_profile: observation.analysis_profile,
        predicate_type: observation
            .predicate_type
            .unwrap_or_else(|| "rea.analysis".to_string()),
        operation: observation.operation,
        parameters: observation.parameters,
        raw_result: observation.raw_result,
        normalized_result: observation.normalized_result,
        confidence: observation.confidence.unwrap_or(EvidenceConfidence::Observed),
        authority: observation
            .authority
            .unwrap_or(EvidenceAuthority::ShippedArtifact),
        environment: observation.environment,
        limitations: observation.limitations.unwrap_or_default(),
        locations: observation.locations.unwrap_or_default(),
        evidence_links: observation.evidence_links.unwrap_or_default(),
    };

    evidence.evidence_id = evidence.compute_id()?;
    Ok(evidence)
}
