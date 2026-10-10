use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Evidence error: {0}")]
    Evidence(#[from] EvidenceError),

    #[error("Residual unknown error: {0}")]
    Unknown(#[from] UnknownError),

    #[error("Bundle error: {0}")]
    Bundle(#[from] BundleError),

    #[error("Canonicalization failed: {0}")]
    Canonicalization(String),

    #[error("JSON error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("Invalid evidence ID format: '{0}', expected 'ev_<sha256>'")]
    InvalidId(String),

    #[error("Evidence semantic identifier does not match record: expected '{expected}', found '{actual}'")]
    TamperedId { expected: String, actual: String },

    #[error("Analysis profile provider ({profile:?}) does not match Evidence provider ({provider:?})")]
    ProfileProviderMismatch { profile: String, provider: String },

    #[error("Analysis profile digest mismatch: expected '{expected}', found '{actual}'")]
    ProfileDigestMismatch { expected: String, actual: String },

    #[error("Evidence field validation error: {0}")]
    InvalidField(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UnknownError {
    #[error("Invalid unknown ID format: '{0}', expected 'unk_<sha256>'")]
    InvalidId(String),

    #[error("Residual unknown revision conflict: expected revision {expected}, current is {actual}")]
    RevisionConflict { expected: u64, actual: u64 },

    #[error("Residual unknown not found: {0}")]
    NotFound(String),

    #[error("Residual unknown already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("Unknown registry integrity violation: {0}")]
    Integrity(String),

    #[error("Residual unknown dependency graph contains a cycle")]
    CycleDetected,

    #[error("Contradicted status requires contradicting evidence")]
    ContradictionRequiresEvidence,

    #[error("An unknown cannot relate to itself: {0}")]
    SelfRelationship(String),

    #[error("Relationships must be unique")]
    DuplicateRelationships,

    #[error("Evidence cannot simultaneously support and contradict")]
    SimultaneousSupportAndContradict,

    #[error("Only the first revision has no predecessor")]
    FirstRevisionPredecessorMismatch,

    #[error("Only resolved unknowns carry a resolution")]
    UnresolvedCarriesResolution,

    #[error("Residual unknown revision digest does not match")]
    RevisionDigestMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("Evidence bundle validation failed: {0}")]
    Integrity(String),

    #[error("Evidence bundle contains duplicate record IDs: {0}")]
    DuplicateRecordId(String),

    #[error("Residual unknown references missing evidence: {0}")]
    MissingEvidence(String),

    #[error("Residual unknown references missing unknown: {0}")]
    MissingUnknown(String),

    #[error("Residual unknown dependency graph contains a cycle")]
    CycleDetected,

    #[error("Evidence bundle manifests are not canonical")]
    ManifestsNotCanonical,

    #[error("Residual unknown revision chain is broken for {0}")]
    BrokenRevisionChain(String),

    #[error("Residual unknown revision history has a gap for {0}")]
    RevisionHistoryGap(String),

    #[error("Residual unknown {0} has no qualifying resolution evidence")]
    NoQualifyingResolutionEvidence(String),

    #[error("Residual unknown {0} retains contradicting evidence")]
    RetainsContradictingEvidence(String),

    #[error("Explicit pair references missing evidence: {0}")]
    MissingPairEvidence(String),

    #[error("Explicit evidence pairs must be one-to-one")]
    PairsNotOneToOne,
}
