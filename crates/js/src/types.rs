use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ZIP_NON_ENTRY_TAIL_LIMITATION: &str =
    "ZIP inventory lists central-directory entries only. Bytes after the central directory, including an APK Signing Block or a ZIP comment, are not occurrences.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactNode {
    pub artifact_id: String,
    pub format: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: Option<String>,
    pub architecture: Option<String>,
    pub content_state: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceLocation {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactOccurrence {
    pub occurrence_id: String,
    pub artifact_id: Option<String>,
    pub parent_occurrence_id: Option<String>,
    pub logical_path: String,
    pub entry_kind: String,
    pub artifact_kind: String,
    pub artifact_format: String,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub hash_status: String,
    pub source_location: Option<SourceLocation>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactEdge {
    pub edge_id: String,
    pub ordinal: u64,
    pub parent_artifact_id: String,
    pub relation: String,
    pub occurrence_id: String,
    pub producer: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityContradiction {
    pub contradiction_id: String,
    pub occurrence_id: String,
    pub parent_artifact_id: String,
    pub logical_path: String,
    pub declared_sha256: String,
    pub observed_sha256: String,
    pub entry_kind: String,
    pub unpacked: bool,
    pub trust: String,
    pub provenance: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactGraphManifest {
    pub manifest_id: String,
    pub root_artifact_id: String,
    pub root_sha256: String,
    pub root_format: String,
    pub graph_sha256: String,
    pub node_count: u64,
    pub occurrence_count: u64,
    pub edge_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactInventoryResult {
    pub manifest: ArtifactGraphManifest,
    pub nodes: Vec<ArtifactNode>,
    pub occurrences: Vec<ArtifactOccurrence>,
    pub edges: Vec<ArtifactEdge>,
    pub provenance: Vec<Value>,
    pub integrity_contradictions: Vec<IntegrityContradiction>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionManifest {
    pub extraction_id: String,
    pub source_manifest_id: String,
    pub selected_occurrence_ids: Vec<String>,
    pub files_sha256: String,
    pub output_root_alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedArtifact {
    pub artifact_id: String,
    pub relative_path: String,
    pub sha256: String,
    pub bytes_written: u64,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionCleanup {
    pub attempted: bool,
    pub verified: bool,
    pub residual_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactExtractionResult {
    pub manifest: ArtifactGraphManifest,
    pub extraction_manifest: ExtractionManifest,
    pub output_root: String,
    pub artifacts: Vec<ExtractedArtifact>,
    pub containment_verified: bool,
    pub cleanup: ExtractionCleanup,
    pub provenance: Vec<Value>,
    pub integrity_contradictions: Vec<IntegrityContradiction>,
    pub limitations: Vec<String>,
}

pub const ARTIFACT_GRAPH_PROVIDER_ID: &str = "rea-artifact-graph";
pub const ARTIFACT_GRAPH_PROVIDER_NAME: &str = "REA safe artifact graph provider";
pub const ARTIFACT_GRAPH_PROVIDER_VERSION: &str = "1";

pub const ARTIFACT_COMPARISON_PROVIDER_ID: &str = "rea-artifact-comparison";
pub const ARTIFACT_COMPARISON_PROVIDER_NAME: &str = "REA artifact comparison";
pub const ARTIFACT_COMPARISON_PROVIDER_VERSION: &str = "1";

pub fn artifact_graph_provider() -> tracewise_domain::evidence::EvidenceProvider {
    tracewise_domain::evidence::EvidenceProvider {
        id: ARTIFACT_GRAPH_PROVIDER_ID.to_string(),
        name: ARTIFACT_GRAPH_PROVIDER_NAME.to_string(),
        version: Some(ARTIFACT_GRAPH_PROVIDER_VERSION.to_string()),
    }
}

pub fn artifact_comparison_provider() -> tracewise_domain::evidence::EvidenceProvider {
    tracewise_domain::evidence::EvidenceProvider {
        id: ARTIFACT_COMPARISON_PROVIDER_ID.to_string(),
        name: ARTIFACT_COMPARISON_PROVIDER_NAME.to_string(),
        version: Some(ARTIFACT_COMPARISON_PROVIDER_VERSION.to_string()),
    }
}
