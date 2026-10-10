use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tracewise_domain::error::DomainError;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, EvidenceSubject,
};
use tracewise_domain::ledger::EvidenceLedger;

use crate::format::inspect_binary_file;

#[derive(Clone)]
pub struct BinarySession {
    pub ledger: Arc<Mutex<EvidenceLedger>>,
    pub active_target: Arc<Mutex<Option<EvidenceSubject>>>,
    pub started_at: String,
    pub provider: EvidenceProvider,
}

impl BinarySession {
    pub fn new() -> Self {
        Self {
            ledger: Arc::new(Mutex::new(EvidenceLedger::new())),
            active_target: Arc::new(Mutex::new(None)),
            started_at: "2026-10-10T00:00:00Z".to_string(),
            provider: EvidenceProvider {
                id: "native".to_string(),
                name: "Tracewise Native".to_string(),
                version: Some("0.1.0".to_string()),
            },
        }
    }

    pub fn open(
        &self,
        path: &str,
        format_hint: Option<String>,
        provider_id: Option<String>,
    ) -> Result<Value, DomainError> {
        let p = Path::new(path);
        let info = inspect_binary_file(p).map_err(|e| {
            DomainError::Canonicalization(format!("Failed to read target file '{}': {e}", path))
        })?;

        let format = format_hint.unwrap_or(info.format);
        let file_name = p
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());

        let subject = EvidenceSubject {
            name: file_name,
            digest: tracewise_domain::evidence::DigestSha256 {
                sha256: info.sha256.clone(),
            },
            format: format.clone(),
            architecture: info.architecture.clone(),
            local_path: path.to_string(),
        };

        let result_obj = json!({
            "path": path,
            "format": format,
            "kind": "binary",
            "sha256": info.sha256,
            "architecture": info.architecture,
        });

        let mut provider = self.provider.clone();
        if let Some(pid) = provider_id {
            provider.id = pid;
        }

        let ev = create_evidence(
            Some(subject.clone()),
            provider,
            EvidenceObservation {
                predicate_type: Some("rea.analysis".to_string()),
                operation: "open_binary".to_string(),
                parameters: json!({ "path": path }),
                normalized_result: result_obj.clone(),
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::ShippedArtifact),
                environment: None,
                limitations: None,
                locations: None,
                evidence_links: None,
            },
        )?;

        let mut ledger = self.ledger.lock().unwrap();
        let _ = ledger.record(ev);

        let mut current_target = self.active_target.lock().unwrap();
        *current_target = Some(subject);

        Ok(result_obj)
    }

    pub fn close(&self) -> Result<(), DomainError> {
        let mut current_target = self.active_target.lock().unwrap();
        let subject = current_target.take();

        let ev = create_evidence(
            subject,
            self.provider.clone(),
            EvidenceObservation {
                predicate_type: Some("rea.analysis".to_string()),
                operation: "close_binary".to_string(),
                parameters: json!({}),
                normalized_result: Value::Null,
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::ShippedArtifact),
                environment: None,
                limitations: None,
                locations: None,
                evidence_links: None,
            },
        )?;

        let mut ledger = self.ledger.lock().unwrap();
        let _ = ledger.record(ev);

        Ok(())
    }

    pub fn status(&self) -> Value {
        let target = self.active_target.lock().unwrap().clone();
        let ledger = self.ledger.lock().unwrap();
        let bundle = ledger.export();

        json!({
            "active_target": target,
            "session_state": if target.is_some() { "open" } else { "closed" },
            "started_at": self.started_at,
            "ledger_summary": {
                "records": bundle.records.len(),
                "unknowns": bundle.unknowns.len(),
                "artifacts": bundle.artifacts.len(),
            },
            "server_identity": {
                "name": "tracewise",
                "version": "0.1.0"
            }
        })
    }

    pub fn inspect_analysis_view(&self, input: &Value) -> Result<Evidence, DomainError> {
        let target = self.active_target.lock().unwrap().clone();
        let ledger = self.ledger.lock().unwrap();
        let bundle = ledger.export();

        let summary = json!({
            "active_target": target,
            "total_records": bundle.records.len(),
            "total_unknowns": bundle.unknowns.len(),
            "view": input.get("view").cloned().unwrap_or(json!({"facet": "summary"})),
        });

        let ev = create_evidence(
            target,
            self.provider.clone(),
            EvidenceObservation {
                predicate_type: Some("rea.analysis-view".to_string()),
                operation: "inspect_analysis_view".to_string(),
                parameters: input.clone(),
                normalized_result: summary,
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::ShippedArtifact),
                environment: None,
                limitations: None,
                locations: None,
                evidence_links: None,
            },
        )?;

        Ok(ev)
    }
}

impl Default for BinarySession {
    fn default() -> Self {
        Self::new()
    }
}
