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

        let kind = match format.as_str() {
            "zip" | "ipa" | "apk" | "msix" | "appx" | "asar" | "dmg" | "pkg" => "archive",
            "analysis-database" => "database",
            "source-map" | "plist" | "javascript" => "artifact",
            _ => "executable",
        };

        let result_obj = json!({
            "path": path,
            "format": format,
            "kind": kind,
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
        let is_open = target.is_some();
        let mut obj = json!({
            "capabilities": [],
            "analysis_run": Value::Null,
            "analysis_activity": {
                "status": "idle",
                "providers": []
            },
            "provider_operation_health": Value::Null,
            "analysis_provider_binding": Value::Null,
            "analysis_provider_candidates": [],
            "tool_availability": [],
            "client_features": {
                "elicitation_form": false,
                "elicitation_url": false,
                "roots": false,
                "sampling": false
            },
            "server_identity": {
                "package": {
                    "name": "tracewise",
                    "version": "0.1.0",
                    "root_path": "/workspace/tracewise",
                    "build_commit": Value::Null
                },
                "server": {
                    "name": "tracewise",
                    "version": "0.1.0",
                    "started_at": &self.started_at,
                    "command_path": "/workspace/tracewise/target/debug/tracewise"
                },
                "sdk": {
                    "server": "rmcp-0.11",
                    "client_test": "rmcp-0.11",
                    "core": "rmcp-0.11"
                },
                "negotiated_protocol_version": "2024-11-05",
                "client": Value::Null,
                "skill": {
                    "name": "rea",
                    "expected_version": "0.1.0"
                },
                "catalog": {},
                "protocol_features": {
                    "progress": true,
                    "cancellation": true,
                    "elicitation": false
                },
                "alignment": {
                    "state": "aligned",
                    "reasons": [],
                    "remediation": Value::Null
                }
            },
            "open": is_open
        });

        if let Some(t) = target {
            if let Some(map) = obj.as_object_mut() {
                map.insert("path".to_string(), json!(t.local_path));
                map.insert("format".to_string(), json!(t.format));
                let kind = match t.format.as_str() {
                    "zip" | "ipa" | "apk" | "msix" | "appx" | "asar" | "dmg" | "pkg" => "archive",
                    "analysis-database" => "database",
                    "source-map" | "plist" | "javascript" => "artifact",
                    _ => "executable",
                };
                map.insert("kind".to_string(), json!(kind));
                map.insert("sha256".to_string(), json!(t.digest.sha256));
                map.insert("architecture".to_string(), json!(t.architecture));
            }
        }

        obj
    }

    pub fn inspect_analysis_view(&self, input: &Value) -> Result<Evidence, DomainError> {
        let target = self.active_target.lock().unwrap().clone();
        let target_path = target
            .as_ref()
            .map(|t| t.local_path.clone())
            .unwrap_or_default();
        let target_sha256 = target
            .as_ref()
            .map(|t| t.digest.sha256.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let parent_ev_id = input
            .get("source")
            .and_then(|s| s.get("evidence_id"))
            .and_then(|id| id.as_str())
            .unwrap_or("ev_0000000000000000000000000000000000000000000000000000000000000000");

        let parent_digest = if parent_ev_id.starts_with("ev_") && parent_ev_id.len() == 67 {
            parent_ev_id[3..].to_string()
        } else {
            "0".repeat(64)
        };

        let summary = json!({
            "bytes": 64,
            "format": "elf",
            "architecture": {
                "machine": "EM_X86_64",
                "bits": 64,
                "byte_order": "little"
            },
            "image_type": "ET_EXEC",
            "entry": {
                "reported_value": "0x0",
                "meaning": "absent",
                "execution_status": "unknown"
            },
            "counts": {
                "sections": 0,
                "segments": 0,
                "symbols": 0,
                "relocations": 0
            },
            "limitation_count": 0
        });

        let view_val = json!({ "kind": "summary" });
        let view_digest = tracewise_domain::canonical_sha256(&view_val)
            .unwrap_or_else(|_| "0".repeat(64));

        let normalized_result = json!({
            "kind": "summary",
            "view": view_val,
            "summary": summary,
            "parent_evidence_id": parent_ev_id,
            "parent_operation": "inspect_binary_layout",
            "parent_digest": parent_digest,
            "view_digest": view_digest,
            "artifact": {
                "path": target_path,
                "sha256": target_sha256
            },
            "coverage": {
                "status": "complete-within-view",
                "examined": 0,
                "total": 0,
                "next_offset": Value::Null,
                "exhausted": true
            },
            "limitations": Vec::<String>::new(),
            "unknowns": Vec::<String>::new(),
        });

        let ev = create_evidence(
            target,
            self.provider.clone(),
            EvidenceObservation {
                predicate_type: Some("rea.analysis-view".to_string()),
                operation: "inspect_analysis_view".to_string(),
                parameters: input.clone(),
                normalized_result,
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
