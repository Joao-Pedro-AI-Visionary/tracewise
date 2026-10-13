//! Hopper candidate backed by REA's private bridge (port of `HopperProvider.ts`,
//! `HopperRegexSearch.ts` and `HopperFileOffset.ts`).

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use regex::RegexBuilder;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::AnalysisProfile;

use crate::error::AnalysisError;
use crate::provider::{
    AnalysisClient, AnalysisExecution, AnalysisProvider, Capability, ExecContext, ProviderAvailability,
    ProviderIdentity, TargetSupport,
};
use crate::target::BinaryTarget;

use super::capabilities::{capabilities, limitations_for, provider_identity};
use super::client::{HopperClient, HopperClientOptions};
use super::config::HopperConfig;
use super::profile;

const REGEX_DEADLINE: Duration = Duration::from_secs(5);

pub struct HopperProvider {
    config: HopperConfig,
    platform: &'static str,
}

impl HopperProvider {
    pub fn new(config: HopperConfig) -> Self {
        Self {
            config,
            platform: if cfg!(target_os = "macos") { "darwin" } else { "linux" },
        }
    }
}

#[async_trait]
impl AnalysisProvider for HopperProvider {
    fn identity(&self) -> ProviderIdentity {
        provider_identity()
    }

    fn capabilities(&self) -> Vec<Capability> {
        capabilities(&provider_identity())
    }

    fn inspect_availability(&self) -> ProviderAvailability {
        let diagnostics = json!({ "launcher_path": self.config.launcher_path, "platform": self.platform });
        let usable = std::fs::metadata(&self.config.launcher_path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
        if usable {
            ProviderAvailability {
                available: true,
                code: None,
                reason: None,
                diagnostics,
            }
        } else {
            ProviderAvailability {
                available: false,
                code: Some("executable_missing".to_string()),
                reason: Some(format!(
                    "Hopper launcher is missing or not executable: {}",
                    self.config.launcher_path
                )),
                diagnostics,
            }
        }
    }

    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport {
        let diagnostics = json!({
            "target_kind": target.kind,
            "target_format": target.format,
            "architecture": target.architecture,
        });
        if target.kind != "executable" && target.kind != "database" {
            return TargetSupport::unsupported(
                "target_kind_unsupported",
                &format!("Hopper cannot directly analyze {} targets.", target.kind),
                diagnostics,
            );
        }
        if target.kind == "database" {
            return TargetSupport::supported(diagnostics);
        }
        if target.architecture.as_deref() == Some("mips") {
            return TargetSupport::unsupported(
                "architecture_unsupported",
                "REA's Hopper adapter does not admit MIPS targets.",
                diagnostics,
            );
        }
        if target.format == "dos-mz" || target.format == "dos-com" {
            return TargetSupport::unsupported(
                "target_format_unsupported",
                "DOS MZ/COM analysis requires the Ghidra 16-bit real-mode adapter.",
                diagnostics,
            );
        }
        TargetSupport::supported(diagnostics)
    }

    async fn resolve_analysis_profile(&self, target: &BinaryTarget) -> Result<Option<AnalysisProfile>, AnalysisError> {
        profile::resolve(target, &self.config.launcher_path, &self.config.loader_args)
    }

    fn create_client(&self, target: &BinaryTarget, profile: Option<AnalysisProfile>) -> Arc<dyn AnalysisClient> {
        if target.kind != "executable" && target.kind != "database" {
            return Arc::new(UnavailableClient(AnalysisError::capability_unavailable(
                "hopper",
                "open_binary",
                &format!(
                    "Hopper cannot open {} targets directly. Inventory or extract the artifact first.",
                    target.kind
                ),
            )));
        }
        let container = profile
            .as_ref()
            .and_then(|p| p.parameters.get("macho_container"))
            .and_then(Value::as_str);
        let derived = match profile::loader_args_for_target(target, container) {
            Ok(args) => args,
            Err(error) => return Arc::new(UnavailableClient(error)),
        };
        let loader_args = if self.config.loader_args.is_empty() {
            derived
        } else {
            self.config.loader_args.clone()
        };
        let client = HopperClient::new(HopperClientOptions {
            launcher_path: self.config.launcher_path.clone(),
            environment: self.config.environment.clone(),
            target_path: target.path.clone(),
            target_kind: target.kind.clone(),
            loader_args,
            startup_timeout_ms: 120_000,
        });
        let identity = profile
            .as_ref()
            .map(|p| ProviderIdentity {
                id: p.provider.id.clone(),
                name: p.provider.name.clone(),
                version: Some(p.provider.version.clone()),
            })
            .unwrap_or_else(provider_identity);
        Arc::new(HopperProviderClient {
            client,
            profile,
            target: target.clone(),
            identity,
            regex_cache: OnceLock::new(),
        })
    }
}

struct UnavailableClient(AnalysisError);

#[async_trait]
impl AnalysisClient for UnavailableClient {
    async fn execute(&self, _: &str, _: &Value, _: &ExecContext) -> Result<AnalysisExecution, AnalysisError> {
        Err(self.0.clone())
    }

    async fn close(&self, _: bool) -> Result<(), AnalysisError> {
        Ok(())
    }
}

pub struct HopperProviderClient {
    client: HopperClient,
    profile: Option<AnalysisProfile>,
    target: BinaryTarget,
    identity: ProviderIdentity,
    #[allow(dead_code)]
    regex_cache: OnceLock<()>,
}

#[async_trait]
impl AnalysisClient for HopperProviderClient {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let is_search = operation == "search_strings" || operation == "search_procedures";
        let result = if is_search && parameters.get("mode") == Some(&json!("regex")) {
            self.regex_search(operation, parameters, ctx).await?
        } else {
            self.client.call_tool(operation, parameters, &ctx.cancel, None).await?
        };
        let mapped = if operation == "address_to_file_offset" {
            map_file_offset(&self.target, &result).await?
        } else {
            result.clone()
        };
        let mut limitations = limitations_for(operation);
        if operation == "read_bytes" {
            limitations.push("Hopper byte reads stop at the containing segment's exclusive end; a readable prefix is returned with complete=false when the requested range crosses it.".to_string());
        }
        if operation == "procedure_references" {
            limitations.push("Native CallReference classifications and unresolved targets are preserved. Detailed reference flags and coverage beyond reported CallReference objects remain unknown.".to_string());
        }
        let raw = if mapped == result { None } else { Some(result) };
        Ok(AnalysisExecution {
            result: mapped,
            raw_result: raw,
            provider: self.identity.clone(),
            analysis_profile: self.profile.clone(),
            limitations,
            locations: Vec::new(),
        })
    }

    async fn close(&self, retain_document: bool) -> Result<(), AnalysisError> {
        self.client.close(retain_document).await
    }
}

impl HopperProviderClient {
    /// Match collected native facts off Hopper's API thread, with a supervised deadline.
    async fn regex_search(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<Value, AnalysisError> {
        let remote = |message: String| AnalysisError::HopperRemote {
            code: -32000,
            safe_message: message,
            diagnostic_type: "invalid_request".to_string(),
            operation: Some(operation.to_string()),
            request_id: None,
        };
        let object = parameters.as_object().cloned().unwrap_or_default();
        let allowed = ["pattern", "mode", "case_sensitive", "document"];
        let valid = object.keys().all(|k| allowed.contains(&k.as_str()))
            && object.get("pattern").and_then(Value::as_str).map(|p| !p.is_empty()).unwrap_or(false)
            && matches!(object.get("case_sensitive"), None | Some(Value::Bool(_)))
            && matches!(object.get("document"), None | Some(Value::String(_)));
        if !valid {
            return Err(remote("Invalid search arguments".to_string()));
        }
        let pattern = object["pattern"].as_str().unwrap_or_default().to_string();
        let case_sensitive = object.get("case_sensitive").and_then(Value::as_bool).unwrap_or(false);
        let inventory_params = match object.get("document") {
            Some(document) => json!({ "document": document }),
            None => json!({}),
        };
        let inventory = self
            .client
            .call_tool(
                if operation == "search_strings" { "list_strings" } else { "list_procedures" },
                &inventory_params,
                &ctx.cancel,
                None,
            )
            .await?;
        let items = inventory
            .as_array()
            .filter(|a| {
                a.iter().all(|i| {
                    i.get("address").map(Value::is_string).unwrap_or(false)
                        && i.get("value").map(Value::is_string).unwrap_or(false)
                })
            })
            .cloned()
            .ok_or_else(|| AnalysisError::output(operation, "Hopper search inventory is malformed"))?;
        if ctx.cancel.is_cancelled() {
            return Err(AnalysisError::cancelled(operation));
        }
        let expression = RegexBuilder::new(&pattern)
            .case_insensitive(!case_sensitive)
            .unicode(true)
            .build()
            .map_err(|e| remote(format!("Invalid regex pattern: {e}")))?;
        let values: Vec<String> = items
            .iter()
            .map(|i| i["value"].as_str().unwrap_or_default().to_string())
            .collect();
        let matching = tokio::task::spawn_blocking(move || {
            values
                .iter()
                .enumerate()
                .filter(|(_, v)| expression.is_match(v))
                .map(|(i, _)| i)
                .collect::<Vec<usize>>()
        });
        let indices = tokio::select! {
            outcome = tokio::time::timeout(REGEX_DEADLINE, matching) => match outcome {
                Ok(Ok(indices)) => indices,
                Ok(Err(e)) => return Err(AnalysisError::output(operation, format!("Regex worker failed: {e}"))),
                Err(_) => {
                    return Err(AnalysisError::ResourceConstraint {
                        operation: operation.to_string(),
                        resource: "cpu".to_string(),
                        reason: "Regex matching exceeded its supervised deadline; the Hopper API thread remains available.".to_string(),
                        reported_limits: Some(json!({ "matching_deadline_ms": 5000 })),
                        remediation: Some("Simplify the ECMAScript Unicode regex or use literal mode, then retry in the same session.".to_string()),
                    })
                }
            },
            _ = ctx.cancel.cancelled() => return Err(AnalysisError::cancelled(operation)),
        };
        Ok(Value::Array(indices.into_iter().map(|i| items[i].clone()).collect()))
    }
}

/// Bind native image-relative offsets to coordinates in the admitted source bytes.
async fn map_file_offset(target: &BinaryTarget, value: &Value) -> Result<Value, AnalysisError> {
    const OPERATION: &str = "address_to_file_offset";
    let Some(observation) = parse_observation(value) else {
        return Err(AnalysisError::output(
            OPERATION,
            "Hopper's native file mapping observation is malformed",
        ));
    };
    let partial = |reason: &str| {
        let mut object = observation.clone();
        object["operation"] = json!(OPERATION);
        object["original_file_offset"] = json!({ "available": false, "reason": reason });
        object
    };
    let unavailable = |reason: &str| AnalysisError::Partial {
        inner: Box::new(AnalysisError::capability_unavailable("hopper", OPERATION, reason)),
        partial_observation: partial(reason),
    };
    if target.kind != "executable" {
        return Err(unavailable(
            "The selected database digest does not identify its original executable bytes. Open that executable to verify original-file coordinates; read_bytes still exposes the database's native bytes.",
        ));
    }
    let path = target.path.clone();
    let source = tokio::task::spawn_blocking(move || -> Result<(String, u64, [u8; 4]), String> {
        use std::io::Read;
        let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err(format!(
                "Source {path} is no longer a regular file. Restore the admitted executable or reopen a regular source."
            ));
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        let mut size = 0u64;
        let mut magic = [0u8; 4];
        loop {
            let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if size < 4 {
                let take = (4 - size as usize).min(n);
                magic[size as usize..size as usize + take].copy_from_slice(&buffer[..take]);
            }
            hasher.update(&buffer[..n]);
            size += n as u64;
        }
        Ok((hex::encode(hasher.finalize()), size, magic))
    })
    .await
    .map_err(|e| AnalysisError::output(OPERATION, e.to_string()))?;
    let (sha256, size, magic) = match source {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            return Err(AnalysisError::Partial {
                inner: Box::new(AnalysisError::ArtifactChanged {
                    operation: OPERATION.to_string(),
                    path: target.path.clone(),
                    reason: reason.clone(),
                }),
                partial_observation: partial(&reason),
            })
        }
    };
    if sha256 != target.sha256 {
        let reason = format!(
            "Source {} differs from the admitted artifact: expected SHA-256 {}, observed {}. Reopen the changed source for a new analysis identity.",
            target.path, target.sha256, sha256
        );
        return Err(AnalysisError::Partial {
            inner: Box::new(AnalysisError::ArtifactChanged {
                operation: OPERATION.to_string(),
                path: target.path.clone(),
                reason: reason.clone(),
            }),
            partial_observation: partial(&reason),
        });
    }
    if [[0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf], [0xbe, 0xba, 0xfe, 0xca], [0xbf, 0xba, 0xfe, 0xca]]
        .contains(&magic)
    {
        return Err(unavailable(
            "FAT Mach-O slice mapping is not ported; thin the Mach-O to verify original-file coordinates.",
        ));
    }
    let offset = observation["provider_file_offset"].as_u64().unwrap_or(0);
    if offset >= size {
        return Err(unavailable("Provider mapping lies outside the admitted executable bytes"));
    }
    Ok(json!({
        "address": observation["address"],
        "file_offset": offset,
        "provider_file_offset": offset,
        "image_base_file_offset": 0,
        "source_path": target.path,
    }))
}

fn parse_observation(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    let keys = ["address", "provider_file_offset", "provider_source_path", "provider_image_header_hex"];
    if object.len() != keys.len() || !keys.iter().all(|k| object.contains_key(*k)) {
        return None;
    }
    let address = object["address"].as_str()?;
    let hex_ok = address.strip_prefix("0x").map(|h| !h.is_empty() && h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))?;
    if !hex_ok {
        return None;
    }
    let offset = object["provider_file_offset"].as_u64()?;
    if offset > 9_007_199_254_740_991 {
        return None;
    }
    if !(object["provider_source_path"].is_string() || object["provider_source_path"].is_null()) {
        return None;
    }
    match &object["provider_image_header_hex"] {
        Value::Null => {}
        Value::String(h) if h.len() == 24 && h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) => {}
        _ => return None,
    }
    Some(value.clone())
}
