//! Electron process and security-boundary facts in the application graph, plus the IPC pairing
//! analysis and boundary summary (REA `ElectronBoundary*.ts`).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::static_types::{
    ElectronBrowserWindowFinding, ElectronContextBridgeFinding, ElectronIpcFinding,
    ElectronNativeAddonBindingFinding, ElectronSenderValidationFinding, ElectronUtilityProcessFinding,
};
use crate::jsgraph::ast_values::display_text;
use crate::jsgraph::util::{compare_code_points, composite_key, sha256_text};

use super::context::{javascript_analysis_coverage, GraphContext, RoleNodeInput};
use super::domain::{
    artifact_local_identity, ast_observation_evidence, static_inference_evidence, EvidenceInput, NodeRef,
    ObservationInput,
};
use super::model::{ArtifactAnalysis, ArtifactFile, FileKind};
use super::path_resolution::{
    resolve_artifact_path_by_context, Files, ModuleKind, PathContext, ResolveInput,
};

// ---- analysis: IPC records, pairings, summary ------------------------------------------------

/// One IPC fact retaining its exact owning artifact for graph projection.
#[derive(Clone)]
pub struct IpcRecord<'a> {
    pub key: String,
    pub file: &'a ArtifactFile,
    pub finding: &'a ElectronIpcFinding,
}

pub struct IpcPairingState<'a> {
    pub transmission: IpcRecord<'a>,
    pub candidates: Vec<IpcRecord<'a>>,
    /// `paired`, `ambiguous`, `unpaired`.
    pub status: &'static str,
}

fn ipc_record_key(path: &str, finding: &ElectronIpcFinding) -> String {
    format!(
        "{path}\0{}:{}\0{}\0{}",
        finding.location.start.line, finding.location.start.column, finding.side, finding.operation
    )
}

/// Flatten all per-file IPC facts into deterministic application records.
pub fn collect_ipc_records(analysis: &ArtifactAnalysis) -> Vec<IpcRecord<'_>> {
    let mut records: Vec<IpcRecord<'_>> = analysis
        .files
        .iter()
        .flat_map(|analyzed| {
            analyzed
                .javascript
                .iter()
                .flat_map(move |js| js.electron.ipc.iter())
                .map(move |finding| IpcRecord {
                    key: ipc_record_key(&analyzed.file.path, finding),
                    file: &analyzed.file,
                    finding,
                })
        })
        .collect();
    records.sort_by(|a, b| compare_code_points(&a.key, &b.key));
    records
}

fn is_renderer_transmission(record: &IpcRecord<'_>) -> bool {
    record.finding.side == "renderer" && (record.finding.mode == "send" || record.finding.mode == "invoke")
}

fn is_pairable(record: &IpcRecord<'_>) -> bool {
    is_renderer_transmission(record) && record.finding.operation != "send-to-host"
}

fn is_main_handler(record: &IpcRecord<'_>) -> bool {
    record.finding.side == "main" && (record.finding.mode == "listen" || record.finding.mode == "handle")
}

fn compatible_modes(transmission: &ElectronIpcFinding, handler: &ElectronIpcFinding) -> bool {
    if transmission.mode == "invoke" {
        handler.mode == "handle"
    } else if transmission.operation == "send-to-host" {
        false
    } else {
        transmission.mode == "send" && handler.mode == "listen"
    }
}

/// Match only exact literal channels and retain ambiguous matches separately.
pub fn classify_ipc_pairings<'a>(records: &[IpcRecord<'a>]) -> Vec<IpcPairingState<'a>> {
    let handlers: Vec<&IpcRecord<'a>> = records.iter().filter(|r| is_main_handler(r)).collect();
    records
        .iter()
        .filter(|r| is_pairable(r))
        .map(|transmission| {
            let candidates: Vec<IpcRecord<'a>> = match &transmission.finding.channel {
                None => Vec::new(),
                Some(channel) => handlers
                    .iter()
                    .filter(|h| {
                        h.finding.channel.as_ref() == Some(channel)
                            && compatible_modes(transmission.finding, h.finding)
                    })
                    .map(|h| (*h).clone())
                    .collect(),
            };
            let status = match candidates.len() {
                1 => "paired",
                0 => "unpaired",
                _ => "ambiguous",
            };
            IpcPairingState { transmission: transmission.clone(), candidates, status }
        })
        .collect()
}

fn resolves_to_file(
    file: &ArtifactFile,
    specifier: &str,
    context: PathContext,
    files: &Files<'_>,
    kind: Option<FileKind>,
    module_kind: Option<ModuleKind>,
) -> bool {
    let mut input = ResolveInput::new(specifier, &file.path, context, files);
    input.module_kind = module_kind;
    match resolve_artifact_path_by_context(&input).resolved_path {
        None => false,
        Some(resolved) => kind.is_none_or(|k| files.get(&resolved).is_some_and(|f| f.kind == k)),
    }
}

/// Summarize static Electron findings without treating gaps as absence.
pub fn summarize_electron_boundaries(analysis: &ArtifactAnalysis) -> Value {
    let files = Files::new(analysis.files.iter().map(|a| &a.file));
    let javascript: Vec<_> = analysis.files.iter().filter_map(|a| a.javascript.as_ref()).collect();
    let windows: Vec<&ElectronBrowserWindowFinding> =
        javascript.iter().flat_map(|js| js.electron.browser_windows.iter()).collect();
    let bridges: Vec<&ElectronContextBridgeFinding> =
        javascript.iter().flat_map(|js| js.electron.context_bridge_apis.iter()).collect();
    let validations: usize = javascript.iter().map(|js| js.electron.sender_validations.len()).sum();
    let utilities: Vec<(&ArtifactFile, &ElectronUtilityProcessFinding)> = analysis
        .files
        .iter()
        .flat_map(|a| {
            a.javascript
                .iter()
                .flat_map(|js| js.electron.utility_processes.iter())
                .map(move |f| (&a.file, f))
        })
        .collect();
    let native: Vec<(&ArtifactFile, &ElectronNativeAddonBindingFinding)> = analysis
        .files
        .iter()
        .flat_map(|a| {
            a.javascript
                .iter()
                .flat_map(|js| js.electron.native_addon_bindings.iter())
                .map(move |f| (&a.file, f))
        })
        .collect();
    let ipc = collect_ipc_records(analysis);
    let pairing = classify_ipc_pairings(&ipc);
    let literal_channels: HashSet<&str> = ipc.iter().filter_map(|r| r.finding.channel.as_deref()).collect();
    json!({
        "browser_windows": windows.len(),
        "explicit_web_preferences": windows.iter().map(|w| w.web_preferences.len()).sum::<usize>(),
        "preload_entrypoints": windows.iter().filter(|w| w.preload_path.is_some()).count(),
        "context_bridge_apis": bridges.len(),
        "exposed_api_members": bridges.iter().map(|b| b.members.len()).sum::<usize>(),
        "ipc": {
            "operations": ipc.len(),
            "literal_channels": literal_channels.len(),
            "dynamic_channel_operations": ipc.iter().filter(|r| r.finding.channel.is_none()).count(),
            "renderer_transmissions": ipc.iter().filter(|r| is_renderer_transmission(r)).count(),
            "renderer_listeners": ipc.iter().filter(|r| r.finding.side == "renderer" && r.finding.mode == "listen").count(),
            "main_handlers": ipc.iter().filter(|r| is_main_handler(r)).count(),
            "paired_renderer_transmissions": pairing.iter().filter(|s| s.status == "paired").count(),
            "ambiguous_renderer_transmissions": pairing.iter().filter(|s| s.status == "ambiguous").count(),
            "unpaired_literal_renderer_transmissions": pairing
                .iter()
                .filter(|s| s.status == "unpaired" && s.transmission.finding.channel.is_some())
                .count(),
        },
        "sender_validation_observations": validations,
        "utility_processes": utilities.len(),
        "resolved_utility_entrypoints": utilities
            .iter()
            .filter(|(file, finding)| {
                finding.module_path.as_deref().is_some_and(|path| {
                    resolves_to_file(
                        file,
                        path,
                        PathContext::parse(finding.module_resolution_context.as_deref().unwrap_or("module-specifier")),
                        &files,
                        None,
                        None,
                    )
                })
            })
            .count(),
        "native_addon_bindings": native.len(),
        "resolved_native_addon_bindings": native
            .iter()
            .filter(|(file, finding)| {
                resolves_to_file(
                    file,
                    &finding.specifier,
                    PathContext::ModuleSpecifier,
                    &files,
                    Some(FileKind::NativeAddon),
                    Some(ModuleKind::parse(&finding.module_kind)),
                )
            })
            .count(),
    })
}

// ---- graph projection ------------------------------------------------------------------------

/// Add every static Electron process and security-boundary fact to the graph.
pub fn add_electron_boundaries(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    add_window_boundaries(ctx)?;
    add_ipc_boundaries(ctx)?;
    add_native_boundaries(ctx)
}

struct ElectronEdge<'a> {
    source: &'a NodeRef,
    target: &'a NodeRef,
    file: &'a ArtifactFile,
    range: &'a SourceRange,
    coverage: &'a Value,
    relation: &'a str,
    operation: &'a str,
    properties: Value,
    confidence: Option<&'a str>,
    limitations: &'a [String],
}

fn add_electron_ast_edge(ctx: &mut GraphContext<'_>, edge: ElectronEdge<'_>) -> Result<(), JsError> {
    ctx.acc.add_edge(
        &edge.source.node_id,
        &edge.target.node_id,
        edge.relation,
        edge.properties,
        ast_observation_evidence(
            &EvidenceInput::new(&edge.file.sha256, &edge.file.path, edge.operation, edge.coverage)
                .range(edge.range)
                .limitations(edge.limitations),
        ),
    )
}

fn add_electron_inference_edge(ctx: &mut GraphContext<'_>, edge: ElectronEdge<'_>) -> Result<(), JsError> {
    let mut input = EvidenceInput::new(&edge.file.sha256, &edge.file.path, edge.operation, edge.coverage)
        .range(edge.range)
        .limitations(edge.limitations);
    if let Some(confidence) = edge.confidence {
        input = input.confidence(confidence);
    }
    ctx.acc.add_edge(
        &edge.source.node_id,
        &edge.target.node_id,
        edge.relation,
        edge.properties,
        static_inference_evidence(&input),
    )
}

/// Resolve the file or recovered bundle module that owns one finding.
fn finding_source_node(
    ctx: &GraphContext<'_>,
    file: &ArtifactFile,
    module_key: Option<&str>,
    runtime: Option<&str>,
) -> Option<NodeRef> {
    match module_key {
        None => ctx
            .asset_nodes
            .get(&file.path)
            .or_else(|| ctx.file_nodes.get(&file.path))
            .cloned(),
        Some(key) => ctx.source_node_for(&file.path, Some(key), runtime),
    }
}

/// Observation-scoped identity shared safely across different artifact files.
fn observation_identity(ctx: &GraphContext<'_>, scope: &str, key: &str) -> Value {
    json!({
        "strategy": "observation-fingerprint",
        "stability": "observation-only",
        "observation_sha256": sha256_text(&format!("{}\0{scope}\0{key}", ctx.snapshot.manifest.root_sha256)),
        "scope": scope,
    })
}

fn range_key(range: &SourceRange) -> String {
    format!(
        "{}:{}-{}:{}",
        range.start.line, range.start.column, range.end.line, range.end.column
    )
}

fn point_cmp(left: &crate::jsgraph::ast::SourcePoint, right: &crate::jsgraph::ast::SourcePoint) -> i64 {
    if left.line == right.line {
        left.column as i64 - right.column as i64
    } else {
        left.line as i64 - right.line as i64
    }
}

fn range_contains(outer: &SourceRange, inner: &SourceRange) -> bool {
    point_cmp(&outer.start, &inner.start) <= 0 && point_cmp(&outer.end, &inner.end) >= 0
}

// ---- windows, bridges, utility processes ---------------------------------------------------

fn add_window_boundaries(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let Some(javascript) = &analyzed.javascript else {
            continue;
        };
        let coverage = javascript_analysis_coverage(javascript);
        for value in &javascript.electron.browser_windows {
            if let Some(source) = finding_source_node(ctx, file, value.module_key.as_deref(), value.module_runtime.as_deref()) {
                add_browser_window(ctx, file, &source, value, &coverage)?;
            }
        }
        for value in &javascript.electron.context_bridge_apis {
            if let Some(source) = finding_source_node(ctx, file, value.module_key.as_deref(), value.module_runtime.as_deref()) {
                add_context_bridge(ctx, file, &source, value, &coverage)?;
            }
        }
        for value in &javascript.electron.utility_processes {
            if let Some(source) = finding_source_node(ctx, file, value.module_key.as_deref(), value.module_runtime.as_deref()) {
                add_utility_process(ctx, file, &source, value, &coverage)?;
            }
        }
    }
    Ok(())
}

fn add_browser_window(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    source: &NodeRef,
    value: &ElectronBrowserWindowFinding,
    coverage: &Value,
) -> Result<(), JsError> {
    let key = range_key(&value.location);
    let limitations = vec![
        "Only explicitly present webPreferences are reported; omitted properties are not interpreted as Electron defaults."
            .to_string(),
    ];
    let window = ctx.acc.add_node(
        "browser-window",
        artifact_local_identity(&file.sha256, "electron-browser-window", &key),
        vec![ObservationInput::new(
            Some(format!("BrowserWindow@{key}")),
            json!({
                "source_path": file.path,
                "options_status": value.options_status,
                "web_preferences_status": value.web_preferences_status,
                "web_preferences": value.web_preferences,
                "preload_path": value.preload_path,
                "preload_resolution_context": value.preload_resolution_context,
                "absence_means_default": false,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-browser-window-construction", coverage)
                    .range(&value.location)
                    .limitations(&limitations),
            ),
        )],
    )?;
    add_electron_ast_edge(
        ctx,
        ElectronEdge {
            source,
            target: &window,
            file,
            range: &value.location,
            coverage,
            relation: "contains",
            operation: "locate-browser-window-construction",
            properties: json!({ "source_path": file.path }),
            confidence: None,
            limitations: &[],
        },
    )?;
    let Some(declared) = &value.preload_path else {
        return Ok(());
    };
    let context = PathContext::parse(value.preload_resolution_context.as_deref().unwrap_or("module-specifier"));
    let resolution = ctx.resolve_by_context(declared, &file.path, context);
    let role = ctx.create_electron_role_node(RoleNodeInput {
        kind: "electron-preload",
        anchor: file,
        resolution: &resolution,
        mechanism: "BrowserWindow:webPreferences.preload",
        range: Some(&value.location),
        coverage: Some(coverage),
    })?;
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source: &window,
            target: &role,
            file,
            range: &value.location,
            coverage,
            relation: "loads",
            operation: "associate-browser-window-preload",
            properties: json!({
                "declared_path": declared,
                "resolution_context": resolution.context.as_str(),
                "resolved_path": resolution.resolved_path,
                "resolution_status": resolution.status.as_str(),
                "limitations": resolution.limitations,
            }),
            confidence: None,
            limitations: &[],
        },
    )?;
    ctx.link_electron_role_to_asset(&role, file, &resolution, Some(&value.location), Some(coverage))
}

fn add_context_bridge(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    source: &NodeRef,
    value: &ElectronContextBridgeFinding,
    coverage: &Value,
) -> Result<(), JsError> {
    let api = value
        .api_key
        .clone()
        .or_else(|| value.api_key_expression.clone())
        .unwrap_or_else(|| "[missing]".to_string());
    let bridge = ctx.acc.add_node(
        "context-bridge-api",
        artifact_local_identity(
            &file.sha256,
            "electron-context-bridge",
            &format!("{}:{}:{}", value.world, api, range_key(&value.location)),
        ),
        vec![ObservationInput::new(
            value.api_key.clone(),
            json!({
                "world": value.world,
                "world_id": value.world_id,
                "api_key": value.api_key,
                "api_key_expression": value.api_key_expression,
                "api_status": value.api_status,
                "members": value.members,
                "unknown_members": value.unknown_members,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-context-bridge-api", coverage)
                    .range(&value.location),
            ),
        )],
    )?;
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source,
            target: &bridge,
            file,
            range: &value.location,
            coverage,
            relation: "exposes",
            operation: "map-context-bridge-exposure",
            properties: json!({
                "world": value.world,
                "api_key": value.api_key,
                "resolution": if value.api_key.is_none() { "dynamic" } else { "literal" },
            }),
            confidence: None,
            limitations: &[],
        },
    )
}

fn add_utility_process(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    source: &NodeRef,
    value: &ElectronUtilityProcessFinding,
    coverage: &Value,
) -> Result<(), JsError> {
    let launch = value
        .module_path
        .clone()
        .or_else(|| value.module_expression.clone())
        .unwrap_or_default();
    let utility = ctx.acc.add_node(
        "electron-utility",
        artifact_local_identity(
            &file.sha256,
            "electron-utility-process",
            &format!("{launch}:{}", range_key(&value.location)),
        ),
        vec![ObservationInput::new(
            value.service_name.clone().or_else(|| value.module_path.clone()),
            json!({
                "module_path": value.module_path,
                "module_resolution_context": value.module_resolution_context,
                "module_expression": value.module_expression,
                "service_name": value.service_name,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-utility-process-fork", coverage)
                    .range(&value.location),
            ),
        )],
    )?;
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source,
            target: &utility,
            file,
            range: &value.location,
            coverage,
            relation: "loads",
            operation: "map-utility-process-launch",
            properties: json!({
                "declared_path": value.module_path,
                "expression": value.module_expression,
            }),
            confidence: None,
            limitations: &[],
        },
    )?;
    let Some(module_path) = &value.module_path else {
        return Ok(());
    };
    let context = PathContext::parse(value.module_resolution_context.as_deref().unwrap_or("module-specifier"));
    let resolution = ctx.resolve_by_context(module_path, &file.path, context);
    let target = resolution
        .resolved_path
        .as_ref()
        .and_then(|p| ctx.asset_nodes.get(p).or_else(|| ctx.file_nodes.get(p)))
        .cloned();
    let Some(target) = target else {
        return Ok(());
    };
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source: &utility,
            target: &target,
            file,
            range: &value.location,
            coverage,
            relation: "maps_to",
            operation: "resolve-utility-process-entrypoint",
            properties: json!({
                "declared_path": module_path,
                "resolution_context": resolution.context.as_str(),
                "resolved_path": resolution.resolved_path,
                "resolution_status": resolution.status.as_str(),
            }),
            confidence: None,
            limitations: &[],
        },
    )
}

// ---- IPC -------------------------------------------------------------------------------------

fn coverage_for(ctx: &GraphContext<'_>, file: &ArtifactFile) -> Option<Value> {
    let javascript = ctx
        .analysis
        .files
        .iter()
        .find(|a| a.file.path == file.path)?
        .javascript
        .as_ref()?;
    Some(javascript_analysis_coverage(javascript))
}

fn add_ipc_boundaries(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    let records = collect_ipc_records(analysis);
    let mut handlers: HashMap<String, NodeRef> = HashMap::new();
    let mut sources: HashMap<String, NodeRef> = HashMap::new();
    for record in &records {
        let Some(coverage) = coverage_for(ctx, record.file) else {
            continue;
        };
        let Some(source) = finding_source_node(
            ctx,
            record.file,
            record.finding.module_key.as_deref(),
            record.finding.module_runtime.as_deref(),
        ) else {
            continue;
        };
        sources.insert(record.key.clone(), source.clone());
        let channel = add_channel_node(ctx, record, &coverage)?;
        if record.finding.mode == "listen" || record.finding.mode == "handle" {
            let handler = add_handler_node(ctx, record, &source, &channel, &coverage)?;
            handlers.insert(record.key.clone(), handler);
            continue;
        }
        let finding = record.finding;
        add_electron_inference_edge(
            ctx,
            ElectronEdge {
                source: &source,
                target: &channel,
                file: record.file,
                range: &finding.location,
                coverage: &coverage,
                relation: if finding.mode == "invoke" { "invokes" } else { "sends" },
                operation: "map-ipc-transmission",
                properties: json!({
                    "side": finding.side,
                    "operation": finding.operation,
                    "channel": finding.channel,
                    "channel_expression": finding.channel_expression,
                    "resolution": if finding.channel.is_none() { "dynamic" } else { "literal" },
                }),
                confidence: None,
                limitations: &[],
            },
        )?;
    }
    add_validation_observations(ctx, &records, &handlers)?;
    add_literal_pairings(ctx, &records, &handlers, &sources)
}

fn add_channel_node(
    ctx: &mut GraphContext<'_>,
    record: &IpcRecord<'_>,
    coverage: &Value,
) -> Result<NodeRef, JsError> {
    let finding = record.finding;
    let file = record.file;
    let identity_key = match &finding.channel {
        None => format!("dynamic:{}", record.key),
        Some(channel) => format!("literal:{channel}"),
    };
    let limitations: Vec<String> = if finding.channel.is_none() {
        vec!["The channel expression is dynamic; its runtime value and pairings remain unknown.".into()]
    } else {
        Vec::new()
    };
    let identity = observation_identity(ctx, "electron-ipc-channel", &identity_key);
    ctx.acc.add_node(
        "ipc-channel",
        identity,
        vec![ObservationInput::new(
            finding.channel.clone().or_else(|| finding.channel_expression.clone()),
            json!({
                "side": finding.side,
                "operation": finding.operation,
                "mode": finding.mode,
                "channel": finding.channel,
                "channel_expression": finding.channel_expression,
                "resolution": if finding.channel.is_none() { "dynamic" } else { "literal" },
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-ipc-channel-expression", coverage)
                    .range(&finding.location)
                    .limitations(&limitations),
            ),
        )],
    )
}

fn add_handler_node(
    ctx: &mut GraphContext<'_>,
    record: &IpcRecord<'_>,
    source: &NodeRef,
    channel: &NodeRef,
    coverage: &Value,
) -> Result<NodeRef, JsError> {
    let finding = record.finding;
    let file = record.file;
    let handler_range = finding.handler_location.unwrap_or(finding.location);
    let channel_text = finding
        .channel
        .clone()
        .or_else(|| finding.channel_expression.clone())
        .unwrap_or_default();
    let handler = ctx.acc.add_node(
        "ipc-handler",
        artifact_local_identity(
            &file.sha256,
            "electron-ipc-handler",
            &format!("{}:{}:{}:{}", finding.side, finding.operation, channel_text, range_key(&handler_range)),
        ),
        vec![ObservationInput::new(
            finding.channel.clone(),
            json!({
                "side": finding.side,
                "operation": finding.operation,
                "mode": finding.mode,
                "channel": finding.channel,
                "channel_expression": finding.channel_expression,
                "handler_kind": finding.handler_kind,
                "handler_location": finding.handler_location,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-ipc-handler", coverage)
                    .range(&handler_range),
            ),
        )],
    )?;
    add_electron_ast_edge(
        ctx,
        ElectronEdge {
            source,
            target: &handler,
            file,
            range: &handler_range,
            coverage,
            relation: "contains",
            operation: "locate-ipc-handler",
            properties: json!({ "side": finding.side, "operation": finding.operation }),
            confidence: None,
            limitations: &[],
        },
    )?;
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source: &handler,
            target: channel,
            file,
            range: &finding.location,
            coverage,
            relation: "handles",
            operation: "map-ipc-handler-registration",
            properties: json!({
                "channel": finding.channel,
                "channel_expression": finding.channel_expression,
                "resolution": if finding.channel.is_none() { "dynamic" } else { "literal" },
            }),
            confidence: None,
            limitations: &[],
        },
    )?;
    Ok(handler)
}

fn add_literal_pairings(
    ctx: &mut GraphContext<'_>,
    records: &[IpcRecord<'_>],
    handlers: &HashMap<String, NodeRef>,
    sources: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    for state in classify_ipc_pairings(records) {
        if state.status != "paired" {
            continue;
        }
        let handler_record = &state.candidates[0];
        let (Some(source), Some(handler)) =
            (sources.get(&state.transmission.key), handlers.get(&handler_record.key))
        else {
            continue;
        };
        let Some(coverage) = coverage_for(ctx, state.transmission.file) else {
            continue;
        };
        let finding = state.transmission.finding;
        let limitations = vec![
            "Literal channel equality does not prove that the handler is registered or reachable at runtime."
                .to_string(),
        ];
        add_electron_inference_edge(
            ctx,
            ElectronEdge {
                source,
                target: handler,
                file: state.transmission.file,
                range: &finding.location,
                coverage: &coverage,
                relation: if finding.mode == "invoke" { "invokes" } else { "sends" },
                operation: "pair-ipc-literal-channel",
                properties: json!({
                    "channel": finding.channel,
                    "pairing_basis": "unique-exact-literal-channel",
                    "handler_path": handler_record.file.path,
                    "handler_operation": handler_record.finding.operation,
                }),
                confidence: None,
                limitations: &limitations,
            },
        )?;
    }
    Ok(())
}

fn containing_handler<'a>(
    records: &[IpcRecord<'a>],
    file: &ArtifactFile,
    validation: &ElectronSenderValidationFinding,
) -> Option<IpcRecord<'a>> {
    let magnitude = |range: &Option<SourceRange>| -> i64 {
        match range {
            None => i64::MAX / 2,
            Some(r) => {
                (r.end.line as i64 - r.start.line as i64) * 1_000_000 + r.end.column as i64 - r.start.column as i64
            }
        }
    };
    let mut candidates: Vec<&IpcRecord<'a>> = records
        .iter()
        .filter(|record| {
            record.file.path == file.path
                && record
                    .finding
                    .handler_location
                    .as_ref()
                    .is_some_and(|loc| range_contains(loc, &validation.location))
        })
        .collect();
    candidates.sort_by_key(|record| magnitude(&record.finding.handler_location));
    candidates.first().map(|r| (*r).clone())
}

fn add_validation_observations(
    ctx: &mut GraphContext<'_>,
    records: &[IpcRecord<'_>],
    handlers: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let Some(javascript) = &analyzed.javascript else {
            continue;
        };
        let coverage = javascript_analysis_coverage(javascript);
        for validation in &javascript.electron.sender_validations {
            let target = match containing_handler(records, file, validation) {
                None => finding_source_node(
                    ctx,
                    file,
                    validation.module_key.as_deref(),
                    validation.module_runtime.as_deref(),
                ),
                Some(record) => handlers.get(&record.key).cloned(),
            };
            let Some(target) = target else {
                continue;
            };
            let limitations = vec![
                "A comparison or string check is visible, but static syntax alone does not prove rejection, ordering, or complete sender validation."
                    .to_string(),
            ];
            ctx.acc.add_node(
                &target.kind,
                target.identity.clone(),
                vec![ObservationInput::new(
                    Some(format!("{} validation candidate", validation.subject)),
                    json!({
                        "fact_kind": "sender-validation-candidate",
                        "subject": validation.subject,
                        "mechanism": validation.mechanism,
                        "expected": validation.expected,
                        "enforcement": validation.enforcement,
                    }),
                    ast_observation_evidence(
                        &EvidenceInput::new(
                            &file.sha256,
                            &file.path,
                            "observe-ipc-sender-validation-candidate",
                            &coverage,
                        )
                        .range(&validation.location)
                        .limitations(&limitations),
                    ),
                )],
            )?;
        }
    }
    Ok(())
}

// ---- native addons ---------------------------------------------------------------------------

fn add_native_boundaries(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let Some(javascript) = &analyzed.javascript else {
            continue;
        };
        let coverage = javascript_analysis_coverage(javascript);
        for value in &javascript.electron.native_addon_bindings {
            add_native_binding(ctx, file, value, &coverage)?;
        }
    }
    Ok(())
}

fn add_native_binding(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    value: &ElectronNativeAddonBindingFinding,
    coverage: &Value,
) -> Result<(), JsError> {
    let Some(source) = finding_source_node(ctx, file, value.module_key.as_deref(), value.module_runtime.as_deref())
    else {
        return Ok(());
    };
    let resolved = ctx.resolve_artifact_path(&value.specifier, &file.path, Some(ModuleKind::parse(&value.module_kind)));
    let addon = resolved.as_ref().and_then(|p| ctx.file_nodes.get(p)).cloned();
    let label = {
        let joined = value.members.iter().map(|m| display_text(m)).collect::<Vec<_>>().join(", ");
        if joined.is_empty() { value.specifier.clone() } else { joined }
    };
    let identity_key = composite_key(&[
        json!(file.path),
        json!(value.specifier),
        json!(value.binding_kind),
        json!(value.members),
        json!(value.namespace_access),
        json!(value.dynamic_member_access),
        json!(range_key(&value.location)),
    ]);
    let identity = observation_identity(ctx, "javascript-requested-native-export", &identity_key);
    let limitations = vec![
        "JavaScript syntax identifies requested member names; it does not prove that the native binary exports or implements them."
            .to_string(),
    ];
    let binding = ctx.acc.add_node(
        "native-export",
        identity,
        vec![ObservationInput::new(
            Some(label),
            json!({
                "specifier": value.specifier,
                "binding_kind": value.binding_kind,
                "requested_members": value.members,
                "namespace_access": value.namespace_access,
                "dynamic_member_access": value.dynamic_member_access,
                "resolved_path": resolved,
                "native_export_verification": "not-performed",
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "observe-native-addon-binding", coverage)
                    .range(&value.location)
                    .limitations(&limitations),
            ),
        )],
    )?;
    let limitations = vec!["Requested JavaScript members are not verified native exports.".to_string()];
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source: &source,
            target: &binding,
            file,
            range: &value.location,
            coverage,
            relation: if value.binding_kind == "re-export" { "exposes" } else { "imports" },
            operation: "map-native-addon-binding",
            properties: json!({
                "specifier": value.specifier,
                "binding_kind": value.binding_kind,
                "requested_members": value.members,
                "namespace_access": value.namespace_access,
                "dynamic_member_access": value.dynamic_member_access,
            }),
            confidence: None,
            limitations: &limitations,
        },
    )?;
    let (Some(addon), Some(resolved)) = (addon, resolved) else {
        return Ok(());
    };
    let limitations = vec![
        "The .node artifact path is resolved, but requested JavaScript members have not been verified against native symbols."
            .to_string(),
    ];
    add_electron_inference_edge(
        ctx,
        ElectronEdge {
            source: &addon,
            target: &binding,
            file,
            range: &value.location,
            coverage,
            relation: "exposes",
            operation: "associate-native-addon-requested-exports",
            properties: json!({
                "resolved_path": resolved,
                "requested_members": value.members,
                "namespace_access": value.namespace_access,
                "dynamic_member_access": value.dynamic_member_access,
                "verified": false,
            }),
            confidence: Some("medium"),
            limitations: &limitations,
        },
    )
}
