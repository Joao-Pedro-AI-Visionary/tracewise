//! Per-file artifact analysis (REA `JavaScriptArtifactAnalysis.ts`, `JavaScriptJsonModules.ts`):
//! package metadata, JSON modules, HTML script references, source maps, and the JavaScript
//! layers (static analysis and semantic IR) behind a seam.

use serde_json::Value;

use crate::error::JsError;
use crate::jsgraph::error::{AnalysisFailure, ArtifactFailure};
use crate::jsgraph::control::{catch_cancellation, Cancel};
use crate::jsgraph::ir::SemanticIr;
use crate::jsgraph::static_types::StaticAnalysis;
use crate::jsgraph::util::{compare_code_points, sha256_text};

use super::html::html_artifact_references;
use super::model::{
    AnalyzedFile, ArtifactAnalysis, ArtifactFile, FileKind, FileSet, HtmlScriptObservation,
    JsonModuleObservation, ModuleSemanticIr, PackageObservation, SourceMapObservation,
    SourceMapOriginal,
};
use crate::jsgraph::ast::{SourcePoint, SourceRange};

/// Result of analyzing one JavaScript/TypeScript file with the producer layers.
pub struct JsFileResult {
    /// `None` when the source could not be parsed at all (`parseJavaScriptSource` returned null).
    pub parsed: Option<ParsedFile>,
}

pub struct ParsedFile {
    pub static_analysis: StaticAnalysis,
    /// Present when the static analysis is `complete` or `partial`.
    pub ir: Option<SemanticIr>,
}

/// The seam between the application analysis and the per-file analysis layers.
pub trait FileAnalyzer {
    fn analyze_javascript(&self, file: &ArtifactFile, source: &str) -> Result<JsFileResult, AnalysisFailure>;

    /// Interpret one source-map `sources` entry (`resolveJavaScriptSourceMapReference`).
    fn source_map_reference(&self, source_name: &str, source_root: Option<&str>, map_path: &str) -> Value;
}

/// Receives each file's full IR while it is still file-local (the semantic graph projection).
pub trait SemanticSink {
    fn project_file(&mut self, file: &ArtifactFile, ir: &SemanticIr) -> Result<(), JsError>;
}

/// A sink that ignores the IR.
pub struct NoSemanticSink;

impl SemanticSink for NoSemanticSink {
    fn project_file(&mut self, _file: &ArtifactFile, _ir: &SemanticIr) -> Result<(), JsError> {
        Ok(())
    }
}

/// Analyze every text source from the artifact without a result quota.
pub fn analyze_artifact_files(
    file_set: &FileSet,
    analyzer: &dyn FileAnalyzer,
    sink: &mut dyn SemanticSink,
    cancel: &Cancel,
) -> Result<ArtifactAnalysis, AnalysisFailure> {
    let mut state = ArtifactAnalysis::default();
    for file in &file_set.files {
        cancel.check()?;
        analyze_file(file, analyzer, sink, &mut state, cancel)?;
    }
    state.findings += state.html_scripts.len() as u64;
    state.limitations = vec![
        "JavaScript and HTML were parsed as inert text; bundle bootstrap code was never executed.".into(),
        "Static paths and relationships may remain unresolved when expressions are dynamic or obfuscated.".into(),
    ];
    Ok(state)
}

fn analyze_file(
    file: &ArtifactFile,
    analyzer: &dyn FileAnalyzer,
    sink: &mut dyn SemanticSink,
    state: &mut ArtifactAnalysis,
    cancel: &Cancel,
) -> Result<(), AnalysisFailure> {
    add_structured_observations(file, state);
    if file.kind == FileKind::Html {
        if let Some(text) = &file.text {
            state.html_scripts.extend(parse_html_scripts(&file.path, text));
        }
    }
    if file.kind == FileKind::SourceMap {
        state.source_maps.push(parse_source_map(file, analyzer));
    }
    if file.kind != FileKind::Javascript || file.text.is_none() {
        state.files.push(AnalyzedFile { file: file.clone(), javascript: None, semantic: None });
        return Ok(());
    }
    let source = file.text.as_deref().unwrap_or_default();
    // The per-file passes check the cancellation every 1024 visited nodes (REA does the same).
    let result = match catch_cancellation(cancel, || analyzer.analyze_javascript(file, source)) {
        Ok(result) => result?,
        Err(_) => return Err(AnalysisFailure::Artifact { reason: ArtifactFailure::Cancelled }),
    };
    let Some(parsed) = result.parsed else {
        state.files.push(AnalyzedFile {
            file: file.clone(),
            javascript: Some(StaticAnalysis::failed()),
            semantic: None,
        });
        state.parse_failures += 1;
        return Ok(());
    };
    let analysis = parsed.static_analysis;
    let static_findings = finding_count(&analysis);
    let mut module_links = 0u64;
    let semantic = match parsed.ir {
        Some(ir) => {
            sink.project_file(file, &ir)?;
            module_links = ir.module_links.len() as u64;
            Some(trim_semantic_ir(ir))
        }
        None => None,
    };
    state.visited_ast_nodes += analysis.visited_ast_nodes;
    state.findings += static_findings + module_links;
    state.modules += analysis
        .bundler_registrations
        .iter()
        .map(|registration| registration.modules.len() as u64)
        .sum::<u64>();
    if analysis.parse_status == "failed" {
        state.parse_failures += 1;
    }
    state.files.push(AnalyzedFile { file: file.clone(), javascript: Some(analysis), semantic });
    Ok(())
}

/// REA `projectFileSemantics`: keep the program scope and what module relationships need.
fn trim_semantic_ir(ir: SemanticIr) -> ModuleSemanticIr {
    let program_scopes: Vec<_> = ir.scopes.iter().filter(|s| s.kind == "program").cloned().collect();
    let program_scope_id = program_scopes.first().map(|s| s.scope_id.clone());
    let local_names: std::collections::HashSet<&str> = ir
        .module_links
        .iter()
        .filter_map(|link| link.local_name.as_deref())
        .collect();
    let callable_ids: std::collections::HashSet<&str> = ir
        .module_links
        .iter()
        .filter_map(|link| link.callable_id.as_deref())
        .collect();
    let bindings = ir
        .bindings
        .iter()
        .filter(|b| Some(&b.scope_id) == program_scope_id.as_ref() && local_names.contains(b.name.as_str()))
        .cloned()
        .collect();
    let callables = ir
        .callables
        .iter()
        .filter(|c| callable_ids.contains(c.callable_id.as_str()))
        .cloned()
        .collect();
    ModuleSemanticIr {
        scopes: program_scopes,
        bindings,
        callables,
        module_links: ir.module_links,
        coverage: Some(ir.coverage),
        limitations: ir.limitations,
    }
}

fn finding_count(analysis: &StaticAnalysis) -> u64 {
    let electron = &analysis.electron;
    (analysis.references.len()
        + analysis.endpoints.len()
        + analysis.storage.len()
        + analysis.role_paths.len()
        + analysis.source_map_urls.len()
        + analysis.bundler_registrations.len()
        + electron.browser_windows.len()
        + electron.context_bridge_apis.len()
        + electron.ipc.len()
        + electron.sender_validations.len()
        + electron.utility_processes.len()
        + electron.native_addon_bindings.len()) as u64
}

// ---- structured observations ---------------------------------------------------------------

fn add_structured_observations(file: &ArtifactFile, state: &mut ArtifactAnalysis) {
    if file.kind == FileKind::PackageJson {
        state.packages.push(parse_package(file));
    }
    if file.kind != FileKind::Json {
        return;
    }
    let json = analyze_json_module(file);
    if json.status == "invalid" {
        state.parse_failures += 1;
    }
    state.json_modules.push(json);
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn parse_package(file: &ArtifactFile) -> PackageObservation {
    let unavailable = |status: &'static str, limitation: &str| PackageObservation {
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        status,
        name: None,
        version: None,
        main: None,
        renderer: None,
        limitation: Some(limitation.to_string()),
    };
    let Some(text) = &file.text else {
        return unavailable("unavailable", "Package metadata text was unavailable.");
    };
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return unavailable("invalid", "package.json is not valid JSON."),
    };
    let Value::Object(map) = &value else {
        return unavailable("invalid", "package.json root is not an object.");
    };
    PackageObservation {
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        status: "included",
        name: optional_string(map.get("name")),
        version: optional_string(map.get("version")),
        main: optional_string(map.get("main")),
        renderer: optional_string(map.get("renderer"))
            .or_else(|| optional_string(map.get("browser")))
            .or_else(|| optional_string(map.get("module"))),
        limitation: None,
    }
}

/// Parse one approved JSON module without evaluating JavaScript or resolving imports.
pub fn analyze_json_module(file: &ArtifactFile) -> JsonModuleObservation {
    let Some(text) = &file.text else {
        return JsonModuleObservation {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
            status: "unavailable",
            top_level_keys: Vec::new(),
            omitted_top_level_keys: None,
            limitation: Some(format!(
                "JSON module text was unavailable: {}.",
                file.text_reason.unwrap_or("not-applicable")
            )),
        };
    };
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return JsonModuleObservation {
                path: file.path.clone(),
                sha256: file.sha256.clone(),
                status: "invalid",
                top_level_keys: Vec::new(),
                omitted_top_level_keys: Some(0),
                limitation: Some("JSON module is not valid JSON.".into()),
            }
        }
    };
    let mut keys: Vec<String> = match &value {
        Value::Object(map) => map.keys().cloned().collect(),
        _ => Vec::new(),
    };
    keys.sort_by(|a, b| compare_code_points(a, b));
    JsonModuleObservation {
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        status: "included",
        top_level_keys: keys,
        omitted_top_level_keys: Some(0),
        limitation: None,
    }
}

// ---- HTML ----------------------------------------------------------------------------------

fn parse_html_scripts(path: &str, text: &str) -> Vec<HtmlScriptObservation> {
    let references = html_artifact_references(text);
    references
        .scripts
        .into_iter()
        .map(|script| HtmlScriptObservation {
            html_path: path.to_string(),
            script_path: script.script_path,
            base_href: references.base_href.clone(),
            location: SourceRange {
                start: point_for_offset(text, script.start_offset),
                end: point_for_offset(text, script.end_offset),
            },
        })
        .collect()
}

/// `pointForOffset`: lines split on `\r\n|\r|\n`, column in UTF-16 units.
fn point_for_offset(text: &str, offset16: usize) -> SourcePoint {
    let mut line = 1u32;
    let mut column = 0u32;
    let mut units = 0usize;
    let mut previous_cr = false;
    for ch in text.chars() {
        if units >= offset16 {
            break;
        }
        match ch {
            '\n' if previous_cr => {
                // `\r\n` counted as one break: the `\r` already started the new line.
                previous_cr = false;
            }
            '\n' => {
                line += 1;
                column = 0;
            }
            '\r' => {
                line += 1;
                column = 0;
                previous_cr = true;
            }
            _ => {
                column += ch.len_utf16() as u32;
                previous_cr = false;
            }
        }
        if ch != '\r' {
            previous_cr = false;
        }
        units += ch.len_utf16();
    }
    SourcePoint { line, column }
}

// ---- source maps ---------------------------------------------------------------------------

fn parse_source_map(file: &ArtifactFile, analyzer: &dyn FileAnalyzer) -> SourceMapObservation {
    let invalid = |limitation: &str| SourceMapObservation {
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        status: "invalid",
        sources: Vec::new(),
        limitation: Some(limitation.to_string()),
    };
    let Some(text) = &file.text else {
        return invalid("Source-map text could not be decoded as UTF-8.");
    };
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return invalid("Source map is not valid JSON."),
    };
    let Some(maps) = flatten_source_map_leaves(&value) else {
        return invalid("Source map is not a version 3 map.");
    };
    let mut sources = Vec::new();
    for map in maps {
        let Some(names) = map.get("sources").and_then(Value::as_array) else {
            return invalid("Source map has no sources array.");
        };
        let contents = map.get("sourcesContent");
        if !has_valid_source_map_contents(names.len(), contents) {
            return invalid(
                "Source map sourcesContent must contain one string or null entry per source.",
            );
        }
        let root = match map.get("sourceRoot") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => return invalid("Source map sourceRoot must be a string or null."),
        };
        for (index, raw) in names.iter().enumerate() {
            let Value::String(name) = raw else {
                return invalid("Source map contains a non-string source name.");
            };
            let content = contents
                .and_then(Value::as_array)
                .and_then(|items| items.get(index))
                .and_then(Value::as_str)
                .map(str::to_string);
            let reference = analyzer.source_map_reference(name, root.as_deref(), &file.path);
            sources.push(SourceMapOriginal {
                reference,
                source_name: name.clone(),
                source_root: root.clone(),
                content_sha256: content.as_deref().map(sha256_text),
                content,
            });
        }
    }
    SourceMapObservation {
        path: file.path.clone(),
        sha256: file.sha256.clone(),
        status: "included",
        sources,
        limitation: None,
    }
}

fn has_valid_source_map_contents(source_count: usize, contents: Option<&Value>) -> bool {
    match contents {
        None => true,
        Some(Value::Array(items)) => {
            items.len() == source_count && items.iter().all(|c| c.is_null() || c.is_string())
        }
        Some(_) => false,
    }
}

/// `flattenSourceMapLeaves` (stack order: later sections are visited first).
fn flatten_source_map_leaves(root: &Value) -> Option<Vec<&serde_json::Map<String, Value>>> {
    fn is_v3(value: &Value) -> Option<&serde_json::Map<String, Value>> {
        let map = value.as_object()?;
        (map.get("version").and_then(Value::as_f64) == Some(3.0)).then_some(map)
    }
    is_v3(root)?;
    let mut leaves = Vec::new();
    let mut pending: Vec<&Value> = vec![root];
    while let Some(value) = pending.pop() {
        let map = is_v3(value)?;
        if let Some(sections) = map.get("sections").and_then(Value::as_array) {
            for section in sections {
                let section = section.as_object()?;
                let inner = section.get("map")?;
                inner.as_object()?;
                pending.push(inner);
            }
        } else {
            leaves.push(map);
        }
    }
    Some(leaves)
}
