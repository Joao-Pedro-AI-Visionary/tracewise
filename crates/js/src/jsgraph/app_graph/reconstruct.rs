//! Application reconstruction orchestration (REA `JavaScriptArtifactReconstruction.ts`):
//! input selection, inventory, file reading, per-file analysis, application graph, semantic graph.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::error::JsError;
use crate::inventory::scan_artifact_inventory_with_policy;
use crate::jsgraph::control::Cancel;
use crate::jsgraph::error::{AnalysisFailure, ArtifactFailure};

use super::analysis::{analyze_artifact_files, FileAnalyzer, SemanticSink};
use super::build::build_application_graph;
use super::electron::summarize_electron_boundaries;
use super::files::read_artifact_files;

/// Builds the semantic graph from the per-file IR it receives while files are analyzed.
pub trait SemanticGraphBuilder: SemanticSink {
    /// Seal the semantic graph against the finished application graph.
    fn finish(self: Box<Self>, root_artifact_sha256: &str, application_graph: &Value) -> Result<Value, JsError>;
}

fn resolve_selected_input(input_path: &str) -> Result<PathBuf, AnalysisFailure> {
    let fail = |error: &std::io::Error| -> AnalysisFailure {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::NotFound => AnalysisFailure::Input {
                path: "input_path",
                message: format!(
                    "No file or directory exists at the selected input path (ENOENT): {input_path}"
                ),
                expected: None,
            },
            ErrorKind::PermissionDenied => AnalysisFailure::AccessDenied {
                path: input_path.to_string(),
                system_code: "EACCES".into(),
            },
            _ => match error.raw_os_error() {
                Some(20) => AnalysisFailure::Input {
                    path: "input_path",
                    message: format!(
                        "No file or directory exists at the selected input path (ENOTDIR): {input_path}"
                    ),
                    expected: None,
                },
                _ => AnalysisFailure::Artifact { reason: ArtifactFailure::Io },
            },
        }
    };
    let path = std::fs::canonicalize(input_path).map_err(|e| fail(&e))?;
    // `access(R_OK)`
    std::fs::metadata(&path).map_err(|e| fail(&e))?;
    Ok(path)
}

fn resolve_format(path: &Path, input_path: &str, requested: &str) -> Result<&'static str, AnalysisFailure> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| AnalysisFailure::from(JsError::from(e)))?;
    let observed = if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() && path.to_string_lossy().to_lowercase().ends_with(".asar") {
        "asar"
    } else {
        return Err(AnalysisFailure::UnsupportedTarget {
            path: input_path.to_string(),
            reason: "JavaScript application analysis accepts only a directory or an .asar file".into(),
            remediation: "Select an extracted application directory, an app bundle, or an .asar file such as Contents/Resources/app.asar.".into(),
        });
    };
    if requested != "auto" && requested != observed {
        return Err(AnalysisFailure::Input {
            path: "format",
            message: format!(
                "Requested {requested} input, but the selected input is {}: {input_path}",
                if observed == "asar" { "an .asar file" } else { "a directory" }
            ),
            expected: Some(vec!["auto".into(), observed.into()]),
        });
    }
    Ok(observed)
}

/// Reconstruct one local ASAR or extracted directory without executing code.
pub fn reconstruct_application(
    input_path: &str,
    requested_format: &str,
    integrity_policy: &str,
    analyzer: &dyn FileAnalyzer,
    semantic: Box<dyn SemanticGraphBuilder>,
    cancel: &Cancel,
) -> Result<Value, AnalysisFailure> {
    cancel.check()?;
    let path = resolve_selected_input(input_path)?;
    let format = resolve_format(&path, input_path, requested_format)?;
    let inventory = scan_artifact_inventory_with_policy(&path, integrity_policy)?;
    cancel.check()?;
    if inventory.manifest.root_format != format {
        return Err(AnalysisFailure::Artifact { reason: ArtifactFailure::Format });
    }
    let file_set = read_artifact_files(&path, &inventory, cancel)?;
    cancel.check()?;
    let mut semantic = semantic;
    let analysis = analyze_artifact_files(&file_set, analyzer, semantic.as_mut(), cancel)?;
    cancel.check()?;
    let graph = build_application_graph(&inventory, &file_set, &analysis, cancel)?;
    cancel.check()?;
    let semantic_graph = semantic.finish(&inventory.manifest.root_sha256, &graph)?;
    cancel.check()?;
    let summary = summarize_electron_boundaries(&analysis);
    let parsed_files = analysis.files.iter().filter(|f| f.javascript.is_some()).count();
    let limitations = graph["limitations"].clone();
    Ok(json!({
        "input_path": path.to_string_lossy(),
        "format": format,
        "root_artifact_sha256": inventory.manifest.root_sha256,
        "inventory_manifest_id": inventory.manifest.manifest_id,
        "inventory_graph_sha256": inventory.manifest.graph_sha256,
        "integrity_contradictions": inventory.integrity_contradictions,
        "graph": graph,
        "summary": summary,
        "statistics": {
            "relevant_files": file_set.files.len(),
            "nested_asar_containers": file_set.containers.len(),
            "text_bytes_read": file_set.text_bytes_read,
            "invalid_utf8_files": file_set.invalid_utf8_files,
            "parsed_javascript_files": parsed_files,
            "visited_ast_nodes": analysis.visited_ast_nodes,
            "findings": analysis.findings,
            "modules": analysis.modules,
            "parse_failures": analysis.parse_failures,
        },
        "limitations": limitations,
        "semantic_graph": semantic_graph,
    }))
}
