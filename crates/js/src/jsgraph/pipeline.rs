//! The native analysis pipeline: parse (Babel-shaped tree) -> static analysis -> semantic IR ->
//! application graph -> semantic graph, behind REA's `reconstructJavaScriptArtifact` contract.

use serde_json::Value;

use super::app_graph::analysis::{FileAnalyzer, JsFileResult, ParsedFile};
use super::app_graph::model::ArtifactFile;
use super::app_graph::reconstruct::reconstruct_application;
use super::ast::{parse_babel, ConvertError, ParseOptions};
use super::control::Cancel;
use super::error::AnalysisFailure;
use super::semantic;
use super::semantic_graph::SemanticGraphProjection;
use super::static_analysis;

/// Syntax-tree depth the converted tree and the recursive analyses are sized for. Deeper trees
/// that still parse (very long `a.b.c...` or `1+1+...` chains) are refused with a structured error.
pub use super::ast::MAX_AST_DEPTH;

/// Stack of the analysis thread. The parse tree conversion and the semantic passes recurse over
/// the syntax tree; the stack is reserved virtually and only touched as deep as the input goes.
const ANALYSIS_STACK_BYTES: usize = 768 * 1024 * 1024;

/// Analyzer backed by this crate's own ports of the REA layers.
pub struct NativeAnalyzer;

impl FileAnalyzer for NativeAnalyzer {
    fn analyze_javascript(&self, file: &ArtifactFile, source: &str) -> Result<JsFileResult, AnalysisFailure> {
        let ast = match parse_babel(source, &ParseOptions { path: Some(&file.path) }) {
            Ok(ast) => ast,
            // Babel would throw (or overflow its stack on hostile nesting): REA records a parse
            // failure for the file.
            Err(ConvertError::Unparseable(_)) => return Ok(JsFileResult { parsed: None }),
            Err(ConvertError::Unsupported(what)) => {
                return Err(AnalysisFailure::Unsupported {
                    what: format!("JavaScript syntax ({what}) in {} is not converted by this port", file.path),
                })
            }
            Err(ConvertError::TooDeep(_)) => {
                return Err(AnalysisFailure::Unsupported {
                    what: format!(
                        "JavaScript syntax tree of {} is nested deeper than {MAX_AST_DEPTH} levels, which this port does not analyze",
                        file.path
                    ),
                })
            }
        };
        let open_receivers = semantic::classify_open_receivers(&ast);
        let electron_bindings = semantic::classify_electron_bindings(&ast);
        let static_analysis =
            static_analysis::analyze_static_source(source, &ast, &open_receivers, &electron_bindings);
        let ir = match static_analysis.parse_status.as_str() {
            "complete" | "partial" => Some(semantic::analyze_semantics(&ast)),
            _ => None,
        };
        Ok(JsFileResult { parsed: Some(ParsedFile { static_analysis, ir }) })
    }

    fn source_map_reference(&self, source_name: &str, source_root: Option<&str>, map_path: &str) -> Value {
        serde_json::to_value(static_analysis::resolve_source_map_reference(source_name, source_root, map_path))
            .unwrap_or(Value::Null)
    }
}

/// Reconstruct one local ASAR or extracted directory (REA `reconstructJavaScriptArtifact`).
pub fn reconstruct_javascript_application(
    input_path: &str,
    format: &str,
    integrity_policy: &str,
    cancel: &Cancel,
) -> Result<Value, AnalysisFailure> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("jsgraph-analysis".into())
            .stack_size(ANALYSIS_STACK_BYTES)
            .spawn_scoped(scope, || {
                reconstruct_application(
                    input_path,
                    format,
                    integrity_policy,
                    &NativeAnalyzer,
                    Box::new(SemanticGraphProjection::new()),
                    cancel,
                )
            })
            .map_err(|error| AnalysisFailure::Other(crate::error::JsError::Io(error.to_string())))?
            .join()
            .unwrap_or_else(|_| {
                Err(AnalysisFailure::Other(crate::error::JsError::Io(
                    "JavaScript application analysis worker panicked".into(),
                )))
            })
    })
}
