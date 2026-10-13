//! Data model between file reading, per-file analysis and graph construction
//! (REA `javascriptArtifactFiles.ts`, `JavaScriptArtifactAnalysisTypes.ts`).

use serde_json::Value;

use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::ir::{
    SemanticBinding, SemanticCallable, SemanticCoverage, SemanticModuleLink, SemanticScope,
};
use crate::jsgraph::static_types::StaticAnalysis;

/// Relevant file categories projected from the complete artifact inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    PackageJson,
    Json,
    Javascript,
    Html,
    SourceMap,
    NativeAddon,
}

impl FileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::PackageJson => "package-json",
            FileKind::Json => "json",
            FileKind::Javascript => "javascript",
            FileKind::Html => "html",
            FileKind::SourceMap => "source-map",
            FileKind::NativeAddon => "native-addon",
        }
    }

    /// REA `relevantKind(path)`.
    pub fn for_path(path: &str) -> Option<FileKind> {
        let lower = path.to_lowercase();
        if lower == "package.json" || lower.ends_with("/package.json") {
            return Some(FileKind::PackageJson);
        }
        if lower.ends_with(".json") {
            return Some(FileKind::Json);
        }
        for extension in [".cjs", ".cts", ".mjs", ".mts", ".js", ".jsx", ".ts", ".tsx"] {
            if lower.ends_with(extension) {
                return Some(FileKind::Javascript);
            }
        }
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            return Some(FileKind::Html);
        }
        if lower.ends_with(".map") {
            return Some(FileKind::SourceMap);
        }
        if lower.ends_with(".node") {
            return Some(FileKind::NativeAddon);
        }
        None
    }
}

/// One content-addressed local artifact file and its text availability.
#[derive(Clone, Debug)]
pub struct ArtifactFile {
    pub path: String,
    pub container_sha256: String,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_artifact_id: String,
    pub kind: FileKind,
    pub unpacked: bool,
    /// Decoded text (`text.included`); `None` when unavailable.
    pub text: Option<String>,
    /// `not-applicable` or `invalid-utf8` when the text is unavailable.
    pub text_reason: Option<&'static str>,
}

/// One filesystem-backed ASAR nested beneath a directory input.
#[derive(Clone, Debug)]
pub struct ArtifactContainer {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_artifact_id: String,
}

/// Deterministic relevant-file projection plus explicit omissions.
#[derive(Clone, Debug, Default)]
pub struct FileSet {
    pub files: Vec<ArtifactFile>,
    pub containers: Vec<ArtifactContainer>,
    pub text_bytes_read: u64,
    pub invalid_utf8_files: u64,
}

/// Parsed package metadata used only for static entrypoint discovery.
#[derive(Clone, Debug)]
pub struct PackageObservation {
    pub path: String,
    pub sha256: String,
    /// `included`, `invalid`, `unavailable`.
    pub status: &'static str,
    pub name: Option<String>,
    pub version: Option<String>,
    pub main: Option<String>,
    pub renderer: Option<String>,
    pub limitation: Option<String>,
}

/// One HTML script source observed without building or executing a DOM.
#[derive(Clone, Debug)]
pub struct HtmlScriptObservation {
    pub html_path: String,
    pub script_path: String,
    pub base_href: Option<String>,
    pub location: SourceRange,
}

/// Local source-map original declaration.
#[derive(Clone, Debug)]
pub struct SourceMapOriginal {
    /// The map-scoped reference object (`javascriptSourceMapReferenceSchema`).
    pub reference: Value,
    pub source_name: String,
    pub source_root: Option<String>,
    pub content: Option<String>,
    pub content_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SourceMapObservation {
    pub path: String,
    pub sha256: String,
    /// `included` or `invalid`.
    pub status: &'static str,
    pub sources: Vec<SourceMapOriginal>,
    pub limitation: Option<String>,
}

/// Parse status for one inventoried JSON module.
#[derive(Clone, Debug)]
pub struct JsonModuleObservation {
    pub path: String,
    pub sha256: String,
    /// `included`, `invalid`, `unavailable`.
    pub status: &'static str,
    pub top_level_keys: Vec<String>,
    pub omitted_top_level_keys: Option<u64>,
    pub limitation: Option<String>,
}

/// Module facts needed after file-local semantic projection has finished
/// (`JavaScriptModuleSemanticIr`).
#[derive(Clone, Debug, Default)]
pub struct ModuleSemanticIr {
    pub scopes: Vec<SemanticScope>,
    pub bindings: Vec<SemanticBinding>,
    pub callables: Vec<SemanticCallable>,
    pub module_links: Vec<SemanticModuleLink>,
    pub coverage: Option<SemanticCoverage>,
    pub limitations: Vec<String>,
}

/// One relevant file plus optional AST-only JavaScript facts.
#[derive(Clone, Debug)]
pub struct AnalyzedFile {
    pub file: ArtifactFile,
    pub javascript: Option<StaticAnalysis>,
    pub semantic: Option<ModuleSemanticIr>,
}

/// Complete static-analysis projection before graph construction.
#[derive(Clone, Debug, Default)]
pub struct ArtifactAnalysis {
    pub files: Vec<AnalyzedFile>,
    pub packages: Vec<PackageObservation>,
    pub json_modules: Vec<JsonModuleObservation>,
    pub html_scripts: Vec<HtmlScriptObservation>,
    pub source_maps: Vec<SourceMapObservation>,
    pub visited_ast_nodes: u64,
    pub findings: u64,
    pub modules: u64,
    pub parse_failures: u64,
    pub limitations: Vec<String>,
}
