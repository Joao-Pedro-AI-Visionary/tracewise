//! Inline scenarios for the static layer. The oracle (REA) produces the expected output; these only
//! have to reach the code paths. Most come from the REA unit tests of the static layer
//! (`electronNativeLoaderPaths`, `electronStaticAnalysisOptions`, `javascriptStaticAnalysis.*`,
//! `javascriptStaticPathResolution`, `JavaScriptFileUrlPaths`, `JavaScriptOpenClassification`), the
//! rest are combinatorial sweeps over callee names and argument shapes.

mod electron;
mod network;
mod bundlers;
mod paths;
mod comments;
pub mod gaps;

/// All snippets as `(file name, source)`.
pub fn all() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    out.extend(electron::snippets());
    out.extend(network::snippets());
    out.extend(bundlers::snippets());
    out.extend(paths::snippets());
    out.extend(comments::snippets());
    out.extend(gaps::snippets());
    out
}

pub(crate) fn named(prefix: &str, sources: &[&str]) -> Vec<(String, String)> {
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("{prefix}{index:03}.js"), (*source).to_string()))
        .collect()
}
