//! Port of `javascriptSemanticProvenance.ts`.

use crate::jsgraph::ir::{BindingProvenance, ModuleOrigin};
use crate::jsgraph::util::OrderedMap;

use super::primitives::json_string;

/// Construct exact local provenance without inventing module origins.
pub fn semantic_local_provenance() -> BindingProvenance {
    BindingProvenance { status: "local".into(), origins: Vec::new(), reason: None }
}

/// Construct an unresolved provenance outcome with an actionable reason (`unknown` or `cycle`).
pub fn semantic_unresolved_provenance(status: &str, reason: impl Into<String>) -> BindingProvenance {
    BindingProvenance { status: status.into(), origins: Vec::new(), reason: Some(reason.into()) }
}

/// Construct ambiguous provenance while retaining every origin.
pub fn semantic_ambiguous_provenance(
    origins: Vec<ModuleOrigin>,
    reason: impl Into<String>,
) -> BindingProvenance {
    BindingProvenance { status: "ambiguous".into(), origins, reason: Some(reason.into()) }
}

/// Normalize exact module origins into one provenance classification.
pub fn semantic_origins_provenance(origins: &[ModuleOrigin]) -> BindingProvenance {
    let mut unique = unique_semantic_origins(origins);
    if unique.len() == 1 {
        BindingProvenance {
            status: "module".into(),
            origins: vec![unique.remove(0)],
            reason: None,
        }
    } else {
        semantic_ambiguous_provenance(unique, "Multiple module origins.")
    }
}

/// `JSON.stringify([specifier, importedPath])`.
fn semantic_origin_key(origin: &ModuleOrigin) -> String {
    let path: Vec<String> = origin.imported_path.iter().map(|segment| json_string(segment)).collect();
    format!("[{},[{}]]", json_string(&origin.specifier), path.join(","))
}

/// Deduplicate (last wins, first position) and canonically order module origins.
pub fn unique_semantic_origins(origins: &[ModuleOrigin]) -> Vec<ModuleOrigin> {
    let mut by_key: OrderedMap<String, ModuleOrigin> = OrderedMap::new();
    for origin in origins {
        by_key.insert(semantic_origin_key(origin), origin.clone());
    }
    let mut entries = by_key.into_entries();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries.into_iter().map(|(_, origin)| origin).collect()
}

/// Match namespace paths only after the caller has identified a Node built-in.
pub fn semantic_builtin_namespace_path(imported_path: &[String]) -> bool {
    imported_path.is_empty() || (imported_path.len() == 1 && imported_path[0] == "default")
}
