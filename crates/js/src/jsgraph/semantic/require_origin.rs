//! Port of `javascriptSemanticRequireOrigin.ts`.

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::static_property_key;
use crate::jsgraph::ir::ModuleOrigin;

use super::ast_util::{is_identifier_named, string_value, unwrapped};
use super::state::{resolve_semantic_binding_state, semantic_resolution_blocked, SemanticAnalysisState};

/// Recover an unshadowed literal require origin and its exact member path.
pub fn semantic_require_origin(
    node: Option<N<'_>>,
    state: &SemanticAnalysisState<'_>,
) -> Option<ModuleOrigin> {
    let mut members: Vec<String> = Vec::new();
    let mut current = node?;
    loop {
        current = unwrapped(current);
        if !current.is_member() {
            break;
        }
        let member = static_property_key(current.f("property")?, current.flag("computed"))?;
        let object = current.f("object")?;
        members.push(member);
        current = object;
    }
    if !current.is(Kind::CallExpression) {
        return None;
    }
    let callee = current.f("callee");
    if !is_identifier_named(callee, "require") {
        return None;
    }
    let callee = callee?;
    if resolve_semantic_binding_state(state, callee, "require").is_some()
        || semantic_resolution_blocked(state, callee, "require")
    {
        return None;
    }
    let specifier = string_value(current.list("arguments").first().copied().flatten())?;
    members.reverse();
    Some(ModuleOrigin { specifier, imported_path: members })
}
