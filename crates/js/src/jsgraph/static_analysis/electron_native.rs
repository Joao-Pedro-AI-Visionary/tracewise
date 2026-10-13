//! Port of `electronStaticAnalysisNative.ts`: JavaScript-side imports and re-exports of
//! native `.node` addons.

use serde_json::{json, Value};

use super::super::ast::{Kind, N};
use super::super::ast_values::{property_name, static_property_key};
use super::super::static_types::ElectronNativeAddonBindingFinding;
use super::super::util::{composite_key, range};
use super::helpers::{callee_name, sorted_set, string_value};
use super::state::{add_located, Ctx};

struct NativeBindingInput {
    specifier: String,
    kind: &'static str,
    module_kind: &'static str,
    members: Vec<String>,
    namespace_access: bool,
    dynamic_member_access: bool,
}

struct NativeMemberAccess {
    members: Vec<String>,
    namespace_access: bool,
    dynamic_member_access: bool,
}

struct NativeRequire {
    specifier: String,
    has_member_access: bool,
    access: NativeMemberAccess,
}

/// `inspectElectronNativeNode`.
pub fn inspect_electron_native_node(node: N<'_>, ctx: &mut Ctx<'_>) {
    match node.kind() {
        Kind::ImportDeclaration => inspect_import(node, ctx),
        Kind::ExportNamedDeclaration => inspect_named_export(node, ctx),
        Kind::ExportAllDeclaration => inspect_export_all(node, ctx),
        Kind::VariableDeclarator => inspect_require_binding(node, ctx),
        Kind::AssignmentExpression => inspect_re_export(node, ctx),
        _ => {}
    }
}

fn source_value<'a>(node: N<'a>) -> Option<&'a str> {
    node.f("source").map(|source| source.str("value").unwrap_or(""))
}

fn inspect_import(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(specifier) = source_value(node) else { return };
    if !is_native_specifier(specifier, false) {
        return;
    }
    let specifiers = node.nodes("specifiers");
    let members: Vec<String> = specifiers
        .iter()
        .filter_map(|specifier| match specifier.kind() {
            Kind::ImportDefaultSpecifier => Some("default".to_string()),
            Kind::ImportNamespaceSpecifier => None,
            _ => specifier.f("imported").map(property_name),
        })
        .collect();
    add_binding(
        ctx,
        node,
        NativeBindingInput {
            specifier: specifier.to_string(),
            kind: "import",
            module_kind: "import",
            members,
            namespace_access: specifiers.iter().any(|value| value.is(Kind::ImportNamespaceSpecifier)),
            dynamic_member_access: false,
        },
    );
}

fn inspect_named_export(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(specifier) = source_value(node) else { return };
    if !is_native_specifier(specifier, false) {
        return;
    }
    let specifiers = node.nodes("specifiers");
    let members: Vec<String> = specifiers
        .iter()
        .filter_map(|specifier| match specifier.kind() {
            Kind::ExportSpecifier => specifier.f("local").map(property_name),
            Kind::ExportDefaultSpecifier => Some("default".to_string()),
            _ => None,
        })
        .collect();
    add_binding(
        ctx,
        node,
        NativeBindingInput {
            specifier: specifier.to_string(),
            kind: "re-export",
            module_kind: "import",
            members,
            namespace_access: specifiers.iter().any(|value| value.is(Kind::ExportNamespaceSpecifier)),
            dynamic_member_access: false,
        },
    );
}

fn inspect_export_all(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(specifier) = source_value(node) else { return };
    if !is_native_specifier(specifier, false) {
        return;
    }
    add_binding(
        ctx,
        node,
        NativeBindingInput {
            specifier: specifier.to_string(),
            kind: "re-export",
            module_kind: "import",
            members: Vec::new(),
            namespace_access: true,
            dynamic_member_access: false,
        },
    );
}

fn inspect_require_binding(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(required) = native_require(node.f("init")) else { return };
    let access = if required.has_member_access {
        required.access
    } else {
        match node.f("id") {
            Some(id) => binding_members(id),
            None => NativeMemberAccess { members: Vec::new(), namespace_access: true, dynamic_member_access: false },
        }
    };
    add_binding(
        ctx,
        node,
        NativeBindingInput {
            specifier: required.specifier,
            kind: "require",
            module_kind: "require",
            members: access.members,
            namespace_access: access.namespace_access,
            dynamic_member_access: access.dynamic_member_access,
        },
    );
}

fn inspect_re_export(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(required) = native_require(node.f("right")) else { return };
    if !node.f("left").is_some_and(is_module_export) {
        return;
    }
    add_binding(
        ctx,
        node,
        NativeBindingInput {
            specifier: required.specifier,
            kind: "re-export",
            module_kind: "require",
            members: required.access.members,
            namespace_access: required.access.namespace_access,
            dynamic_member_access: required.access.dynamic_member_access,
        },
    );
}

fn add_binding(ctx: &mut Ctx<'_>, node: N<'_>, input: NativeBindingInput) {
    let members = sorted_set(input.members);
    // Members are a variable-length source-derived list: compositeKey keeps
    // ["a\0b"] distinct from ["a", "b"] instead of collapsing one binding.
    let key = composite_key(&[
        Value::from("native-addon-binding"),
        Value::from(input.kind),
        Value::from(input.specifier.as_str()),
        json!(members),
        Value::from(input.namespace_access),
        Value::from(input.dynamic_member_access),
    ]);
    let finding = ElectronNativeAddonBindingFinding {
        specifier: input.specifier,
        binding_kind: input.kind.into(),
        module_kind: input.module_kind.into(),
        members,
        namespace_access: Some(input.namespace_access),
        dynamic_member_access: Some(input.dynamic_member_access),
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.native_addon_bindings, &key, node, finding);
}

fn native_require(node: Option<N<'_>>) -> Option<NativeRequire> {
    let mut node = node?;
    let mut member: Option<String> = None;
    let mut has_member_access = false;
    while node.is_member() {
        let object = node.f("object")?;
        let property = node
            .f("property")
            .and_then(|property| static_property_key(property, node.flag("computed")));
        // Walking inward leaves the first member consumed from the addon itself.
        member = property;
        has_member_access = true;
        node = object;
    }
    if !node.is(Kind::CallExpression) {
        return None;
    }
    let name = callee_name(node.f("callee")?);
    if name != "require" && !name.ends_with(".require") && !name.contains("__webpack_require__") {
        return None;
    }
    let specifier = string_value(node.nodes("arguments").first().copied())?;
    if !is_native_specifier(&specifier, true) {
        return None;
    }
    Some(NativeRequire {
        specifier,
        has_member_access,
        access: NativeMemberAccess {
            dynamic_member_access: has_member_access && member.is_none(),
            members: member.into_iter().collect(),
            namespace_access: !has_member_access,
        },
    })
}

fn binding_members(pattern: N<'_>) -> NativeMemberAccess {
    if !pattern.is(Kind::ObjectPattern) {
        return NativeMemberAccess { members: Vec::new(), namespace_access: true, dynamic_member_access: false };
    }
    let mut members = Vec::new();
    let mut namespace_access = false;
    let mut dynamic_member_access = false;
    for property in pattern.nodes("properties") {
        if property.is(Kind::RestElement) {
            namespace_access = true;
            continue;
        }
        let key = property
            .f("key")
            .and_then(|key| static_property_key(key, property.flag("computed")));
        match key {
            None => dynamic_member_access = true,
            Some(key) => members.push(key),
        }
    }
    NativeMemberAccess { members, namespace_access, dynamic_member_access }
}

fn is_module_export(node: N<'_>) -> bool {
    let mut keys: Vec<Option<String>> = Vec::new();
    let mut node = node;
    while node.is_member() {
        keys.push(
            node.f("property")
                .and_then(|property| static_property_key(property, node.flag("computed"))),
        );
        match node.f("object") {
            Some(object) => node = object,
            None => return false,
        }
    }
    keys.reverse();
    if !node.is_identifier() {
        return false;
    }
    match node.name() {
        Some("exports") => !keys.is_empty(),
        Some("module") => keys.first().and_then(|key| key.as_deref()) == Some("exports"),
        _ => false,
    }
}

/// `isNativeSpecifier`: the path (query/fragment stripped for imports) ends in `.node`.
fn is_native_specifier(specifier: &str, require: bool) -> bool {
    let path = if require { specifier } else { strip_query_and_fragment(specifier) };
    path.to_lowercase().ends_with(".node")
}

/// `stripQueryAndFragment`: drop any query string and fragment from a declared reference.
fn strip_query_and_fragment(value: &str) -> &str {
    let before_fragment = value.split('#').next().unwrap_or("");
    before_fragment.split('?').next().unwrap_or("")
}
