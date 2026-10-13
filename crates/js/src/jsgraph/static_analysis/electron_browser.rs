//! Port of `electronStaticAnalysisBrowser.ts`: BrowserWindow, contextBridge and
//! utility-process syntax.

use super::super::ast::{Kind, N};
use super::super::ast_values::static_property_name;
use super::super::ir::Primitive;
use super::super::static_types::{
    ElectronBrowserWindowFinding, ElectronContextBridgeFinding, ElectronStaticValue,
    ElectronUtilityProcessFinding, ElectronWebPreference,
};
use super::super::util::{compare_code_points, range};
use super::electron_values::{
    bounded_expression, collect_context_bridge_members, electron_callee_name,
    electron_static_value, object_property, ObjectProperty,
};
use super::helpers::{static_path, static_path_resolution_context};
use super::state::{add_located, Ctx};

/// `inspectElectronBrowserNode`.
pub fn inspect_electron_browser_node(node: N<'_>, ctx: &mut Ctx<'_>) {
    if node.is(Kind::NewExpression) {
        inspect_browser_window(node, ctx);
    }
    if !node.is(Kind::CallExpression) {
        return;
    }
    inspect_context_bridge(node, ctx);
    inspect_utility_process(node, ctx);
}

fn argument(node: N<'_>, index: usize) -> Option<N<'_>> {
    node.nodes("arguments").get(index).copied()
}

struct WindowOptions {
    status: &'static str,
    preferences: Vec<ElectronWebPreference>,
    preload_path: Option<String>,
    preload_resolution_context: Option<String>,
    unknown: u64,
}

fn inspect_browser_window(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    let name = electron_callee_name(callee, ctx);
    if name != "BrowserWindow" && !name.ends_with(".BrowserWindow") {
        return;
    }
    let options = argument(node, 0);
    let collected = collect_window_options(options);
    ctx.acc.unknown_findings += collected.unknown;
    let finding = ElectronBrowserWindowFinding {
        preload_path: collected.preload_path,
        preload_resolution_context: collected.preload_resolution_context,
        options_status: match options {
            None => "missing",
            Some(options) if options.is(Kind::ObjectExpression) => "object-literal",
            Some(_) => "dynamic",
        }
        .into(),
        web_preferences_status: collected.status.into(),
        web_preferences: collected.preferences,
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(
        &mut ctx.acc.seen,
        &mut ctx.acc.browser_windows,
        &format!("electron-window\0{name}"),
        node,
        finding,
    );
}

fn collect_window_options(options: Option<N<'_>>) -> WindowOptions {
    match object_property(options, "webPreferences") {
        ObjectProperty::Explicit(property)
            if property.f("value").is_some_and(|value| value.is(Kind::ObjectExpression)) =>
        {
            let object = property.f("value").expect("checked above");
            collect_web_preferences(object)
        }
        other => {
            let missing = matches!(other, ObjectProperty::Missing);
            WindowOptions {
                status: if missing { "missing" } else { "dynamic" },
                preferences: Vec::new(),
                preload_path: None,
                preload_resolution_context: None,
                unknown: u64::from(!missing),
            }
        }
    }
}

fn collect_web_preferences(object: N<'_>) -> WindowOptions {
    let mut preferences: Vec<ElectronWebPreference> = Vec::new();
    let mut unknown = 0u64;
    let effective_preload = object_property(Some(object), "preload");
    let preload_value = match effective_preload {
        ObjectProperty::Explicit(property) => property.f("value"),
        _ => None,
    };
    let preload_path = preload_value.and_then(static_path);
    let (preload_path, preload_resolution_context) = match (preload_value, preload_path) {
        (Some(value), Some(path)) => (Some(path), Some(static_path_resolution_context(value))),
        _ => (None, None),
    };
    for property in object.nodes("properties") {
        if property.is(Kind::SpreadElement) {
            unknown += 1;
            preferences.push(ElectronWebPreference {
                name: format!("[spread@{}]", property.start()),
                value: electron_static_value(property.f("argument")),
            });
            continue;
        }
        let name = property
            .f("key")
            .map(|key| static_property_name(key, property.flag("computed")))
            .unwrap_or_default();
        if name.is_empty() || property.flag("computed") {
            unknown += 1;
            preferences.push(ElectronWebPreference {
                name: format!("[dynamic@{}]", property.start()),
                value: electron_static_value(Some(property)),
            });
            continue;
        }
        if property.is(Kind::ObjectMethod) {
            unknown += 1;
            preferences.push(ElectronWebPreference {
                name,
                value: electron_static_value(Some(property)),
            });
            continue;
        }
        let property_value = property.f("value");
        let path = if name == "preload" { property_value.and_then(static_path) } else { None };
        let value = match path {
            None => electron_static_value(property_value),
            Some(path) => ElectronStaticValue {
                status: "literal".into(),
                value: Primitive::Str(path),
                expression: None,
            },
        };
        if value.status == "dynamic" {
            unknown += 1;
        }
        preferences.push(ElectronWebPreference { name, value });
    }
    preferences.sort_by(|left, right| compare_code_points(&left.name, &right.name));
    WindowOptions {
        status: "object-literal",
        preferences,
        preload_path,
        preload_resolution_context,
        unknown,
    }
}

fn inspect_context_bridge(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    let name = electron_callee_name(callee, ctx);
    let main = name == "contextBridge.exposeInMainWorld"
        || name.ends_with(".contextBridge.exposeInMainWorld");
    let isolated = name == "contextBridge.exposeInIsolatedWorld"
        || name.ends_with(".contextBridge.exposeInIsolatedWorld");
    if !main && !isolated {
        return;
    }
    let key_node = argument(node, if isolated { 1 } else { 0 });
    let api_node = argument(node, if isolated { 2 } else { 1 });
    let key = electron_static_value(key_node);
    let api = collect_context_bridge_members(api_node);
    let world_id = isolated.then(|| electron_static_value(argument(node, 0)));
    let unknown = u64::from(key.status == "dynamic")
        + u64::from(world_id.as_ref().is_some_and(|value| value.status == "dynamic"))
        + api.unknown;
    ctx.acc.unknown_findings += unknown;
    let (api_key, api_key_expression) = if key.status == "dynamic" {
        (None, key.expression.clone())
    } else if let Primitive::Str(text) = &key.value {
        (Some(text.clone()), None)
    } else {
        (None, None)
    };
    let dedupe_key = format!(
        "context-bridge\0{}\0{}",
        if isolated { "isolated" } else { "main" },
        api_key.as_deref().or(api_key_expression.as_deref()).unwrap_or("[missing]")
    );
    let finding = ElectronContextBridgeFinding {
        api_key,
        api_key_expression,
        world: if isolated { "isolated" } else { "main" }.into(),
        world_id,
        api_status: api.status.into(),
        members: api.members,
        unknown_members: api.unknown,
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.context_bridge_apis, &dedupe_key, node, finding);
}

fn inspect_utility_process(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    let name = electron_callee_name(callee, ctx);
    if name != "utilityProcess.fork" && !name.ends_with(".utilityProcess.fork") {
        return;
    }
    let module_node = argument(node, 0);
    let module_path = module_node.and_then(static_path);
    let options = argument(node, 2);
    let service_name_property = object_property(options, "serviceName");
    let service_name = match &service_name_property {
        ObjectProperty::Explicit(property) => property.f("value").and_then(static_path),
        _ => None,
    };
    if !matches!(service_name_property, ObjectProperty::Missing) && service_name.is_none() {
        ctx.acc.unknown_findings += 1;
    }
    if module_path.is_none() {
        ctx.acc.unknown_findings += 1;
    }
    let (module_path, module_resolution_context, module_expression) = match (&module_path, module_node) {
        (Some(path), Some(module_node)) => (
            Some(path.clone()),
            Some(static_path_resolution_context(module_node)),
            None,
        ),
        _ => (None, None, Some(bounded_expression(module_node))),
    };
    let dedupe_key = format!(
        "electron-utility\0{}",
        module_path.as_deref().or(module_expression.as_deref()).unwrap_or("")
    );
    let finding = ElectronUtilityProcessFinding {
        service_name,
        module_key: None,
        module_runtime: None,
        location: range(node),
        module_path,
        module_resolution_context,
        module_expression,
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.utility_processes, &dedupe_key, node, finding);
}
