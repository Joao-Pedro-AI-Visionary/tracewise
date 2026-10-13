//! Port of `javascriptStaticAnalysisCalls.ts`: references, endpoints, storage, roles and
//! source-map directives.

use fancy_regex::Regex;
use tracewise_web::browser_observation::sanitize_browser_url;

use super::super::ast::{Ast, Kind, N};
use super::super::ast_values::static_property_name;
use super::super::static_types::{
    OpenReceiverFact, RolePath, SourceMapUrl, StaticEndpoint, StaticReference, StaticStorage,
};
use super::super::util::range;
use super::helpers::{
    argument_value, callee_name, endpoint_argument, is_js_whitespace, prefixed_argument,
    static_path, static_path_resolution_context, storage_kind, string_value,
};
use super::state::{add_located, Accumulator, Ctx};

/// Recognized route-construction call suffixes.
const STATIC_ROUTE_CALL_NAMES: [&str; 5] =
    ["route", "addRoute", "useRoutes", "createBrowserRouter", "createHashRouter"];

/// `inspectCall` for a call, optional call or `new` expression.
pub fn inspect_call(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    let name = callee_name(callee);
    let args = node.nodes("arguments");
    let first = string_value(args.first().copied());
    let module_require_name: Option<String> = ctx
        .acc
        .module_range_index
        .find(i64::from(node.start()))
        .and_then(|module| module.require_name.clone());
    if let Some(specifier) = require_call_specifier(&args, &name, module_require_name.as_deref()) {
        add_reference(ctx, node, "require", specifier);
    }
    if let Some(specifier) = chunk_load_specifier(&args, &name, module_require_name.as_deref()) {
        add_reference(ctx, node, "dynamic-import", specifier);
    }
    for specifier in vite_preload_dependency_specifiers(ctx, &args, &name) {
        add_reference(ctx, node, "dynamic-import", Some(specifier));
    }
    if name == "Worker" || name.ends_with(".Worker") {
        add_reference(ctx, node, "worker", first.clone());
    }
    if name.ends_with("serviceWorker.register") {
        add_reference(ctx, node, "service-worker", first.clone());
    }
    inspect_endpoint_call(node, callee, &args, &name, first.as_deref(), ctx);
    inspect_storage_call(node, &name, first.as_deref(), ctx);
    if first.as_deref() == Some("audio") || first.as_deref() == Some("video") {
        note_media_element_preloads(&args, &mut ctx.acc);
    }
    if name.ends_with("loadFile") {
        if let Some(first) = &first {
            add_role(ctx, node, "renderer", first, "filesystem-expression", format!("call:{name}"));
        }
    }
    if name.ends_with("loadURL") {
        if let Some(first) = &first {
            add_role(ctx, node, "renderer", first, "module-specifier", format!("call:{name}"));
        }
    }
}

fn add_role(
    ctx: &mut Ctx<'_>,
    node: N<'_>,
    role: &str,
    path: &str,
    resolution_context: &str,
    mechanism: String,
) {
    let key = format!("role\0{role}\0{path}");
    let value = RolePath {
        role: role.into(),
        path: path.into(),
        resolution_context: resolution_context.into(),
        mechanism,
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.roles, &key, node, value);
}

/// Element factories such as `jsx("audio", props)` and `createElement("video", props)` carry
/// the HTML media `preload` hint, which never names an Electron preload script.
fn note_media_element_preloads(args: &[N<'_>], acc: &mut Accumulator) {
    let Some(props) = args.get(1) else { return };
    if !props.is(Kind::ObjectExpression) {
        return;
    }
    for property in props.nodes("properties") {
        if property.is(Kind::ObjectProperty)
            && property
                .f("key")
                .is_some_and(|key| static_property_name(key, property.flag("computed")) == "preload")
        {
            acc.media_element_preloads.insert(property.id);
        }
    }
}

/// `Some(specifier)` when the call is a recognized require form (the specifier may be unknown).
fn require_call_specifier(
    args: &[N<'_>],
    name: &str,
    module_require_name: Option<&str>,
) -> Option<Option<String>> {
    if name == "require" || name.ends_with(".require") {
        return Some(argument_value(args.first().copied()));
    }
    if name == "__webpack_require__" || Some(name) == module_require_name {
        return Some(argument_value(args.first().copied()));
    }
    if name == "__webpack_require__.bind"
        || module_require_name.is_some_and(|require| name == format!("{require}.bind"))
    {
        return Some(argument_value(args.get(1).copied()));
    }
    None
}

fn chunk_load_specifier(
    args: &[N<'_>],
    name: &str,
    module_require_name: Option<&str>,
) -> Option<Option<String>> {
    if name != "__webpack_require__.e"
        && !module_require_name.is_some_and(|require| name == format!("{require}.e"))
    {
        return None;
    }
    Some(prefixed_argument("chunk:", args.first().copied()))
}

fn vite_preload_dependency_specifiers(ctx: &Ctx<'_>, args: &[N<'_>], name: &str) -> Vec<String> {
    if name != "__vite__mapDeps" {
        return Vec::new();
    }
    let Some(array) = args.first().filter(|array| array.is(Kind::ArrayExpression)) else {
        return Vec::new();
    };
    let elements = array.list("elements");
    let indexes: Vec<f64> = elements
        .iter()
        .filter_map(|element| element.filter(|node| node.is_numeric_literal()))
        .map(|node| node.num("value").unwrap_or(f64::NAN))
        .collect();
    if indexes.len() != elements.len() {
        return Vec::new();
    }
    let table = ctx.acc.vite_table.get_or_init(|| vite_preload_dependency_table(ctx.source()));
    indexes
        .into_iter()
        // `table[index] ?? []`: only an in-range integer index names an entry.
        .filter(|index| index.fract() == 0.0 && *index >= 0.0 && *index < table.len() as f64)
        .map(|index| table[index as usize].clone())
        .collect()
}

/// JS `\s`: WhiteSpace and LineTerminator code points.
const JS_WS: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

fn vite_preload_dependency_table(source: &str) -> Vec<String> {
    // /\.\s*f\s*\|\|\s*\(\s*[^)]*?\.f\s*=\s*\[([\s\S]*?)\]\s*\)/u
    let pattern = format!(
        r"\.[{ws}]*f[{ws}]*\|\|[{ws}]*\([{ws}]*[^)]*?\.f[{ws}]*=[{ws}]*\[([\s\S]*?)\][{ws}]*\)",
        ws = JS_WS
    );
    let table = Regex::new(&pattern).expect("vite table pattern");
    let Ok(Some(captures)) = table.captures(source) else { return Vec::new() };
    let Some(body) = captures.get(1) else { return Vec::new() };
    // /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/gu, where `.` excludes line terminators.
    let literal = Regex::new(
        r#""([^"\\]*(?:\\[^\n\r\x{2028}\x{2029}][^"\\]*)*)"|'([^'\\]*(?:\\[^\n\r\x{2028}\x{2029}][^'\\]*)*)'"#,
    )
    .expect("string literal pattern");
    let mut out = Vec::new();
    for found in literal.captures_iter(body.as_str()).flatten() {
        let text = found
            .get(1)
            .or_else(|| found.get(2))
            .map_or("", |capture| capture.as_str());
        out.push(text.to_string());
    }
    out
}

fn inspect_endpoint_call(
    node: N<'_>,
    callee: N<'_>,
    args: &[N<'_>],
    name: &str,
    first: Option<&str>,
    ctx: &mut Ctx<'_>,
) {
    let route = STATIC_ROUTE_CALL_NAMES
        .iter()
        .any(|candidate| name == *candidate || name.ends_with(&format!(".{candidate}")));
    if route {
        if let Some(first) = first {
            add_endpoint(ctx, node, "route", first, format!("call:{name}"));
        }
    }
    let receiver_fact: Option<OpenReceiverFact> = ctx.open_receivers.get(&node.start()).copied();
    if let Some(endpoint) = endpoint_argument(name, args, callee, receiver_fact) {
        add_endpoint(ctx, node, "network", &endpoint, format!("call:{name}"));
    }
}

/// `inspectRouteProperty`.
pub fn inspect_route_property(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(key_node) = node.f("key") else { return };
    let key = static_property_name(key_node, node.flag("computed"));
    if key != "path" && key != "route" {
        return;
    }
    let Some(value) = node.f("value").filter(|value| value.is_string_literal()) else { return };
    add_endpoint(
        ctx,
        node,
        "route",
        value.str("value").unwrap_or(""),
        format!("property:{key}"),
    );
}

/// `inspectRoleProperty`.
pub fn inspect_role_property(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(key_node) = node.f("key") else { return };
    if static_property_name(key_node, node.flag("computed")) != "preload" {
        return;
    }
    if ctx.acc.media_element_preloads.contains(&node.id) {
        return;
    }
    let Some(value) = node.f("value") else { return };
    let Some(path) = static_path(value) else { return };
    let key = format!("role\0preload\0{path}");
    let role = RolePath {
        role: "preload".into(),
        path,
        resolution_context: static_path_resolution_context(value),
        mechanism: "property:preload".into(),
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.roles, &key, node, role);
}

fn inspect_storage_call(node: N<'_>, name: &str, first: Option<&str>, ctx: &mut Ctx<'_>) {
    let receiver_fact = ctx.open_receivers.get(&node.start()).copied();
    let storage: Option<&str> = match receiver_fact {
        Some(
            OpenReceiverFact::Local
            | OpenReceiverFact::LocalIndexedDb
            | OpenReceiverFact::LocalCacheStorage,
        ) => None,
        Some(OpenReceiverFact::IndexedDb) => Some("indexed-db"),
        Some(OpenReceiverFact::CacheStorage) => Some("cache-storage"),
        _ => storage_kind(name),
    };
    let Some(storage) = storage else { return };
    let key = format!("storage\0{storage}\0{}", first.unwrap_or(""));
    let value = StaticStorage {
        kind: storage.into(),
        name: first.map(str::to_string),
        mechanism: format!("call:{name}"),
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.storage, &key, node, value);
}

/// `addReference`.
pub fn add_reference(ctx: &mut Ctx<'_>, node: N<'_>, kind: &str, specifier: Option<String>) {
    let (specifier, expression) = match specifier {
        None => (None, Some(node.text().to_string())),
        Some(specifier) => (Some(specifier), None),
    };
    let key = format!(
        "reference\0{kind}\0{}",
        specifier.as_deref().or(expression.as_deref()).unwrap_or("")
    );
    let value = StaticReference {
        kind: kind.into(),
        module_key: None,
        module_runtime: None,
        location: range(node),
        specifier,
        expression,
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.references, &key, node, value);
}

fn add_endpoint(ctx: &mut Ctx<'_>, node: N<'_>, kind: &str, value: &str, mechanism: String) {
    let key = format!("endpoint\0{kind}\0{value}");
    let endpoint = StaticEndpoint {
        kind: kind.into(),
        value: sanitize_browser_url(value).url,
        mechanism,
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.endpoints, &key, node, endpoint);
}

fn is_ws_unit(unit: u16) -> bool {
    char::from_u32(u32::from(unit)).is_some_and(is_js_whitespace)
}

fn starts_with_ascii(units: &[u16], from: usize, needle: &str) -> bool {
    let needle: Vec<u16> = needle.encode_utf16().collect();
    units.len() >= from + needle.len() && units[from..from + needle.len()] == needle[..]
}

/// `addSourceMapDirectives`: read real comment tokens only; quoted text can contain identical
/// markers. Both current/legacy line annotations and minifier block annotations are kept.
pub fn add_source_map_directives(ast: &Ast, acc: &mut Accumulator) {
    for comment in &ast.comments {
        let (start, end) = (comment.start, comment.end);
        let text = ast.source.slice(start, end);
        let bytes = text.as_bytes();
        if !(text.starts_with("//") || text.starts_with("/*"))
            || !matches!(bytes.get(2), Some(b'#' | b'@'))
        {
            continue;
        }
        let units: Vec<u16> = text.encode_utf16().collect();
        // Single-class searches avoid regex backtracking over unbounded whitespace.
        let Some(name_offset) = units[3.min(units.len())..].iter().position(|u| !is_ws_unit(*u)) else {
            continue;
        };
        let name_start = 3 + name_offset;
        if !starts_with_ascii(&units, name_start, "sourceMappingURL") {
            continue;
        }
        let name_end = name_start + "sourceMappingURL".len();
        let Some(equals_offset) = units[name_end..].iter().position(|u| !is_ws_unit(*u)) else {
            continue;
        };
        let equals_start = name_end + equals_offset;
        if !starts_with_ascii(&units, equals_start, "=") {
            continue;
        }
        let Some(url_offset) = units[equals_start + 1..].iter().position(|u| !is_ws_unit(*u)) else {
            continue;
        };
        let declared_start = equals_start + 1 + url_offset;
        let terminator = units[declared_start..]
            .iter()
            .position(|u| is_ws_unit(*u) || *u == u16::from(b'*'));
        let declared_end = terminator.map_or(units.len(), |offset| declared_start + offset);
        if declared_end == declared_start {
            continue;
        }
        let declared = String::from_utf16_lossy(&units[declared_start..declared_end]);
        let location = ast.range(start, start + declared_end as u32);
        if acc.reserve(format!("source-map\0{declared}")) {
            acc.source_maps.push(SourceMapUrl { declared_url: declared, location });
        }
    }
}
