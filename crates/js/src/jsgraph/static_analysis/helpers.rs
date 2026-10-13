//! Port of `javascriptStaticAnalysisHelpers.ts`: callee names, literal reads, static path
//! recovery, endpoint recognition, vendor markers.

use super::super::ast::{Kind, N};
use super::super::ast_values::{
    read_exact_literal, static_property_name, unwrap_expression,
};
use super::super::ir::Primitive;
use super::super::static_types::{OpenReceiverFact, StaticPathContext};
use super::super::util::{compare_code_points, js_number_to_string};
use super::posix;
use super::uri;

/// Characters `String.prototype.trim` strips (WhiteSpace and LineTerminator).
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `String.prototype.trim`.
pub fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

/// Deduplicated values in `compareUnicodeCodePoints` order (`[...new Set(v)].sort(cmp)`).
pub fn sorted_set(mut values: Vec<String>) -> Vec<String> {
    values.sort_by(|a, b| compare_code_points(a, b));
    values.dedup();
    values
}

/// Static literal values of an array plus the count of elements that are not static.
pub struct StaticValues {
    pub values: Vec<String>,
    pub unknown: u64,
}

/// `chunkRuntime`: the runtime name of a Webpack/Rspack `push` call.
pub fn chunk_runtime(call: N<'_>) -> Option<String> {
    let callee = call.f("callee")?;
    if !callee.is_member() {
        return None;
    }
    if static_property_name(callee.f("property")?, callee.flag("computed")) != "push" {
        return None;
    }
    find_chunk_runtime(callee.f("object")?)
}

/// `/(?:webpack|rspack)Chunk/iu` (simple case folding, so U+017F and U+212A fold to `s` and `k`).
fn has_chunk_marker(text: &str) -> bool {
    let folded: Vec<char> = text
        .chars()
        .map(|c| match c {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect();
    let contains = |needle: &str| {
        let needle: Vec<char> = needle.chars().collect();
        folded.windows(needle.len()).any(|window| window == needle.as_slice())
    };
    contains("webpackchunk") || contains("rspackchunk")
}

fn find_chunk_runtime(node: N<'_>) -> Option<String> {
    let mut pending: Vec<N<'_>> = vec![node];
    while let Some(current) = pending.pop() {
        if current.is_identifier() {
            let name = current.name().unwrap_or("");
            if has_chunk_marker(name) {
                return Some(name.to_string());
            }
        }
        if current.is_member() {
            let property =
                static_property_name(current.f("property")?, current.flag("computed"));
            if has_chunk_marker(&property) {
                return Some(property);
            }
            if let Some(object) = current.f("object") {
                pending.push(object);
            }
            continue;
        }
        if current.is(Kind::AssignmentExpression) {
            pending.extend(current.f("right"));
            pending.extend(current.f("left"));
            continue;
        }
        if current.is(Kind::LogicalExpression) || current.is(Kind::BinaryExpression) {
            pending.extend(current.f("right"));
            pending.extend(current.f("left"));
            continue;
        }
        let unwrapped = unwrap_expression(current).0;
        if unwrapped != current {
            pending.push(unwrapped);
        }
    }
    None
}

/// `moduleFactory`: a literal function factory from one module-table property.
pub fn module_factory(property: N<'_>) -> Option<N<'_>> {
    if property.is(Kind::ObjectMethod) {
        return Some(property);
    }
    if property.is(Kind::ObjectProperty) {
        let value = property.f("value")?;
        if value.is(Kind::FunctionExpression) || value.is(Kind::ArrowFunctionExpression) {
            return Some(value);
        }
    }
    None
}

/// `modulePropertyName`: literal or explicitly computed module key.
pub fn module_property_name(property: N<'_>) -> String {
    let unknown = || format!("[unknown@{}]", property.start());
    if property.is(Kind::ObjectMethod) || property.is(Kind::ObjectProperty) {
        let Some(key) = property.f("key") else { return unknown() };
        let computed = property.flag("computed");
        if computed && !key.is_string_literal() && !key.is_numeric_literal() {
            return format!("[computed@{}]", property.start());
        }
        let name = static_property_name(key, computed);
        if name.is_empty() {
            unknown()
        } else {
            name
        }
    } else {
        unknown()
    }
}

/// `factoryRequireName`: the factory-local bundler require parameter when declared.
pub fn factory_require_name(factory: N<'_>) -> Option<String> {
    let params = factory.list("params");
    let parameter = params.get(2).copied().flatten()?;
    parameter.is_identifier().then(|| parameter.name().unwrap_or("").to_string())
}

/// `staticArrayValues`: unique static literal values of an array.
pub fn static_array_values(array: N<'_>) -> StaticValues {
    let elements = array.list("elements");
    let static_values: Vec<String> =
        elements.iter().filter_map(|element| argument_value(*element)).collect();
    let unknown = (elements.len() - static_values.len()) as u64;
    StaticValues { values: sorted_set(static_values), unknown }
}

/// `staticPathResolutionContext`.
pub fn static_path_resolution_context(node: N<'_>) -> StaticPathContext {
    if is_filesystem_path_expression(node) {
        "filesystem-expression".into()
    } else {
        "module-specifier".into()
    }
}

/// `staticPath`: a path composed only from inert literal syntax.
pub fn static_path(node: N<'_>) -> Option<String> {
    match node.kind() {
        Kind::StringLiteral => return Some(node.str("value").unwrap_or("").to_string()),
        Kind::TemplateLiteral if node.list_len("expressions") == 0 => {
            return string_value(Some(node));
        }
        Kind::BinaryExpression if node.str("operator") == Some("+") => {
            let left = static_path(node.f("left")?);
            let right = static_path(node.f("right")?);
            return match (left, right) {
                (Some(left), Some(right)) => Some(format!("{left}{right}")),
                _ => None,
            };
        }
        Kind::CallExpression | Kind::NewExpression => return static_call_path(node),
        _ => {}
    }
    None
}

fn arguments_of(node: N<'_>) -> Vec<N<'_>> {
    node.nodes("arguments")
}

fn name_is_or_ends(name: &str, exact: &str, suffix: &str) -> bool {
    name == exact || name.ends_with(suffix)
}

fn is_url_name(name: &str) -> bool {
    name_is_or_ends(name, "URL", ".URL")
}

fn is_file_url_to_path_name(name: &str) -> bool {
    name_is_or_ends(name, "fileURLToPath", ".fileURLToPath")
}

fn is_dirname_name(name: &str) -> bool {
    name_is_or_ends(name, "dirname", ".dirname")
}

fn static_call_path(node: N<'_>) -> Option<String> {
    let name = callee_name(node.f("callee")?);
    let args = arguments_of(node);
    if is_url_name(&name) {
        return if is_file_identity(args.get(1).copied()) {
            string_value(args.first().copied())
        } else {
            None
        };
    }
    if is_file_url_to_path_name(&name) {
        return static_file_url_path(args.first().copied());
    }
    if is_dirname_name(&name) && is_file_identity(args.first().copied()) {
        return Some(String::new());
    }
    if name.ends_with(".resolve") {
        return if name == "win32.resolve" || name.ends_with(".win32.resolve") {
            None
        } else {
            static_resolved_path(node)
        };
    }
    if !name.ends_with(".join") && name != "join" {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for argument in &args {
        if is_directory_identity(Some(*argument)) {
            continue;
        }
        parts.push(static_path(*argument)?);
    }
    if parts.is_empty() {
        None
    } else {
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        Some(posix::join(&refs))
    }
}

fn static_file_url_path(argument: Option<N<'_>>) -> Option<String> {
    let argument = argument?;
    if is_source_file_url(argument) {
        source_relative_file_url_path(argument)
    } else {
        static_path(argument)
    }
}

/// `/^[a-z][a-z0-9+.-]*:/iu`: under `/iu` the class also folds U+017F and U+212A.
fn has_url_scheme(value: &str) -> bool {
    let folds = |c: char| c.is_ascii_alphabetic() || c == '\u{17f}' || c == '\u{212a}';
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if folds(first) => {}
        _ => return false,
    }
    for c in chars {
        if c == ':' {
            return true;
        }
        if !(folds(c) || c.is_ascii_digit() || c == '+' || c == '.' || c == '-') {
            return false;
        }
    }
    false
}

/// `/%(?:2e|2f|5c)/iu`.
fn has_encoded_dot_or_separator(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(3).any(|window| {
        window[0] == b'%'
            && matches!(
                (window[1], window[2].to_ascii_lowercase()),
                (b'2', b'e') | (b'2', b'f') | (b'5', b'c')
            )
    })
}

/// Project a known source-relative URL through the actual file URL decoder.
fn source_relative_file_url_path(node: N<'_>) -> Option<String> {
    if !is_source_file_url(node) {
        return None;
    }
    let args = arguments_of(node);
    let value = string_value(args.first().copied())?;
    let head = value.split(['?', '#']).next().unwrap_or("");
    if head.is_empty()
        || value != js_trim(&value)
        || value.contains('\\')
        || value.chars().any(|c| (c as u32) < 32)
        || has_url_scheme(&value)
        || value.starts_with("//")
        || has_encoded_dot_or_separator(head)
    {
        return None;
    }
    // A sufficiently deep inert anchor preserves any leading parent segments
    // without using this host's cwd or inventing the application's directory.
    let depth = value.split('/').count() + 1;
    let directory = format!("/{}", "source/".repeat(depth));
    let base = url::Url::parse(&format!("file://{directory}entry.js")).ok()?;
    let resolved = base.join(&value).ok()?;
    let path = uri::file_url_to_path_posix(&resolved)?;
    if value.starts_with('/') {
        return Some(path);
    }
    let relative = posix::relative(&directory, &path);
    let relative = if relative.is_empty() { ".".to_string() } else { relative };
    // Keep the established explicit source-directory observation spelling.
    if value.starts_with("./") && relative != "." && !relative.starts_with("../") {
        Some(format!("./{relative}"))
    } else {
        Some(relative)
    }
}

fn is_source_file_url(node: N<'_>) -> bool {
    if !(node.is(Kind::CallExpression) || node.is(Kind::NewExpression)) {
        return false;
    }
    let Some(callee) = node.f("callee") else { return false };
    is_url_name(&callee_name(callee)) && is_file_identity(arguments_of(node).get(1).copied())
}

fn static_resolved_path(node: N<'_>) -> Option<String> {
    let mut parts: Vec<Option<String>> = Vec::new();
    for argument in arguments_of(node) {
        if is_directory_identity(Some(argument)) {
            parts.push(None);
            continue;
        }
        // Validate every argument, including those before the last anchor.
        parts.push(Some(static_path(argument)?));
    }
    let anchor = parts
        .iter()
        .rposition(|part| part.as_ref().is_none_or(|value| posix::is_absolute(value)))?;
    // A null anchor is the source directory; preserve its relative projection.
    let kept: Vec<&str> = parts[anchor..].iter().flatten().map(String::as_str).collect();
    let path = posix::join(&kept);
    if path == "/" {
        Some(path)
    } else {
        Some(path.strip_suffix('/').map(str::to_string).unwrap_or(path))
    }
}

fn is_filesystem_path_expression(node: N<'_>) -> bool {
    if node.is_string_literal() {
        return node.str("value").unwrap_or("").starts_with('/');
    }
    if is_file_identity(Some(node)) || is_directory_identity(Some(node)) {
        return true;
    }
    if node.is(Kind::BinaryExpression) && node.str("operator") == Some("+") {
        return node.f("left").is_some_and(is_filesystem_path_expression)
            || node.f("right").is_some_and(is_filesystem_path_expression);
    }
    if node.is(Kind::CallExpression) || node.is(Kind::NewExpression) {
        let Some(callee) = node.f("callee") else { return false };
        let name = callee_name(callee);
        let args = arguments_of(node);
        if name.ends_with(".resolve") && static_call_path(node).is_some() {
            return true;
        }
        if is_url_name(&name) {
            return is_file_identity(args.get(1).copied());
        }
        // `fileURLToPath` and every other callee: any argument that is itself a filesystem path.
        return args.iter().any(|argument| is_filesystem_path_expression(*argument));
    }
    false
}

fn is_directory_identity(node: Option<N<'_>>) -> bool {
    let Some(node) = node else { return false };
    if node.is_identifier() && node.name() == Some("__dirname") {
        return true;
    }
    if !(node.is(Kind::CallExpression) || node.is(Kind::NewExpression)) {
        return false;
    }
    let Some(callee) = node.f("callee") else { return false };
    let name = callee_name(callee);
    let args = arguments_of(node);
    if is_url_name(&name) {
        return is_file_identity(args.get(1).copied());
    }
    is_dirname_name(&name) && is_file_identity(args.first().copied())
}

fn is_file_identity(node: Option<N<'_>>) -> bool {
    let Some(node) = node else { return false };
    if node.is_identifier() && node.name() == Some("__filename") {
        return true;
    }
    if node.is(Kind::MemberExpression) {
        if let Some(object) = node.f("object") {
            if object.is(Kind::MetaProperty)
                && object.f("meta").and_then(|meta| meta.name()) == Some("import")
                && object.f("property").and_then(|property| property.name()) == Some("meta")
                && node
                    .f("property")
                    .is_some_and(|property| static_property_name(property, node.flag("computed")) == "url")
            {
                return true;
            }
        }
    }
    if !node.is(Kind::CallExpression) {
        return false;
    }
    let Some(callee) = node.f("callee") else { return false };
    is_file_url_to_path_name(&callee_name(callee))
        && is_file_identity(arguments_of(node).first().copied())
}

const XHR_METHODS: [&str; 9] =
    ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"];

/// An absolute HTTP(S)/WebSocket URL, or an absolute or relative path.
fn is_request_url_literal(value: &str) -> bool {
    // `/^(?:https?|wss?):\/\//iu`: simple case folding maps U+017F to `s`.
    let lower_prefix: String = value
        .chars()
        .take(8)
        .map(|c| if c == '\u{17f}' { 's' } else { c.to_ascii_lowercase() })
        .collect();
    lower_prefix.starts_with("http://")
        || lower_prefix.starts_with("https://")
        || lower_prefix.starts_with("ws://")
        || lower_prefix.starts_with("wss://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

/// `WINDOW_OPEN_CALL`: `(?:^|\.)(?:window|self|globalThis|top|parent|opener|frames|document)\.open$`.
fn is_window_open_call(name: &str) -> bool {
    const OWNERS: [&str; 8] =
        ["window", "self", "globalThis", "top", "parent", "opener", "frames", "document"];
    let Some(owner) = name.strip_suffix(".open") else { return false };
    OWNERS
        .iter()
        .any(|candidate| owner == *candidate || owner.ends_with(&format!(".{candidate}")))
}

/// Node `fs.open` flag strings, which are never request URLs.
fn is_fs_open_flag(value: &str) -> bool {
    const FLAGS: [&str; 22] = [
        "a", "a+", "as", "as+", "ax", "ax+", "r", "r+", "rs", "rs+", "sa", "sa+", "sr", "sr+", "w",
        "w+", "wx", "wx+", "xa", "xa+", "xw", "xw+",
    ];
    FLAGS.contains(&value)
}

/// `/^[A-Z][A-Z-]*$/u`.
fn is_uppercase_token(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c == '-')
}

/// Read `XMLHttpRequest.open(method, url)` (see the REA comment on `xhrOpenUrl`).
fn xhr_open_url(
    name: &str,
    method_node: Option<N<'_>>,
    url_node: Option<N<'_>>,
    receiver_fact: Option<OpenReceiverFact>,
) -> Option<String> {
    let url = string_value(url_node)?;
    // A lexical fact is stronger than the receiver's spelling.
    if receiver_fact == Some(OpenReceiverFact::Window) {
        return None;
    }
    let method = string_value(method_node);
    let storage = matches!(
        receiver_fact,
        Some(
            OpenReceiverFact::LocalIndexedDb
                | OpenReceiverFact::LocalCacheStorage
                | OpenReceiverFact::IndexedDb
                | OpenReceiverFact::CacheStorage
        )
    ) || storage_kind(name).is_some();
    let Some(method) = method else {
        let blocked = storage
            || (receiver_fact.is_none() && is_window_open_call(name))
            || is_fs_open_flag(&url)
            || matches!(url.to_lowercase().as_str(), "_blank" | "_parent" | "_self" | "_top");
        return if blocked { None } else { Some(url) };
    };
    let local_storage = matches!(
        receiver_fact,
        Some(OpenReceiverFact::LocalIndexedDb | OpenReceiverFact::LocalCacheStorage)
    );
    if XHR_METHODS.contains(&method.to_uppercase().as_str())
        || ((!storage || local_storage) && is_uppercase_token(&method))
    {
        Some(url)
    } else {
        None
    }
}

/// Whether a get/delete receiver is spelled as a keyed collection.
fn is_keyed_collection_receiver(callee: N<'_>) -> bool {
    const CONSTRUCTORS: [&str; 7] =
        ["FormData", "Headers", "Map", "Set", "URLSearchParams", "WeakMap", "WeakSet"];
    if !callee.is_member() {
        return false;
    }
    let Some(receiver) = callee.f("object") else { return false };
    if receiver.is(Kind::NewExpression) {
        return receiver.f("callee").is_some_and(|constructor| {
            constructor.is_identifier()
                && CONSTRUCTORS.contains(&constructor.name().unwrap_or(""))
        });
    }
    if !receiver.is_member() {
        return false;
    }
    let Some(property) = receiver.f("property") else { return false };
    let property = static_property_name(property, receiver.flag("computed"));
    property == "headers" || property == "searchParams"
}

/// `endpointArgument`: the literal URL argument for recognized network callees.
pub fn endpoint_argument(
    name: &str,
    args: &[N<'_>],
    callee: N<'_>,
    receiver_fact: Option<OpenReceiverFact>,
) -> Option<String> {
    if receiver_fact == Some(OpenReceiverFact::Window) {
        return None;
    }
    let arg = |index: usize| args.get(index).copied();
    if name == "fetch" || name.ends_with(".fetch") || name == "WebSocket" {
        return string_value(arg(0));
    }
    if name.ends_with(".open") {
        return xhr_open_url(name, arg(0), arg(1), receiver_fact);
    }
    let method = ["get", "post", "put", "patch", "delete", "request"]
        .into_iter()
        .find(|candidate| name == *candidate || name.ends_with(&format!(".{candidate}")));
    if let Some(method) = method {
        let value = string_value(arg(0));
        // Only get and delete also belong to the keyed-collection APIs, whose
        // keys are header, field, and parameter names rather than URLs or paths.
        return match value {
            Some(ref text)
                if (method == "get" || method == "delete")
                    && !is_request_url_literal(text)
                    && is_keyed_collection_receiver(callee) =>
            {
                None
            }
            other => other,
        };
    }
    if name.ends_with("loadURL") {
        return string_value(arg(0));
    }
    None
}

/// `storageKind`: classify a recognized storage API call name.
pub fn storage_kind(name: &str) -> Option<&'static str> {
    if name.contains("localStorage.") {
        return Some("local-storage");
    }
    if name.contains("sessionStorage.") {
        return Some("session-storage");
    }
    if name.ends_with("indexedDB.open") {
        return Some("indexed-db");
    }
    if name.ends_with("caches.open") {
        return Some("cache-storage");
    }
    if name == "Database" || name.ends_with(".Database") {
        return Some("sqlite");
    }
    None
}

/// `memberPropertyName`: a member property only when its syntax commits an exact name.
fn member_property_name(node: N<'_>) -> String {
    let Some(property) = node.f("property") else { return String::new() };
    let computed = node.flag("computed");
    if computed && !property.is_string_literal() && !property.is_numeric_literal() {
        return format!("[computed@{}]", property.start());
    }
    static_property_name(property, computed)
}

/// `calleeName`: a dotted callee name from member syntax.
pub fn callee_name(node: N<'_>) -> String {
    let mut segments: Vec<String> = Vec::new();
    let mut node = node;
    while node.is_member() {
        // Dynamic keys retain their syntax identity instead of inventing a name.
        segments.push(member_property_name(node));
        match node.f("object") {
            Some(object) => node = object,
            None => break,
        }
    }
    let base = if node.is_identifier() {
        node.name().unwrap_or("")
    } else if node.is(Kind::Import) {
        "import"
    } else {
        ""
    };
    segments.push(base.to_string());
    segments.reverse();
    match segments.iter().position(|segment| !segment.is_empty()) {
        None => String::new(),
        Some(first) => segments[first..].join("."),
    }
}

/// `stringValue`: a string literal value without evaluating an expression.
pub fn string_value(node: Option<N<'_>>) -> Option<String> {
    match read_exact_literal(node?) {
        Some(Primitive::Str(text)) => Some(text),
        _ => None,
    }
}

/// `argumentValue`: a string or numeric argument literal.
pub fn argument_value(node: Option<N<'_>>) -> Option<String> {
    let node = node?;
    if node.is_numeric_literal() {
        return Some(js_number_to_string(node.num("value").unwrap_or(f64::NAN)));
    }
    string_value(Some(node))
}

/// `prefixedArgument`: prefix a static argument value when one is available.
pub fn prefixed_argument(prefix: &str, node: Option<N<'_>>) -> Option<String> {
    argument_value(node).map(|value| format!("{prefix}{value}"))
}

/// `detectVendors`: known bundler/framework marker strings.
pub fn detect_vendors(source: &str) -> Vec<String> {
    const PATTERNS: [(&str, &[&str]); 10] = [
        ("webpack", &["__webpack_require__", "webpackChunk"]),
        ("Rspack", &["__webpack_require__.f", "rspackChunk"]),
        ("Vite", &["__vite__", "import.meta.hot"]),
        ("Rollup", &["ROLLUP_FILE_URL", "import.meta.ROLLUP"]),
        ("esbuild", &["__commonJS", "__esm"]),
        ("React", &["React.createElement", "react/jsx-runtime"]),
        ("Vue", &["__VUE__", "createApp("]),
        ("Next.js", &["__NEXT_DATA__", "/_next/"]),
        ("Angular", &["\u{275}\u{275}defineComponent"]),
        ("Svelte", &["svelte/internal"]),
    ];
    PATTERNS
        .iter()
        .filter(|(_, patterns)| patterns.iter().any(|pattern| source.contains(pattern)))
        .map(|(name, _)| (*name).to_string())
        .collect()
}
