//! Port of `javascriptStaticAnalysisBundler.ts`: Webpack/Rspack chunk registrations and
//! esbuild helper wrappers.

use super::super::ast::{walk, Kind, N};
use super::super::static_types::{BundlerModule, BundlerRegistration};
use super::super::util::{compare_code_points, composite_key, range, sha256_text, sorted_unique};
use super::fingerprint::{collect_javascript_exports, fingerprint_javascript_ast};
use super::helpers::{
    argument_value, callee_name, chunk_runtime, factory_require_name, module_factory,
    module_property_name, sorted_set, static_array_values, StaticValues,
};
use super::state::{Accumulator, Ctx, ModuleRange};
use serde_json::{json, Value};

/// `registrationKey`: the static semantic content used to deduplicate registrations.
pub fn registration_key(registration: &BundlerRegistration) -> String {
    // Collision-free tuple: chunk/module keys are variable-length source-derived lists.
    composite_key(&[
        Value::from(registration.runtime.as_str()),
        json!(registration.chunk_keys),
        Value::from(registration.unknown_chunk_keys.to_string()),
        Value::Array(
            registration
                .modules
                .iter()
                .map(|module| json!([module.module_key, module.source_sha256]))
                .collect(),
        ),
    ])
}

/// `sortedUnique(registrations, registrationKey)`.
pub fn sorted_unique_registrations(registrations: Vec<BundlerRegistration>) -> Vec<BundlerRegistration> {
    sorted_unique(registrations, registration_key)
}

/// `inspectBundlerRegistration`: a Webpack/Rspack push call and its module table.
pub fn inspect_bundler_registration(call: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(runtime) = chunk_runtime(call) else { return };
    let args = call.nodes("arguments");
    let Some(entry) = args.first().filter(|entry| entry.is(Kind::ArrayExpression)) else { return };
    let elements = entry.list("elements");
    let element = |index: usize| elements.get(index).copied().flatten();
    let chunk_ids = element(0);
    let table = element(1);
    let runtime_value = runtime_metadata(elements.get(2).copied());
    let (Some(chunk_ids), Some(table)) = (chunk_ids, table) else { return };
    if !chunk_ids.is(Kind::ArrayExpression) || !table.is(Kind::ObjectExpression) {
        return;
    }
    let recovered = recover_bundler_modules(table, &runtime, &mut ctx.acc);
    let chunk_keys = static_array_values(chunk_ids);
    ctx.acc.unknown_findings += chunk_keys.unknown;
    ctx.acc.unknown_findings += runtime_value.unknown_entry_module_keys
        + runtime_value.unknown_async_chunk_keys
        + recovered.unknown_async_chunk_keys;
    let mut async_chunk_keys = runtime_value.async_chunk_keys.clone();
    async_chunk_keys.extend(recovered.async_chunk_keys.iter().cloned());
    let async_chunk_keys = sorted_set(async_chunk_keys);
    let mut modules = recovered.modules;
    modules.sort_by(|left, right| compare_code_points(&left.module_key, &right.module_key));
    let registration = BundlerRegistration {
        bundler: if runtime.to_lowercase().contains("rspack") { "rspack" } else { "webpack" }.into(),
        runtime,
        chunk_keys: chunk_keys.values,
        unknown_chunk_keys: chunk_keys.unknown,
        runtime_require_name: runtime_value.require_name,
        runtime_module_cache_status: bundler_module_cache_status(ctx),
        entry_module_keys: runtime_value.entry_module_keys,
        unknown_entry_module_keys: runtime_value.unknown_entry_module_keys,
        async_chunk_keys,
        unknown_async_chunk_keys: runtime_value.unknown_async_chunk_keys
            + recovered.unknown_async_chunk_keys,
        modules,
        location: range(call),
    };
    push_registration(ctx, registration);
}

/// `inspectEsbuildWrapper`: esbuild helper wrappers and their literal module tables.
pub fn inspect_esbuild_wrapper(call: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = call.f("callee") else { return };
    let name = callee_name(callee);
    let wrapper_kind = if name == "__commonJS" || name.ends_with(".__commonJS") {
        Some("commonjs")
    } else if name == "__esm" || name.ends_with(".__esm") {
        Some("esm")
    } else {
        None
    };
    let args = call.nodes("arguments");
    let table = args.first().copied();
    let (Some(wrapper_kind), Some(table)) = (wrapper_kind, table) else { return };
    if !table.is(Kind::ObjectExpression) {
        return;
    }
    let runtime = format!("esbuild-{wrapper_kind}");
    let recovered = recover_bundler_modules(table, &runtime, &mut ctx.acc);
    if recovered.modules.is_empty() {
        return;
    }
    ctx.acc.unknown_findings += recovered.unknown_async_chunk_keys;
    let mut modules = recovered.modules;
    modules.sort_by(|left, right| compare_code_points(&left.module_key, &right.module_key));
    let registration = BundlerRegistration {
        bundler: "esbuild".into(),
        runtime,
        chunk_keys: vec![format!("{wrapper_kind}@{}", call.start())],
        unknown_chunk_keys: 0,
        runtime_require_name: None,
        runtime_module_cache_status: "not-observed".into(),
        entry_module_keys: Vec::new(),
        unknown_entry_module_keys: 0,
        async_chunk_keys: recovered.async_chunk_keys,
        unknown_async_chunk_keys: recovered.unknown_async_chunk_keys,
        modules,
        location: range(call),
    };
    push_registration(ctx, registration);
}

fn push_registration(ctx: &mut Ctx<'_>, registration: BundlerRegistration) {
    let key = format!("registration\0{}", registration_key(&registration));
    if ctx.acc.reserve(key) {
        ctx.acc.registrations.push(registration);
    }
}

struct RecoveredBundlerModules {
    modules: Vec<BundlerModule>,
    async_chunk_keys: Vec<String>,
    unknown_async_chunk_keys: u64,
}

fn recover_bundler_modules(
    table: N<'_>,
    runtime: &str,
    acc: &mut Accumulator,
) -> RecoveredBundlerModules {
    let mut modules = Vec::new();
    let mut async_chunk_keys = Vec::new();
    let mut unknown_async_chunk_keys = 0u64;
    for property in table.nodes("properties") {
        let Some(recovered) = recover_bundler_module(property, runtime, acc) else { continue };
        modules.push(recovered.0);
        async_chunk_keys.extend(recovered.1.values);
        unknown_async_chunk_keys += recovered.1.unknown;
    }
    RecoveredBundlerModules { modules, async_chunk_keys, unknown_async_chunk_keys }
}

fn recover_bundler_module(
    property: N<'_>,
    runtime: &str,
    acc: &mut Accumulator,
) -> Option<(BundlerModule, StaticValues)> {
    let factory = module_factory(property)?;
    let key = module_property_name(property);
    if key.starts_with("[computed@") || key.starts_with("[unknown@") {
        acc.unknown_findings += 1;
    }
    let fingerprint = fingerprint_javascript_ast(factory);
    let exports = collect_javascript_exports(factory);
    let require_name = factory_require_name(factory);
    let async_chunks = collect_bundler_async_chunk_keys(factory, require_name.as_deref());
    acc.module_range_index.add(ModuleRange {
        start: i64::from(factory.start()),
        end: i64::from(factory.end()),
        key: key.clone(),
        runtime: runtime.to_string(),
        require_name: require_name.clone(),
    });
    Some((
        BundlerModule {
            module_key: key,
            factory_require_name: require_name,
            source_sha256: sha256_text(factory.text()),
            structural_fingerprint_sha256: fingerprint,
            structural_fingerprint_algorithm: "babel-ast-v1".into(),
            exports: exports.values,
            location: range(factory),
        },
        async_chunks,
    ))
}

struct RuntimeMetadata {
    require_name: Option<String>,
    entry_module_keys: Vec<String>,
    unknown_entry_module_keys: u64,
    async_chunk_keys: Vec<String>,
    unknown_async_chunk_keys: u64,
}

/// `runtimeMetadata`: `element` is `entry.elements[2]` (`None` outer = absent, inner = hole).
fn runtime_metadata(element: Option<Option<N<'_>>>) -> RuntimeMetadata {
    let node = element.flatten();
    let function = node.filter(|node| is_bundler_function(*node));
    let Some(function) = function else {
        return RuntimeMetadata {
            require_name: None,
            entry_module_keys: Vec::new(),
            unknown_entry_module_keys: u64::from(node.is_some()),
            async_chunk_keys: Vec::new(),
            unknown_async_chunk_keys: 0,
        };
    };
    let params = function.list("params");
    let require_name = params
        .first()
        .copied()
        .flatten()
        .filter(|parameter| parameter.is_identifier())
        .map(|parameter| parameter.name().unwrap_or("").to_string());
    let Some(require_name) = require_name else {
        return RuntimeMetadata {
            require_name: None,
            entry_module_keys: Vec::new(),
            unknown_entry_module_keys: 1,
            async_chunk_keys: Vec::new(),
            unknown_async_chunk_keys: 0,
        };
    };
    let entries = collect_bundler_call_argument_values(function, &require_name);
    let async_chunks = collect_bundler_async_chunk_keys(function, Some(&require_name));
    RuntimeMetadata {
        require_name: Some(require_name),
        entry_module_keys: entries.values,
        unknown_entry_module_keys: entries.unknown,
        async_chunk_keys: async_chunks.values,
        unknown_async_chunk_keys: async_chunks.unknown,
    }
}

fn collect_bundler_async_chunk_keys(factory: N<'_>, require_name: Option<&str>) -> StaticValues {
    match require_name {
        None => StaticValues { values: Vec::new(), unknown: 0 },
        Some(name) => collect_bundler_call_argument_values(factory, &format!("{name}.e")),
    }
}

fn collect_bundler_call_argument_values(factory: N<'_>, callee: &str) -> StaticValues {
    let mut values: Vec<String> = Vec::new();
    let mut unknown = 0u64;
    walk(
        factory,
        |node, _| {
            if (node.is(Kind::CallExpression) || node.is(Kind::NewExpression))
                && node.f("callee").is_some_and(|c| callee_name(c) == callee)
            {
                match argument_value(node.nodes("arguments").first().copied()) {
                    None => unknown += 1,
                    Some(value) => values.push(value),
                }
            }
            true
        },
        |_, _| {},
    );
    StaticValues { values: sorted_set(values), unknown }
}

fn is_bundler_function(node: N<'_>) -> bool {
    matches!(
        node.kind(),
        Kind::FunctionExpression | Kind::ArrowFunctionExpression | Kind::ObjectMethod
    )
}

/// `/\b(?:__webpack_module_cache__|__rspack_module_cache__|installedModules)\b/u`.
fn bundler_module_cache_status(ctx: &Ctx<'_>) -> String {
    let observed = *ctx.acc.module_cache_observed.get_or_init(|| {
        let source = ctx.source();
        let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        ["__webpack_module_cache__", "__rspack_module_cache__", "installedModules"].iter().any(|needle| {
            source.match_indices(needle).any(|(index, _)| {
                let before_ok = index == 0 || !is_word(source.as_bytes()[index - 1]);
                let after = index + needle.len();
                let after_ok = after >= source.len() || !is_word(source.as_bytes()[after]);
                before_ok && after_ok
            })
        })
    });
    if observed { "observed" } else { "not-observed" }.into()
}
