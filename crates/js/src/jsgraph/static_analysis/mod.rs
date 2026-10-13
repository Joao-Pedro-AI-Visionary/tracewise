//! AST-only static analysis (port of `domain/javascript/javascriptStaticAnalysis*.ts`,
//! `electronStaticAnalysis*.ts`, `javascriptAstFingerprint.ts`, `javascriptSourceMapPaths.ts`).
//!
//! File map (REA → here):
//! - `javascriptStaticAnalysis.ts` → this file (`analyze_static_source`)
//! - `javascriptStaticAnalysisState.ts`, `javascriptStaticAnalysisFindings.ts` → `state.rs`
//! - `javascriptStaticAnalysisHelpers.ts` → `helpers.rs` (+ `posix.rs`, `uri.rs` for the Node
//!   `path.posix` / `decodeURIComponent` / `fileURLToPath` pieces it leans on)
//! - `javascriptStaticAnalysisCalls.ts` → `calls.rs`
//! - `javascriptStaticAnalysisBundler.ts` → `bundler.rs`
//! - `electronStaticAnalysis{Browser,Ipc,Native,Values}.ts` → `electron_*.rs`
//! - `javascriptAstFingerprint.ts` → `fingerprint.rs`
//! - `javascriptSourceMapPaths.ts` → `source_map_paths.rs`

mod bundler;
mod calls;
mod electron_browser;
mod electron_ipc;
mod electron_native;
mod electron_values;
mod fingerprint;
mod helpers;
mod posix;
mod source_map_paths;
mod state;
mod uri;

use std::collections::HashMap;

use super::ast::{walk, Ast, Kind, N};
use super::static_types::{ElectronStaticFindings, OpenReceiverFact, StaticAnalysis};

pub use bundler::{registration_key, sorted_unique_registrations};
pub use fingerprint::{
    collect_javascript_exports, fingerprint_javascript_ast, fingerprint_javascript_file,
    member_path, StaticExports,
};
pub use helpers::{
    argument_value, callee_name, chunk_runtime, detect_vendors, endpoint_argument,
    factory_require_name, module_factory, module_property_name, static_array_values, static_path,
    static_path_resolution_context, storage_kind, string_value,
};
pub use source_map_paths::{
    resolve_source_map_reference, SourceMapReference, SourceMapResolution,
};

use state::{finalize_located, Accumulator, Ctx};

/// Stack for the analysis thread: a few helpers (`staticPath`, filesystem-expression checks)
/// recurse over expression nesting exactly like REA, so deep input needs more than a test
/// thread's default stack. The pages are only touched when the input is that deep.
const ANALYSIS_STACK_BYTES: usize = 256 * 1024 * 1024;

/// `analyzeParsedJavaScriptStaticSource`: recover static structure from a parsed artifact.
///
/// `open_receivers` is the semantic layer's `classifyParsedJavaScriptOpenReceivers` map (key =
/// call `start`) and `electron_bindings` its `classifyParsedJavaScriptElectronBindings` map
/// (key = root identifier `start`). A source that failed to parse is handled by the caller with
/// [`StaticAnalysis::failed`].
pub fn analyze_static_source(
    source: &str,
    ast: &Ast,
    open_receivers: &HashMap<u32, OpenReceiverFact>,
    electron_bindings: &HashMap<u32, String>,
) -> StaticAnalysis {
    let run = || analyze_inner(source, ast, open_receivers, electron_bindings);
    std::thread::scope(|scope| {
        match std::thread::Builder::new().stack_size(ANALYSIS_STACK_BYTES).spawn_scoped(scope, crate::jsgraph::control::inherit(run)) {
            Ok(handle) => handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            Err(_) => run(),
        }
    })
}

fn analyze_inner(
    source: &str,
    ast: &Ast,
    open_receivers: &HashMap<u32, OpenReceiverFact>,
    electron_bindings: &HashMap<u32, String>,
) -> StaticAnalysis {
    let mut ctx = Ctx {
        ast,
        acc: Accumulator::new(ast.source.len16()),
        open_receivers,
        electron_bindings,
    };
    // The Babel `File` node above the tree root is visited too; it carries no findings.
    ctx.acc.visited_nodes = 1;
    walk(
        ast.root(),
        |node, _| {
            ctx.acc.visited_nodes += 1;
            inspect_node(node, &mut ctx);
            true
        },
        |_, _| {},
    );
    calls::add_source_map_directives(ast, &mut ctx.acc);
    finalize(source, ast, ctx.acc)
}

fn finalize(source: &str, ast: &Ast, acc: Accumulator) -> StaticAnalysis {
    let parser_errors = ast.error_count as u64;
    let mut limitations: Vec<String> = Vec::new();
    if parser_errors != 0 {
        limitations.push("The parser recovered from syntax errors; affected facts are partial.".into());
    }
    if acc.unknown_findings != 0 {
        limitations.push(
            "One or more static keys, expressions, or Electron boundary values were dynamic and remain unknown."
                .into(),
        );
    }
    limitations.push("JavaScript syntax was parsed as data and was never evaluated.".into());
    let Accumulator {
        references,
        endpoints,
        storage,
        roles,
        source_maps,
        registrations,
        browser_windows,
        context_bridge_apis,
        ipc,
        sender_validations,
        utility_processes,
        native_addon_bindings,
        module_range_index,
        visited_nodes,
        unknown_findings,
        ..
    } = acc;
    let modules = &module_range_index;
    StaticAnalysis {
        parse_status: if parser_errors > 0 || unknown_findings > 0 { "partial" } else { "complete" }.into(),
        parse_error_count: parser_errors,
        visited_ast_nodes: visited_nodes,
        references: finalize_located(references, modules),
        endpoints: finalize_located(endpoints, modules),
        storage: finalize_located(storage, modules),
        bundler_registrations: sorted_unique_registrations(registrations),
        role_paths: finalize_located(roles, modules),
        source_map_urls: source_maps,
        vendors: detect_vendors(source),
        electron: ElectronStaticFindings {
            browser_windows: finalize_located(browser_windows, modules),
            context_bridge_apis: finalize_located(context_bridge_apis, modules),
            ipc: finalize_located(ipc, modules),
            sender_validations: finalize_located(sender_validations, modules),
            utility_processes: finalize_located(utility_processes, modules),
            native_addon_bindings: finalize_located(native_addon_bindings, modules),
        },
        limitations,
    }
}

/// `inspectNode`: one node of the shared inert traversal.
fn inspect_node(node: N<'_>, ctx: &mut Ctx<'_>) {
    // inspectElectronStaticNode
    electron_browser::inspect_electron_browser_node(node, ctx);
    electron_ipc::inspect_electron_ipc_node(node, ctx);
    electron_native::inspect_electron_native_node(node, ctx);
    match node.kind() {
        Kind::CallExpression => {
            bundler::inspect_bundler_registration(node, ctx);
            bundler::inspect_esbuild_wrapper(node, ctx);
            calls::inspect_call(node, ctx);
        }
        Kind::OptionalCallExpression | Kind::NewExpression => calls::inspect_call(node, ctx),
        _ => {}
    }
    match node.kind() {
        Kind::ImportDeclaration | Kind::ExportAllDeclaration => {
            if let Some(source) = node.f("source") {
                calls::add_reference(
                    ctx,
                    node,
                    "static-import",
                    Some(source.str("value").unwrap_or("").to_string()),
                );
            }
        }
        Kind::ExportNamedDeclaration => {
            if let Some(source) = node.f("source") {
                calls::add_reference(
                    ctx,
                    node,
                    "static-import",
                    Some(source.str("value").unwrap_or("").to_string()),
                );
            }
        }
        Kind::ImportExpression => {
            let specifier = helpers::string_value(node.f("source"));
            calls::add_reference(ctx, node, "dynamic-import", specifier);
        }
        _ => {}
    }
    if node.is(Kind::ObjectProperty) {
        calls::inspect_route_property(node, ctx);
        calls::inspect_role_property(node, ctx);
    }
}
