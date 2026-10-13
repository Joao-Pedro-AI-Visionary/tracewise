//! Port target of `javascriptSemanticDerivedAnalysis.ts`: the derived collectors (calls,
//! promises, async effects, child processes, data effects, resources, objects, fingerprints).
//!
//! Module map (TS file -> module): `javascriptSemanticCalls` -> [`super::calls`], `Promises` ->
//! [`super::promises`], `AsyncEffects` -> [`super::async_effects`], `ChildProcesses` ->
//! [`super::child_processes`], `DataEffects` -> [`super::data_effects`], `DataEffectHelpers` ->
//! [`super::data_effect_helpers`], `Resources` -> [`super::resources`], `Objects` ->
//! [`super::objects`], `Fingerprints` -> [`super::fingerprints`].

use crate::jsgraph::ast::Ast;
use crate::jsgraph::ir::{
    SemanticArgumentFlow, SemanticBoundaryOperation, SemanticCallResultFlow, SemanticCallReturnFlow,
    SemanticCallSite, SemanticCallable, SemanticChildProcessInteraction, SemanticChildProcessSpawn,
    SemanticClosureCapture, SemanticConfigurationOperation, SemanticEventOperation, SemanticFrontier,
    SemanticFunctionFingerprint, SemanticObjectOperation, SemanticPromiseOperation, SemanticRequestOperation,
    SemanticResourceOperation, SemanticTimerOperation,
};

use super::async_effects::collect_semantic_async_effects;
use super::calls::collect_semantic_calls;
use super::child_processes::collect_semantic_child_processes;
use super::data_effects::collect_semantic_data_effects;
use super::fingerprints::{collect_semantic_fingerprints, FingerprintInput};
use super::objects::collect_semantic_objects;
use super::promises::collect_semantic_promises;
use super::resources::collect_semantic_resources;
use super::state::SemanticAnalysisState;

/// `DerivedSemanticAnalysis`: the 17 derived fields of the semantic IR.
#[derive(Clone, Debug, Default)]
pub struct DerivedSemantics {
    pub argument_flows: Vec<SemanticArgumentFlow>,
    pub call_result_flows: Vec<SemanticCallResultFlow>,
    pub call_return_flows: Vec<SemanticCallReturnFlow>,
    pub call_sites: Vec<SemanticCallSite>,
    pub boundary_operations: Vec<SemanticBoundaryOperation>,
    pub child_process_interactions: Vec<SemanticChildProcessInteraction>,
    pub child_process_spawns: Vec<SemanticChildProcessSpawn>,
    pub closure_captures: Vec<SemanticClosureCapture>,
    pub configuration_operations: Vec<SemanticConfigurationOperation>,
    pub event_operations: Vec<SemanticEventOperation>,
    pub frontiers: Vec<SemanticFrontier>,
    pub function_fingerprints: Vec<SemanticFunctionFingerprint>,
    pub object_operations: Vec<SemanticObjectOperation>,
    pub promise_operations: Vec<SemanticPromiseOperation>,
    pub request_operations: Vec<SemanticRequestOperation>,
    pub resource_operations: Vec<SemanticResourceOperation>,
    pub timer_operations: Vec<SemanticTimerOperation>,
}

/// `collectJavaScriptDerivedSemanticsSteps`: compose the bounded semantic passes after lexical
/// definitions are available. Each collector completes before the next starts.
pub(crate) fn collect_derived<'a>(
    ast: &'a Ast,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
    parser_partial: bool,
) -> DerivedSemantics {
    let root = ast.root();
    let calls = collect_semantic_calls(root, state, callables);
    let promise_operations = collect_semantic_promises(root, state, callables);
    let async_effects = collect_semantic_async_effects(root, state, callables);
    let child_processes = collect_semantic_child_processes(root, state, callables);
    let data_effects = collect_semantic_data_effects(root, state, callables);
    let resource_operations = collect_semantic_resources(root, state, callables);
    let object_operations = collect_semantic_objects(root, state, callables);
    let function_fingerprints = collect_semantic_fingerprints(&FingerprintInput {
        state,
        callables,
        call_sites: &calls.call_sites,
        closure_captures: &calls.closure_captures,
        promises: &promise_operations,
        events: &async_effects.event_operations,
        timers: &async_effects.timer_operations,
        child_process_spawns: &child_processes.child_process_spawns,
        child_process_interactions: &child_processes.child_process_interactions,
        request_operations: &data_effects.request_operations,
        resource_operations: &resource_operations,
        parser_partial,
    });
    DerivedSemantics {
        argument_flows: calls.argument_flows,
        call_result_flows: calls.call_result_flows,
        call_return_flows: calls.call_return_flows,
        call_sites: calls.call_sites,
        boundary_operations: data_effects.boundary_operations,
        child_process_interactions: child_processes.child_process_interactions,
        child_process_spawns: child_processes.child_process_spawns,
        closure_captures: calls.closure_captures,
        configuration_operations: data_effects.configuration_operations,
        event_operations: async_effects.event_operations,
        frontiers: calls.frontiers,
        function_fingerprints,
        object_operations,
        promise_operations,
        request_operations: data_effects.request_operations,
        resource_operations,
        timer_operations: async_effects.timer_operations,
    }
}
