//! Port of `javascriptSemanticAsyncEffects.ts`: explicit EventEmitter and Node timer candidates.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::static_property_name;
use crate::jsgraph::ir::{
    JsNumber, ProjectedResultBinding, SemanticCallable, SemanticEventOperation, SemanticTimerOperation,
};

use super::data_effect_helpers::{
    ancestors_nearest_first, assigned_semantic_result_bindings, data_effect_literal_string, data_effect_member_callee,
    projected_result_facts, scalar_assigned_result_binding, traverse_data_effects,
};
use super::provenance::semantic_builtin_namespace_path;
use super::state::{
    resolve_semantic_binding_state, semantic_resolution_blocked, BindingIx, SemanticAnalysisState,
};

const EVENT_REGISTER_METHODS: [&str; 5] = ["on", "once", "addListener", "prependListener", "prependOnceListener"];
const EVENT_REMOVE_METHODS: [&str; 3] = ["off", "removeListener", "removeAllListeners"];
const TIMER_SCHEDULE_METHODS: [&str; 3] = ["setTimeout", "setInterval", "setImmediate"];
const TIMER_CANCEL_METHODS: [&str; 3] = ["clearTimeout", "clearInterval", "clearImmediate"];

/// `AsyncEffectAnalysis`.
#[derive(Clone, Debug, Default)]
pub struct AsyncEffectAnalysis {
    pub event_operations: Vec<SemanticEventOperation>,
    pub timer_operations: Vec<SemanticTimerOperation>,
}

struct TimerCandidate<'a> {
    node: N<'a>,
    method: &'static str,
    kind: &'static str,
    owner_callable_id: Option<String>,
    handle_binding_id: Option<String>,
    projected_result_bindings: Vec<ProjectedResultBinding>,
}

/// Recover explicit EventEmitter and Node timer candidates from inert syntax
/// (`collectJavaScriptSemanticAsyncEffects`).
pub fn collect_semantic_async_effects<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> AsyncEffectAnalysis {
    let mut events = Vec::new();
    let mut timers = Vec::new();
    let callable_ids: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    traverse_data_effects(root, &callable_ids, |node, _parent, owner| {
        if node.is_call() {
            let owner = owner.map(String::from);
            collect_event(node, owner.clone(), state, &mut events);
            collect_timer(node, owner, state, &mut timers);
        }
    });
    AsyncEffectAnalysis { event_operations: events, timer_operations: resolve_timers(&timers) }
}

fn event_method(name: &str) -> Option<&'static str> {
    EVENT_REGISTER_METHODS
        .iter()
        .chain(EVENT_REMOVE_METHODS.iter())
        .chain(["emit"].iter())
        .copied()
        .find(|candidate| *candidate == name)
}

fn collect_event<'a>(
    node: N<'a>,
    owner_callable_id: Option<String>,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<SemanticEventOperation>,
) {
    let Some(member) = data_effect_member_callee(node) else { return };
    let Some(property) = member.f("property") else { return };
    let Some(method) = event_method(&static_property_name(property, member.flag("computed"))) else { return };
    let kind = if EVENT_REGISTER_METHODS.contains(&method) {
        "register"
    } else if EVENT_REMOVE_METHODS.contains(&method) {
        "remove"
    } else {
        "dispatch"
    };
    let arguments = node.list("arguments");
    let event_argument = arguments.first().copied().flatten();
    let listener_argument = arguments.get(1).copied().flatten();
    let (emitter_key, emitter_binding_id, emitter_complete) = match member.f("object") {
        Some(object) => emitter_identity(object, state),
        None => (String::new(), None, false),
    };
    let event_name = data_effect_literal_string(event_argument);
    output.push(SemanticEventOperation {
        event_id: format!("event:{kind}:{}:{}", node.start(), node.end()),
        kind: kind.into(),
        method: method.into(),
        location: node.loc(),
        owner_callable_id,
        emitter_key,
        emitter_binding_id,
        listener_binding_id: binding_id(listener_argument, state),
        listener_location: listener_argument.map(|argument| argument.loc()),
        resolution: if event_name.is_none() {
            "unresolved"
        } else if emitter_complete {
            "complete"
        } else {
            "partial"
        }
        .into(),
        event_name,
    });
}

fn emitter_identity<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> (String, Option<String>, bool) {
    if node.is_identifier() {
        let name = node.name().unwrap_or("");
        return match resolve_semantic_binding_state(state, node, name) {
            Some(binding) => {
                let id = state.bindings[binding].binding_id.clone();
                (format!("binding:{id}"), Some(id), true)
            }
            None => (format!("global:{name}"), None, !semantic_resolution_blocked(state, node, name)),
        };
    }
    if node.is(Kind::ThisExpression) {
        return ("this".to_string(), None, true);
    }
    (format!("expression:{}:{}", node.start(), node.end()), None, false)
}

fn collect_timer<'a>(
    node: N<'a>,
    owner_callable_id: Option<String>,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<TimerCandidate<'a>>,
) {
    let Some(callee) = node.f("callee") else { return };
    let Some(method) = timer_method(callee, state) else { return };
    let kind = if TIMER_SCHEDULE_METHODS.contains(&method) { "schedule" } else { "cancel" };
    let projected = assigned_semantic_result_bindings(node, ancestors_nearest_first(node), state);
    let first_argument = node.list("arguments").first().copied().flatten();
    output.push(TimerCandidate {
        node,
        method,
        kind,
        owner_callable_id,
        handle_binding_id: if kind == "schedule" {
            scalar_assigned_result_binding(&projected)
        } else {
            binding_id(first_argument, state)
        },
        projected_result_bindings: if kind == "schedule" { projected_result_facts(&projected) } else { Vec::new() },
    });
}

fn resolve_timers(candidates: &[TimerCandidate<'_>]) -> Vec<SemanticTimerOperation> {
    let mut schedules_by_binding: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.kind != "schedule" {
            continue;
        }
        let ids = candidate
            .handle_binding_id
            .iter()
            .map(String::as_str)
            .chain(candidate.projected_result_bindings.iter().map(|binding| binding.binding_id.as_str()));
        for id in ids {
            schedules_by_binding.entry(id).or_default().push(index);
        }
    }
    candidates
        .iter()
        .map(|candidate| {
            let linked: &[usize] = match (&candidate.handle_binding_id, candidate.kind) {
                (Some(handle), "cancel") => schedules_by_binding.get(handle.as_str()).map_or(&[], Vec::as_slice),
                _ => &[],
            };
            let single_direct = linked.len() == 1
                && !candidates[linked[0]].projected_result_bindings.iter().any(|binding| {
                    candidate.handle_binding_id.as_deref() == Some(binding.binding_id.as_str())
                });
            let resolution = if candidate.kind == "schedule" || single_direct {
                "complete"
            } else if linked.len() > 1 {
                "partial"
            } else {
                "unresolved"
            };
            SemanticTimerOperation {
                timer_id: timer_id(candidate),
                kind: candidate.kind.into(),
                method: candidate.method.into(),
                location: candidate.node.loc(),
                owner_callable_id: candidate.owner_callable_id.clone(),
                handle_binding_id: candidate.handle_binding_id.clone(),
                projected_result_bindings: candidate.projected_result_bindings.clone(),
                linked_timer_id: (linked.len() == 1).then(|| timer_id(&candidates[linked[0]])),
                delay_milliseconds: timer_delay(candidate),
                resolution: resolution.into(),
            }
        })
        .collect()
}

fn timer_method<'a>(callee: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<&'static str> {
    if callee.is_identifier() {
        let name = callee.name().unwrap_or("");
        return match resolve_semantic_binding_state(state, callee, name) {
            None => {
                let method = admitted_timer_method(name)?;
                if semantic_resolution_blocked(state, callee, name) {
                    None
                } else {
                    Some(method)
                }
            }
            Some(binding) => timer_method_from_binding(state, binding),
        };
    }
    if !callee.is_member() {
        return None;
    }
    let method = admitted_timer_method(&static_property_name(callee.f("property")?, callee.flag("computed")))?;
    let object = callee.f("object")?;
    if !object.is_identifier() {
        return None;
    }
    let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
    timer_namespace_binding(state, binding).then_some(method)
}

fn admitted_timer_method(value: &str) -> Option<&'static str> {
    TIMER_SCHEDULE_METHODS.iter().chain(TIMER_CANCEL_METHODS.iter()).copied().find(|candidate| *candidate == value)
}

fn timer_method_from_binding(state: &SemanticAnalysisState<'_>, binding: BindingIx) -> Option<&'static str> {
    for origin in &state.bindings[binding].direct_origins {
        if !timer_module(&origin.specifier) {
            continue;
        }
        if let Some(method) = admitted_timer_method(origin.imported_path.last().map_or("", String::as_str)) {
            return Some(method);
        }
    }
    None
}

fn timer_namespace_binding(state: &SemanticAnalysisState<'_>, binding: Option<BindingIx>) -> bool {
    binding.is_some_and(|binding| {
        state.bindings[binding]
            .direct_origins
            .iter()
            .any(|origin| timer_module(&origin.specifier) && semantic_builtin_namespace_path(&origin.imported_path))
    })
}

fn timer_module(specifier: &str) -> bool {
    specifier == "timers" || specifier == "node:timers"
}

fn binding_id<'a>(node: Option<N<'a>>, state: &SemanticAnalysisState<'a>) -> Option<String> {
    let node = node?;
    if !node.is_identifier() {
        return None;
    }
    resolve_semantic_binding_state(state, node, node.name().unwrap_or(""))
        .map(|binding| state.bindings[binding].binding_id.clone())
}

fn timer_delay(candidate: &TimerCandidate<'_>) -> Option<JsNumber> {
    if candidate.kind != "schedule" || candidate.method == "setImmediate" {
        return None;
    }
    let delay = candidate.node.list("arguments").get(1).copied().flatten()?;
    if delay.is_numeric_literal() {
        delay.num("value").map(JsNumber)
    } else {
        None
    }
}

fn timer_id(candidate: &TimerCandidate<'_>) -> String {
    format!("timer:{}:{}:{}", candidate.kind, candidate.node.start(), candidate.node.end())
}
