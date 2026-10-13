//! Port of `javascriptSemanticChildProcesses.ts`: explicit asynchronous `node:child_process`
//! ownership candidates.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::static_property_name;
use crate::jsgraph::ir::{
    ProjectedResultBinding, SemanticCallable, SemanticChildProcessInteraction, SemanticChildProcessSpawn,
};
use crate::jsgraph::util::compare_code_points;

use super::data_effect_helpers::{
    ancestors_nearest_first, assigned_semantic_result_bindings, data_effect_literal_string, data_effect_member_callee,
    projected_result_facts, scalar_assigned_result_binding, traverse_data_effects,
};
use super::provenance::semantic_builtin_namespace_path;
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};

const CHILD_PROCESS_METHODS: [&str; 4] = ["spawn", "exec", "execFile", "fork"];
const CHILD_LISTENER_METHODS: [&str; 3] = ["on", "once", "addListener"];

/// `ChildProcessAnalysis`.
#[derive(Clone, Debug, Default)]
pub struct ChildProcessAnalysis {
    pub child_process_spawns: Vec<SemanticChildProcessSpawn>,
    pub child_process_interactions: Vec<SemanticChildProcessInteraction>,
}

struct SpawnCandidate<'a> {
    node: N<'a>,
    method: &'static str,
    owner_callable_id: Option<String>,
    result_binding_id: Option<String>,
    projected_result_bindings: Vec<ProjectedResultBinding>,
}

/// Recover explicit asynchronous node:child_process ownership candidates
/// (`collectJavaScriptSemanticChildProcesses`).
pub fn collect_semantic_child_processes<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> ChildProcessAnalysis {
    let callable_ids: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    let candidates = collect_spawns(root, state, &callable_ids);
    let child_process_spawns = candidates.iter().map(immutable_spawn).collect();
    let child_process_interactions = collect_interactions(root, state, &callable_ids, &candidates);
    ChildProcessAnalysis { child_process_spawns, child_process_interactions }
}

fn collect_spawns<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
) -> Vec<SpawnCandidate<'a>> {
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        let Some(callee) = node.f("callee") else { return };
        let Some(method) = child_process_method(callee, state) else { return };
        let projected = assigned_semantic_result_bindings(node, ancestors_nearest_first(node), state);
        output.push(SpawnCandidate {
            node,
            method,
            owner_callable_id: owner.map(String::from),
            result_binding_id: scalar_assigned_result_binding(&projected),
            projected_result_bindings: projected_result_facts(&projected),
        });
    });
    output
}

fn immutable_spawn(candidate: &SpawnCandidate<'_>) -> SemanticChildProcessSpawn {
    let options = spawn_options(candidate);
    let command = data_effect_literal_string(candidate.node.list("arguments").first().copied().flatten());
    SemanticChildProcessSpawn {
        process_id: spawn_id(candidate),
        method: candidate.method.into(),
        location: candidate.node.loc(),
        owner_callable_id: candidate.owner_callable_id.clone(),
        result_binding_id: candidate.result_binding_id.clone(),
        projected_result_bindings: candidate.projected_result_bindings.clone(),
        resolution: if command.is_none() { "partial" } else { "complete" }.into(),
        command,
        argv_count: spawn_argv_count(candidate),
        environment_supplied: object_property(options, "env").is_some(),
        stdio_mode: stdio_mode(options),
    }
}

fn collect_interactions<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
    spawns: &[SpawnCandidate<'a>],
) -> Vec<SemanticChildProcessInteraction> {
    let mut output = Vec::new();
    let mut spawn_by_node: HashMap<NodeId, usize> = HashMap::new();
    let mut spawns_by_binding: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, spawn) in spawns.iter().enumerate() {
        spawn_by_node.insert(spawn.node.id, index);
        let ids = spawn
            .result_binding_id
            .iter()
            .map(String::as_str)
            .chain(spawn.projected_result_bindings.iter().map(|binding| binding.binding_id.as_str()));
        for id in ids {
            spawns_by_binding.entry(id).or_default().push(index);
        }
    }
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        if let Some(interaction) =
            child_interaction(node, owner.map(String::from), state, spawns, &spawn_by_node, &spawns_by_binding)
        {
            output.push(interaction);
        }
    });
    output
}

fn child_interaction<'a>(
    node: N<'a>,
    owner_callable_id: Option<String>,
    state: &SemanticAnalysisState<'a>,
    spawns: &[SpawnCandidate<'a>],
    spawn_by_node: &HashMap<NodeId, usize>,
    spawns_by_binding: &HashMap<&str, Vec<usize>>,
) -> Option<SemanticChildProcessInteraction> {
    let member = data_effect_member_callee(node)?;
    let method = static_property_name(member.f("property")?, member.flag("computed"));
    let object = member.f("object")?;
    let binding = object_binding(object, state);
    let binding_id = binding.map(|ix| state.bindings[ix].binding_id.as_str());
    let linked: Vec<usize> = match spawn_by_node.get(&object.id) {
        Some(&direct) => vec![direct],
        None => match binding_id {
            None => Vec::new(),
            Some(id) => spawns_by_binding.get(id).cloned().unwrap_or_default(),
        },
    };
    if linked.is_empty() {
        return None;
    }
    let first_argument = node.list("arguments").first().copied().flatten();
    let (kind, interaction_method, event_name) = classify_interaction(&method, first_argument)?;
    let listener = node.list("arguments").get(1).copied().flatten();
    let mut linked_ids: Vec<String> = linked.iter().map(|&index| spawn_id(&spawns[index])).collect();
    linked_ids.sort_by(|left, right| compare_code_points(left, right));
    Some(SemanticChildProcessInteraction {
        interaction_id: format!("child:{kind}:{}:{}", node.start(), node.end()),
        kind: kind.into(),
        method: interaction_method.into(),
        location: node.loc(),
        owner_callable_id,
        process_binding_id: binding_id.map(String::from),
        linked_process_ids: linked_ids,
        event_name: if kind == "listener" { event_name } else { None },
        signal_name: if kind == "signal" {
            Some(data_effect_literal_string(first_argument).unwrap_or_else(|| "SIGTERM".to_string()))
        } else {
            None
        },
        listener_location: if kind == "listener" { listener.map(|listener| listener.loc()) } else { None },
        resolution: if linked.len() == 1
            && !spawns[linked[0]]
                .projected_result_bindings
                .iter()
                .any(|projected| Some(projected.binding_id.as_str()) == binding_id)
        {
            "complete"
        } else {
            "partial"
        }
        .into(),
    })
}

/// `classifyInteraction`: `(kind, method, eventName)`.
fn classify_interaction(
    method: &str,
    argument: Option<N<'_>>,
) -> Option<(&'static str, &'static str, Option<String>)> {
    if method == "kill" {
        return Some(("signal", "kill", None));
    }
    let listener_method = CHILD_LISTENER_METHODS.iter().copied().find(|candidate| *candidate == method)?;
    let event_name = data_effect_literal_string(argument)?;
    if event_name == "exit" || event_name == "error" {
        Some(("listener", listener_method, Some(event_name)))
    } else {
        None
    }
}

fn child_process_method<'a>(callee: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<&'static str> {
    if callee.is_identifier() {
        let binding = resolve_semantic_binding_state(state, callee, callee.name().unwrap_or(""))?;
        return method_from_binding(state, binding);
    }
    if !callee.is_member() {
        return None;
    }
    let method = admitted_child_method(&static_property_name(callee.f("property")?, callee.flag("computed")))?;
    let object = callee.f("object")?;
    if !object.is_identifier() {
        return None;
    }
    let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
    child_process_namespace(state, binding).then_some(method)
}

fn method_from_binding(state: &SemanticAnalysisState<'_>, binding: BindingIx) -> Option<&'static str> {
    for origin in &state.bindings[binding].direct_origins {
        if !child_process_module(&origin.specifier) {
            continue;
        }
        if let Some(method) = admitted_child_method(origin.imported_path.last().map_or("", String::as_str)) {
            return Some(method);
        }
    }
    None
}

fn admitted_child_method(value: &str) -> Option<&'static str> {
    CHILD_PROCESS_METHODS.iter().copied().find(|candidate| *candidate == value)
}

fn child_process_namespace(state: &SemanticAnalysisState<'_>, binding: Option<BindingIx>) -> bool {
    binding.is_some_and(|binding| {
        state.bindings[binding].direct_origins.iter().any(|origin| {
            child_process_module(&origin.specifier) && semantic_builtin_namespace_path(&origin.imported_path)
        })
    })
}

fn child_process_module(specifier: &str) -> bool {
    specifier == "child_process" || specifier == "node:child_process"
}

fn spawn_options<'a>(candidate: &SpawnCandidate<'a>) -> Option<N<'a>> {
    let index = if candidate.method == "exec" { 1 } else { 2 };
    candidate.node.list("arguments").get(index).copied().flatten().filter(|value| value.is(Kind::ObjectExpression))
}

fn spawn_argv_count(candidate: &SpawnCandidate<'_>) -> Option<u64> {
    if candidate.method == "exec" {
        return None;
    }
    let args = candidate.node.list("arguments").get(1).copied().flatten()?;
    args.is(Kind::ArrayExpression).then(|| args.list_len("elements") as u64)
}

fn stdio_mode(options: Option<N<'_>>) -> String {
    let Some(property) = object_property(options, "stdio") else { return "default".into() };
    if !property.is(Kind::ObjectProperty) {
        return "default".into();
    }
    match property.f("value") {
        Some(value) if value.is_string_literal() => value.str("value").unwrap_or("").to_string(),
        Some(value) if value.is(Kind::ArrayExpression) => "array".into(),
        _ => "dynamic".into(),
    }
}

/// `{[env]: vars}` has a dynamic key; treating it as `env` would claim the caller supplied an
/// environment when the real key is unknown.
fn object_property<'a>(object: Option<N<'a>>, name: &str) -> Option<N<'a>> {
    object?.nodes("properties").into_iter().find(|property| {
        (property.is(Kind::ObjectMethod) || property.is(Kind::ObjectProperty))
            && property
                .f("key")
                .is_some_and(|key| static_property_name(key, property.flag("computed")) == name)
    })
}

fn object_binding<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<BindingIx> {
    if node.is_identifier() {
        resolve_semantic_binding_state(state, node, node.name().unwrap_or(""))
    } else {
        None
    }
}

fn spawn_id(candidate: &SpawnCandidate<'_>) -> String {
    format!("child:spawn:{}:{}", candidate.node.start(), candidate.node.end())
}
