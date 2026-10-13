//! Port of `electronStaticAnalysisIpc.ts`: Electron IPC operations and sender validation.

use serde_json::Value;

use super::super::ast::{Kind, N};
use super::super::ast_values::static_property_name;
use super::super::ir::Primitive;
use super::super::static_types::{
    ElectronIpcFinding, ElectronSenderValidationFinding, ElectronStaticValue,
};
use super::super::util::{composite_key, js_number_to_string, range};
use super::electron_values::{
    bounded_expression, electron_callee_name, electron_static_value, handler_kind,
};
use super::helpers::callee_name;
use super::state::{add_located, Ctx};

/// `inspectElectronIpcNode`.
pub fn inspect_electron_ipc_node(node: N<'_>, ctx: &mut Ctx<'_>) {
    if node.is(Kind::CallExpression) {
        inspect_ipc_call(node, ctx);
        inspect_validation_call(node, ctx);
    }
    if node.is(Kind::BinaryExpression) {
        inspect_validation_comparison(node, ctx);
    }
}

struct IpcDescriptor {
    side: &'static str,
    operation: &'static str,
    mode: &'static str,
}

fn argument(node: N<'_>, index: usize) -> Option<N<'_>> {
    node.nodes("arguments").get(index).copied()
}

fn inspect_ipc_call(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    let name = electron_callee_name(callee, ctx);
    let Some(descriptor) = ipc_descriptor(&name) else { return };
    let channel_node = argument(node, 0);
    let channel_value = electron_static_value(channel_node);
    let channel = match (&channel_value.status[..], &channel_value.value) {
        ("literal", Primitive::Str(text)) => Some(text.clone()),
        _ => None,
    };
    let channel_expression = if channel.is_some() {
        None
    } else if channel_value.status == "dynamic" {
        channel_value.expression.clone()
    } else {
        Some(bounded_expression(channel_node))
    };
    let handler_node = if descriptor.mode == "listen" || descriptor.mode == "handle" {
        argument(node, 1)
    } else {
        None
    };
    let (handler_kind_value, handler_location) = if descriptor.mode == "send" || descriptor.mode == "invoke" {
        (None, None)
    } else {
        match handler_node {
            None => (Some("missing".to_string()), None),
            Some(handler) => (Some(handler_kind(handler).to_string()), Some(range(handler))),
        }
    };
    if channel.is_none() {
        ctx.acc.unknown_findings += 1;
    }
    if handler_kind_value.as_deref() == Some("missing") {
        ctx.acc.unknown_findings += 1;
    }
    let dedupe_key = format!(
        "electron-ipc\0{}\0{}\0{}",
        descriptor.side,
        descriptor.operation,
        channel.as_deref().or(channel_expression.as_deref()).unwrap_or("")
    );
    let finding = ElectronIpcFinding {
        side: descriptor.side.into(),
        operation: descriptor.operation.into(),
        mode: descriptor.mode.into(),
        handler_kind: handler_kind_value,
        handler_location,
        module_key: None,
        module_runtime: None,
        location: range(node),
        channel,
        channel_expression,
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.ipc, &dedupe_key, node, finding);
}

fn inspect_validation_comparison(node: N<'_>, ctx: &mut Ctx<'_>) {
    let operator = node.str("operator").unwrap_or("");
    if !["==", "===", "!=", "!==", "in"].contains(&operator) {
        return;
    }
    let (Some(left_node), Some(right_node)) = (node.f("left"), node.f("right")) else { return };
    let left = sender_subject(left_node);
    let right = sender_subject(right_node);
    if left.is_none() && right.is_none() {
        return;
    }
    let expected = if left.is_none() { left_node } else { right_node };
    add_validation(
        ctx,
        node,
        left.or(right).unwrap_or("sender-frame"),
        format!("comparison:{operator}"),
        electron_static_value(Some(expected)),
    );
}

fn inspect_validation_call(node: N<'_>, ctx: &mut Ctx<'_>) {
    let Some(callee) = node.f("callee") else { return };
    if !callee.is_member() {
        return;
    }
    let method = callee
        .f("property")
        .map(|property| static_property_name(property, callee.flag("computed")))
        .unwrap_or_default();
    if !["startsWith", "endsWith", "includes"].contains(&method.as_str()) {
        return;
    }
    let Some(subject) = callee.f("object").and_then(sender_subject) else { return };
    add_validation(
        ctx,
        node,
        subject,
        format!("call:{method}"),
        electron_static_value(argument(node, 0)),
    );
}

fn add_validation(
    ctx: &mut Ctx<'_>,
    node: N<'_>,
    subject: &str,
    mechanism: String,
    expected: ElectronStaticValue,
) {
    if expected.status == "dynamic" {
        ctx.acc.unknown_findings += 1;
    }
    let expected_key = if expected.status == "literal" {
        match &expected.value {
            Primitive::Str(text) => text.clone(),
            Primitive::Num(number) => js_number_to_string(number.0),
            Primitive::Bool(flag) => flag.to_string(),
            Primitive::Null => "null".into(),
        }
    } else {
        expected.expression.clone().unwrap_or_default()
    };
    let key = composite_key(&[
        Value::from("electron-validation"),
        Value::from(subject),
        Value::from(mechanism.as_str()),
        Value::from(expected_key),
    ]);
    let finding = ElectronSenderValidationFinding {
        subject: subject.into(),
        mechanism,
        expected,
        enforcement: "unknown".into(),
        module_key: None,
        module_runtime: None,
        location: range(node),
    };
    add_located(&mut ctx.acc.seen, &mut ctx.acc.sender_validations, &key, node, finding);
}

fn ipc_descriptor(name: &str) -> Option<IpcDescriptor> {
    let descriptor = |side, operation, mode| Some(IpcDescriptor { side, operation, mode });
    if let Some(renderer) = suffix_operation(name, "ipcRenderer") {
        match renderer {
            "send" => return descriptor("renderer", "send", "send"),
            "sendSync" => return descriptor("renderer", "send-sync", "send"),
            "invoke" => return descriptor("renderer", "invoke", "invoke"),
            "postMessage" => return descriptor("renderer", "post-message", "send"),
            "sendToHost" => return descriptor("renderer", "send-to-host", "send"),
            "on" => return descriptor("renderer", "on", "listen"),
            "once" => return descriptor("renderer", "once", "listen"),
            _ => {}
        }
    }
    match suffix_operation(name, "ipcMain") {
        Some("on") => descriptor("main", "on", "listen"),
        Some("once") => descriptor("main", "once", "listen"),
        Some("handle") => descriptor("main", "handle", "handle"),
        Some("handleOnce") => descriptor("main", "handle-once", "handle"),
        _ => None,
    }
}

fn suffix_operation<'a>(name: &'a str, object: &str) -> Option<&'a str> {
    let marker = format!("{object}.");
    let index = name.rfind(&marker)?;
    let prefix = &name[..index];
    if !prefix.is_empty() && !prefix.ends_with('.') {
        return None;
    }
    let operation = &name[index + marker.len()..];
    if operation.contains('.') {
        None
    } else {
        Some(operation)
    }
}

/// `name` equals `tail` or ends with `.tail`, i.e. `/(?:^|\.)tail$/u` for a literal tail.
fn is_dotted_suffix(name: &str, tail: &str) -> bool {
    name == tail || (name.ends_with(tail) && name[..name.len() - tail.len()].ends_with('.'))
}

fn sender_subject(node: N<'_>) -> Option<&'static str> {
    let name = if node.is(Kind::CallExpression) {
        callee_name(node.f("callee")?)
    } else {
        callee_name(node)
    };
    if is_dotted_suffix(&name, "sender.getURL") {
        return Some("sender-url");
    }
    if is_dotted_suffix(&name, "senderFrame.origin") {
        return Some("sender-origin");
    }
    if is_dotted_suffix(&name, "senderFrame.url") {
        return Some("sender-url");
    }
    if is_dotted_suffix(&name, "senderFrame") {
        return Some("sender-frame");
    }
    if is_dotted_suffix(&name, "sender.id") {
        return Some("sender-id");
    }
    if is_dotted_suffix(&name, "frameId") {
        return Some("frame-id");
    }
    if is_dotted_suffix(&name, "processId") {
        return Some("process-id");
    }
    None
}
