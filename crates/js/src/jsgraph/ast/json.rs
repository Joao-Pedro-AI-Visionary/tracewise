//! JSON view of the tree, shaped like `@babel/parser` output (used by the AST parity test).

use serde_json::{json, Map, Value};

use super::{Ast, NodeId, Val};

pub fn ast_to_json(ast: &Ast) -> Value {
    node_json(ast, ast.root)
}

fn node_json(ast: &Ast, id: NodeId) -> Value {
    let data = ast.data(id);
    let mut map = Map::new();
    map.insert("type".into(), json!(data.kind.as_str()));
    map.insert("start".into(), json!(data.start));
    map.insert("end".into(), json!(data.end));
    if data.kind == super::Kind::TemplateElement {
        let mut value = Map::new();
        for (key, field) in &data.fields {
            match *key {
                "raw" | "cooked" => {
                    value.insert((*key).to_string(), val_json(ast, field));
                }
                _ => {
                    map.insert((*key).to_string(), val_json(ast, field));
                }
            }
        }
        map.insert("value".into(), Value::Object(value));
        return Value::Object(map);
    }
    for (key, value) in &data.fields {
        map.insert((*key).to_string(), val_json(ast, value));
    }
    Value::Object(map)
}

fn val_json(ast: &Ast, value: &Val) -> Value {
    match value {
        Val::Node(id) => node_json(ast, *id),
        Val::List(items) => Value::Array(
            items
                .iter()
                .map(|item| item.map_or(Value::Null, |id| node_json(ast, id)))
                .collect(),
        ),
        Val::Str(text) => json!(text),
        Val::Num(number) => {
            if number.is_finite() && number.fract() == 0.0 && number.abs() < 9.0e18 {
                json!(*number as i64)
            } else {
                json!(number)
            }
        }
        Val::Bool(flag) => json!(flag),
        Val::Null => Value::Null,
    }
}
