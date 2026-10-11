//! OpenAPI 3.1 document → a deterministic SDK model.
//!
//! Generated types follow schemas that are present in the document. Tracewise
//! evidence annotations are not client fields: they describe how the spec was
//! inferred, and the SDK must not round-trip them as payload.

use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::error::WebError;

const HTTP_METHODS: &[&str] = &[
    "delete", "get", "head", "options", "patch", "post", "put", "trace",
];

const VALUE_TOKEN: &str = "%%VALUE%%";

const HELPERS: &[&str] = &[
    "asArray", "asBool", "asInt", "asNum", "asObject", "asString", "firstParse",
];

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FieldModel {
    pub ident: String,
    pub json_name: String,
    pub json_literal: String,
    pub optional: bool,
    pub ts_type: String,
    pub py_type: String,
    pub ts_expr: String,
    pub py_expr: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InterfaceModel {
    pub name: String,
    pub parse_name: String,
    pub has_required: bool,
    pub fields: Vec<FieldModel>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ResponseModel {
    pub status: u16,
    pub ts_type: String,
    pub py_type: String,
    pub ts_body: String,
    pub py_body: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OperationModel {
    pub operation_id: String,
    pub operation_literal: String,
    pub py_name: String,
    pub method_literal: String,
    pub ts_params: String,
    pub ts_result: String,
    pub py_signature: String,
    pub py_return: String,
    pub path_code_ts: String,
    pub path_code_py: String,
    pub query_code_ts: String,
    pub query_code_py: String,
    pub body_code_ts: String,
    pub body_code_py: String,
    pub has_path: bool,
    pub has_query: bool,
    pub has_body: bool,
    pub path_type: String,
    pub query_type: String,
    pub body_class: Option<String>,
    pub body_cast: String,
    pub responses: Vec<ResponseModel>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RenderModel {
    pub package_name: String,
    pub package_literal: String,
    pub description_literal: String,
    pub base_url_literal: String,
    pub interfaces: Vec<InterfaceModel>,
    pub operations: Vec<OperationModel>,
    pub type_imports: Vec<String>,
    pub value_imports: Vec<String>,
    pub model_imports: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct OpMeta {
    pub method: String,
    pub path: String,
    pub operation_id: String,
    pub path_types: Vec<(String, String)>,
    pub query_types: Vec<(String, String, bool)>,
    pub has_json_body: bool,
    pub body_required: bool,
    pub statuses: Vec<u16>,
}

struct TyRef {
    ts: String,
    py: String,
    ts_parse: String,
    py_parse: String,
    class_name: Option<String>,
}

struct Builder {
    interfaces: Vec<InterfaceModel>,
    names: HashSet<String>,
}

pub(crate) struct SdkBuild {
    pub model: RenderModel,
    pub metas: Vec<OpMeta>,
}

pub(crate) fn build_sdk(spec: &Value, package_name: &str) -> Result<SdkBuild, WebError> {
    let paths = spec
        .get("paths")
        .and_then(|value| value.as_object())
        .ok_or_else(|| WebError::Format("OpenAPI document is missing paths.".to_string()))?;
    let mut builder = Builder {
        interfaces: Vec::new(),
        names: HashSet::new(),
    };
    let mut operations = Vec::new();
    let mut metas = Vec::new();
    let mut path_names: Vec<&String> = paths.keys().collect();
    path_names.sort();
    let mut used_ids = HashSet::new();
    let mut used_py = HashSet::new();
    for path_name in path_names {
        let item = &paths[path_name];
        let Some(item_obj) = item.as_object() else {
            continue;
        };
        let mut methods: Vec<&String> = item_obj
            .keys()
            .filter(|method| HTTP_METHODS.contains(&method.as_str()))
            .collect();
        methods.sort();
        for method in methods {
            let (rendered, meta) = builder.build_operation(
                spec,
                path_name,
                method,
                item,
                &item_obj[method],
                &mut NameSets {
                    ids: &mut used_ids,
                    py: &mut used_py,
                },
            )?;
            operations.push(rendered);
            metas.push(meta);
        }
    }

    let title = spec
        .get("info")
        .and_then(|info| info.get("title"))
        .and_then(|value| value.as_str())
        .unwrap_or(package_name);
    let base_url = spec
        .get("servers")
        .and_then(|servers| servers.as_array())
        .and_then(|servers| servers.first())
        .and_then(|server| server.get("url"))
        .and_then(|url| url.as_str())
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();

    let type_imports = collect_type_imports(&builder.interfaces, &operations);
    let value_imports = collect_value_imports(&builder.interfaces, &operations);
    let model_imports = collect_model_imports(&builder.interfaces, &operations);

    let model = RenderModel {
        package_literal: serde_json::to_string(package_name)?,
        description_literal: serde_json::to_string(&format!(
            "Typed client generated by tracewise for {title}."
        ))?,
        package_name: package_name.to_string(),
        base_url_literal: serde_json::to_string(&base_url)?,
        interfaces: builder.interfaces,
        operations,
        type_imports,
        value_imports,
        model_imports,
    };
    Ok(SdkBuild { model, metas })
}

struct NameSets<'a> {
    ids: &'a mut HashSet<String>,
    py: &'a mut HashSet<String>,
}

impl Builder {
    fn build_operation(
        &mut self,
        root: &Value,
        path: &str,
        method: &str,
        path_item: &Value,
        operation: &Value,
        names: &mut NameSets<'_>,
    ) -> Result<(OperationModel, OpMeta), WebError> {
        let fallback = fallback_operation_id(method, path);
        let raw_id = operation
            .get("operationId")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback.as_str());
        let operation_id = unique_name(&js_ident(raw_id), names.ids);
        let py_name = unique_name(&snake(&operation_id), names.py);
        let hint = type_name(&operation_id);

        let params = merged_parameters(path_item, operation);
        let mut path_params = Vec::new();
        let mut query_params = Vec::new();
        for parameter in params {
            let Some(name) = parameter.get("name").and_then(|value| value.as_str()) else {
                continue;
            };
            let location = parameter.get("in").and_then(|value| value.as_str()).unwrap_or("");
            let schema = parameter
                .get("schema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "string" }));
            let required = parameter
                .get("required")
                .and_then(|value| value.as_bool())
                .unwrap_or(location == "path");
            let entry = (name.to_string(), schema, required);
            if location == "path" {
                path_params.push(entry);
            } else if location == "query" {
                query_params.push(entry);
            }
        }

        let path_ty = if path_params.is_empty() {
            None
        } else {
            Some(self.object_from_params(&format!("{hint}Path"), &path_params)?)
        };
        let query_ty = if query_params.is_empty() {
            None
        } else {
            Some(self.object_from_params(&format!("{hint}Query"), &query_params)?)
        };
        let (body_ty, body_required) =
            self.request_body(root, operation, &format!("{hint}Request"))?;

        let mut responses = Vec::new();
        let mut statuses = Vec::new();
        if let Some(response_map) = operation.get("responses").and_then(|value| value.as_object()) {
            let mut codes: Vec<&String> = response_map.keys().collect();
            codes.sort();
            for code in codes {
                let Ok(status) = code.parse::<u16>() else {
                    continue;
                };
                let schema = response_map[code]
                    .get("content")
                    .and_then(json_schema_of_content);
                let ty = if let Some(schema) = schema {
                    self.walk(root, &schema, &format!("{hint}Response{status}"), 0)?
                } else {
                    unknown_ty()
                };
                responses.push(ResponseModel {
                    status,
                    ts_type: ty.ts.clone(),
                    py_type: ty.py.clone(),
                    ts_body: bind(&ty.ts_parse, "result.body"),
                    py_body: bind(&ty.py_parse, "parsed"),
                });
                statuses.push(status);
            }
        }

        let path_names = path_ty.as_ref().and_then(|ty| ty.class_name.as_deref()).map(|name| {
            self.interfaces
                .iter()
                .find(|iface| iface.name == name)
                .map(|iface| {
                    iface
                        .fields
                        .iter()
                        .map(|field| field.json_name.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        });
        let path_code_ts = path_expr_ts(path, path_names.as_deref().unwrap_or(&[]))?;
        let path_literal = serde_json::to_string(path)?;
        let path_code_py = if path_ty.is_some() {
            format!("_fill_path({path_literal}, path)")
        } else {
            path_literal
        };

        let mut ts_params = Vec::new();
        let mut py_params = Vec::new();
        if let Some(path_ty) = &path_ty {
            let name = class_or(&path_ty.class_name, &path_ty.ts);
            ts_params.push(format!("path: {name}"));
            py_params.push(format!("path: {name}"));
        }
        if let Some(query_ty) = &query_ty {
            let name = class_or(&query_ty.class_name, &query_ty.ts);
            let py_name = class_or(&query_ty.class_name, &query_ty.py);
            ts_params.push(format!("query: {name}"));
            py_params.push(format!("query: {py_name}"));
        }
        if let Some(body_ty) = &body_ty {
            ts_params.push(format!("body: {}", body_ty.ts));
            py_params.push(format!("body: {}", body_ty.py));
        }

        let ts_result = if responses.is_empty() {
            "{ status: number; body: unknown }".to_string()
        } else {
            responses
                .iter()
                .map(|response| {
                    format!(
                        "{{ status: {}; body: {} }}",
                        response.status,
                        paren_type(&response.ts_type)
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ")
        };
        let py_return = match responses.as_slice() {
            [] => "tuple[int, Any]".to_string(),
            [only] => format!("tuple[int, {}]", only.py_type),
            many => {
                let parts = many
                    .iter()
                    .map(|response| format!("tuple[int, {}]", response.py_type))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("Union[{parts}]")
            }
        };

        let meta = OpMeta {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            operation_id: operation_id.clone(),
            path_types: param_types(&path_params),
            query_types: query_param_meta(&query_params),
            has_json_body: body_ty.is_some(),
            body_required,
            statuses,
        };
        let model = OperationModel {
            operation_literal: serde_json::to_string(&operation_id)?,
            operation_id,
            py_name,
            method_literal: serde_json::to_string(&method.to_ascii_uppercase())?,
            ts_params: ts_params.join(", "),
            ts_result,
            py_signature: if py_params.is_empty() {
                String::new()
            } else {
                format!(", {}", py_params.join(", "))
            },
            py_return,
            path_code_ts,
            path_code_py,
            query_code_ts: if query_ty.is_some() { "query" } else { "undefined" }.to_string(),
            query_code_py: if query_ty.is_some() { "query" } else { "None" }.to_string(),
            body_code_ts: if body_ty.is_some() { "body" } else { "undefined" }.to_string(),
            body_code_py: if body_ty.is_some() { "body" } else { "None" }.to_string(),
            has_path: path_ty.is_some(),
            has_query: query_ty.is_some(),
            has_body: body_ty.is_some(),
            path_type: path_ty
                .as_ref()
                .and_then(|ty| ty.class_name.clone())
                .unwrap_or_default(),
            query_type: query_ty
                .as_ref()
                .and_then(|ty| ty.class_name.clone())
                .unwrap_or_default(),
            body_class: body_ty.as_ref().and_then(|ty| ty.class_name.clone()),
            body_cast: body_ty
                .as_ref()
                .map(|ty| ty.ts.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            responses,
        };
        Ok((model, meta))
    }

    fn request_body(
        &mut self,
        root: &Value,
        operation: &Value,
        hint: &str,
    ) -> Result<(Option<TyRef>, bool), WebError> {
        let Some(body) = operation.get("requestBody") else {
            return Ok((None, false));
        };
        let required = body
            .get("required")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let Some(schema) = body.get("content").and_then(json_schema_of_content) else {
            return Ok((None, required));
        };
        Ok((Some(self.walk(root, &schema, hint, 0)?), required))
    }

    fn object_from_params(
        &mut self,
        hint: &str,
        params: &[(String, Value, bool)],
    ) -> Result<TyRef, WebError> {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for (name, schema, is_required) in params {
            properties.insert(name.clone(), schema.clone());
            if *is_required {
                required.push(Value::String(name.clone()));
            }
        }
        let mut schema = Map::new();
        schema.insert("type".to_string(), json!("object"));
        schema.insert("properties".to_string(), Value::Object(properties));
        if !required.is_empty() {
            schema.insert("required".to_string(), Value::Array(required));
        }
        self.walk_object(&Value::Null, &Value::Object(schema), hint, 0)
    }

    fn walk(&mut self, root: &Value, schema: &Value, hint: &str, depth: u32) -> Result<TyRef, WebError> {
        if depth > 32 {
            return Err(WebError::Format(
                "Schema nesting is too deep to generate a client.".to_string(),
            ));
        }
        let schema = resolve(root, schema);
        if let Some(variants) = schema.get("anyOf").and_then(|value| value.as_array()) {
            return self.walk_union(root, variants, hint, depth);
        }
        if let Some(variants) = schema.get("oneOf").and_then(|value| value.as_array()) {
            return self.walk_union(root, variants, hint, depth);
        }
        if let Some(kinds) = schema.get("type").and_then(|value| value.as_array()) {
            let variants: Vec<Value> = kinds
                .iter()
                .filter_map(|kind| kind.as_str())
                .map(|kind| json!({ "type": kind }))
                .collect();
            if variants.len() == 1 {
                return self.walk(root, &variants[0], hint, depth);
            }
            if !variants.is_empty() {
                return self.walk_union(root, &variants, hint, depth);
            }
        }
        let kind = schema.get("type").and_then(|value| value.as_str()).unwrap_or("");
        if kind == "array" || (schema.get("items").is_some() && kind != "object") {
            return self.walk_array(root, &schema, hint, depth);
        }
        if kind == "object" || schema.get("properties").is_some() {
            return self.walk_object(root, &schema, hint, depth);
        }
        if kind.is_empty() {
            return Ok(unknown_ty());
        }
        Ok(primitive(kind))
    }

    fn walk_object(
        &mut self,
        root: &Value,
        schema: &Value,
        hint: &str,
        depth: u32,
    ) -> Result<TyRef, WebError> {
        let name = self.alloc_name(hint);
        let required = required_set(schema);
        let mut fields = Vec::new();
        let mut used_fields = HashSet::new();
        if let Some(properties) = schema.get("properties").and_then(|value| value.as_object()) {
            for (key, property) in properties {
                let child = self.walk(root, property, &format!("{name}{}", type_name(key)), depth + 1)?;
                let json_literal = serde_json::to_string(key)?;
                let access = format!("data[{json_literal}]");
                let optional = !required.contains(key);
                let ident = unique_name(&field_ident(key), &mut used_fields);
                let py_expr = if optional {
                    format!(
                        "_optional_key(data, {json_literal}, lambda __value__: {})",
                        bind(&child.py_parse, "__value__")
                    )
                } else {
                    bind(&child.py_parse, &access)
                };
                let py_type = if optional {
                    format!("Optional[{}]", child.py)
                } else {
                    child.py
                };
                fields.push(FieldModel {
                    ident,
                    json_name: key.clone(),
                    json_literal,
                    optional,
                    ts_type: child.ts,
                    py_type,
                    ts_expr: bind(&child.ts_parse, &access),
                    py_expr,
                });
            }
        }
        let (required_fields, optional_fields): (Vec<_>, Vec<_>) =
            fields.into_iter().partition(|field| !field.optional);
        let mut fields = required_fields;
        fields.extend(optional_fields);
        let has_required = fields.iter().any(|field| !field.optional);
        let parse_name = format!("parse{name}");
        self.interfaces.push(InterfaceModel {
            name: name.clone(),
            parse_name: parse_name.clone(),
            has_required,
            fields,
        });
        Ok(TyRef {
            ts: name.clone(),
            py: name.clone(),
            ts_parse: format!("{parse_name}({VALUE_TOKEN})"),
            py_parse: format!("{name}.parse({VALUE_TOKEN})"),
            class_name: Some(name),
        })
    }

    fn walk_array(
        &mut self,
        root: &Value,
        schema: &Value,
        hint: &str,
        depth: u32,
    ) -> Result<TyRef, WebError> {
        let items = schema.get("items").cloned().unwrap_or_else(|| json!({}));
        let item = self.walk(root, &items, &format!("{hint}Item"), depth + 1)?;
        let var = format!("item{depth}");
        let inner_ts = bind(&item.ts_parse, &var);
        let inner_py = bind(&item.py_parse, &var);
        let ts = if item.ts.contains('|') || item.ts.contains('&') {
            format!("({})[]", item.ts)
        } else {
            format!("{}[]", item.ts)
        };
        Ok(TyRef {
            ts,
            py: format!("list[{}]", item.py),
            ts_parse: format!("asArray({VALUE_TOKEN}).map(({var}) => {inner_ts})"),
            py_parse: format!("[{inner_py} for {var} in _as_list({VALUE_TOKEN})]"),
            class_name: None,
        })
    }

    fn walk_union(
        &mut self,
        root: &Value,
        variants: &[Value],
        hint: &str,
        depth: u32,
    ) -> Result<TyRef, WebError> {
        let mut parts = Vec::new();
        for (index, variant) in variants.iter().enumerate() {
            parts.push(self.walk(root, variant, &format!("{hint}Variant{index}"), depth + 1)?);
        }
        if parts.is_empty() {
            return Ok(unknown_ty());
        }
        let ts = parts
            .iter()
            .map(|part| part.ts.clone())
            .collect::<Vec<_>>()
            .join(" | ");
        let py = format!(
            "Union[{}]",
            parts
                .iter()
                .map(|part| part.py.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let ts_parsers = parts
            .iter()
            .map(|part| format!("(value) => {}", bind(&part.ts_parse, "value")))
            .collect::<Vec<_>>()
            .join(", ");
        let py_parsers = parts
            .iter()
            .map(|part| format!("lambda __value__: {}", bind(&part.py_parse, "__value__")))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(TyRef {
            ts,
            py,
            ts_parse: format!("firstParse({VALUE_TOKEN}, [{ts_parsers}])"),
            py_parse: format!("_first_parse({VALUE_TOKEN}, [{py_parsers}])"),
            class_name: None,
        })
    }

    fn alloc_name(&mut self, hint: &str) -> String {
        let base = type_name(hint);
        let mut name = base.clone();
        let mut suffix = 2u32;
        while !self.names.insert(name.clone()) {
            name = format!("{base}{suffix}");
            suffix += 1;
        }
        name
    }
}

fn collect_type_imports(interfaces: &[InterfaceModel], operations: &[OperationModel]) -> Vec<String> {
    let mut names = BTreeSet::new();
    for operation in operations {
        harvest_tokens(&operation.ts_params, interfaces, &mut names, false);
        harvest_tokens(&operation.ts_result, interfaces, &mut names, false);
        if !operation.path_type.is_empty() {
            names.insert(operation.path_type.clone());
        }
        if !operation.query_type.is_empty() {
            names.insert(operation.query_type.clone());
        }
    }
    names.into_iter().collect()
}

fn collect_value_imports(interfaces: &[InterfaceModel], operations: &[OperationModel]) -> Vec<String> {
    let mut names = BTreeSet::new();
    for operation in operations {
        for response in &operation.responses {
            for iface in interfaces {
                if response.ts_body.contains(&iface.parse_name) {
                    names.insert(iface.parse_name.clone());
                }
            }
            for helper in HELPERS {
                if response.ts_body.contains(&format!("{helper}(")) {
                    names.insert((*helper).to_string());
                }
            }
        }
    }
    names.into_iter().collect()
}

fn collect_model_imports(interfaces: &[InterfaceModel], operations: &[OperationModel]) -> Vec<String> {
    let mut names = BTreeSet::new();
    for operation in operations {
        if !operation.path_type.is_empty() {
            names.insert(operation.path_type.clone());
        }
        if !operation.query_type.is_empty() {
            names.insert(operation.query_type.clone());
        }
        if let Some(body) = &operation.body_class {
            names.insert(body.clone());
        }
        harvest_tokens(&operation.py_return, interfaces, &mut names, false);
        for response in &operation.responses {
            harvest_tokens(&response.py_body, interfaces, &mut names, false);
        }
    }
    names.into_iter().collect()
}

fn harvest_tokens(
    expr: &str,
    interfaces: &[InterfaceModel],
    out: &mut BTreeSet<String>,
    _parse: bool,
) {
    for token in expr.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
        if interfaces.iter().any(|iface| iface.name == token) {
            out.insert(token.to_string());
        }
    }
}

fn param_types(params: &[(String, Value, bool)]) -> Vec<(String, String)> {
    params
        .iter()
        .map(|(name, schema, _)| (name.clone(), schema_type_name(schema)))
        .collect()
}

fn query_param_meta(params: &[(String, Value, bool)]) -> Vec<(String, String, bool)> {
    params
        .iter()
        .map(|(name, schema, required)| (name.clone(), schema_type_name(schema), *required))
        .collect()
}

fn schema_type_name(schema: &Value) -> String {
    if let Some(kind) = schema.get("type").and_then(|value| value.as_str()) {
        return kind.to_string();
    }
    if schema.get("properties").is_some() {
        return "object".to_string();
    }
    "string".to_string()
}

fn path_expr_ts(path: &str, names: &[String]) -> Result<String, WebError> {
    let mut expr = serde_json::to_string(path)?;
    for name in names {
        let needle = serde_json::to_string(&format!("{{{name}}}"))?;
        let literal = serde_json::to_string(name)?;
        expr.push_str(&format!(
            ".replace({needle}, encodeURIComponent(String((path as unknown as Record<string, unknown>)[{literal}])))"
        ));
    }
    Ok(expr)
}

fn class_or(class_name: &Option<String>, fallback: &str) -> String {
    class_name.clone().unwrap_or_else(|| fallback.to_string())
}

fn paren_type(ts: &str) -> String {
    if ts.contains('|') || ts.contains('&') {
        format!("({ts})")
    } else {
        ts.to_string()
    }
}

fn json_schema_of_content(content: &Value) -> Option<Value> {
    let obj = content.as_object()?;
    if let Some(media) = obj.get("application/json") {
        return Some(media.get("schema").cloned().unwrap_or_else(|| json!({})));
    }
    for (mime, media) in obj {
        if mime.to_ascii_lowercase().contains("json") {
            return Some(media.get("schema").cloned().unwrap_or_else(|| json!({})));
        }
    }
    None
}

fn merged_parameters(path_item: &Value, operation: &Value) -> Vec<Value> {
    let mut all = Vec::new();
    if let Some(params) = path_item.get("parameters").and_then(|value| value.as_array()) {
        all.extend(params.iter().cloned());
    }
    if let Some(params) = operation.get("parameters").and_then(|value| value.as_array()) {
        all.extend(params.iter().cloned());
    }
    all
}

fn required_set(schema: &Value) -> HashSet<String> {
    schema
        .get("required")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn resolve(root: &Value, schema: &Value) -> Value {
    let Some(reference) = schema.get("$ref").and_then(|value| value.as_str()) else {
        return schema.clone();
    };
    let Some(name) = reference.strip_prefix("#/components/schemas/") else {
        return schema.clone();
    };
    if name.contains('~') || name.contains('/') {
        return schema.clone();
    }
    root.pointer(&format!("/components/schemas/{name}"))
        .cloned()
        .unwrap_or_else(|| schema.clone())
}

fn bind(template: &str, expr: &str) -> String {
    template.replace(VALUE_TOKEN, expr)
}

fn unknown_ty() -> TyRef {
    TyRef {
        ts: "unknown".to_string(),
        py: "Any".to_string(),
        ts_parse: VALUE_TOKEN.to_string(),
        py_parse: VALUE_TOKEN.to_string(),
        class_name: None,
    }
}

fn primitive(kind: &str) -> TyRef {
    match kind {
        "string" => TyRef {
            ts: "string".to_string(),
            py: "str".to_string(),
            ts_parse: format!("asString({VALUE_TOKEN})"),
            py_parse: format!("_as_str({VALUE_TOKEN})"),
            class_name: None,
        },
        "integer" => TyRef {
            ts: "number".to_string(),
            py: "int".to_string(),
            ts_parse: format!("asInt({VALUE_TOKEN})"),
            py_parse: format!("_as_int({VALUE_TOKEN})"),
            class_name: None,
        },
        "number" => TyRef {
            ts: "number".to_string(),
            py: "float".to_string(),
            ts_parse: format!("asNum({VALUE_TOKEN})"),
            py_parse: format!("_as_float({VALUE_TOKEN})"),
            class_name: None,
        },
        "boolean" => TyRef {
            ts: "boolean".to_string(),
            py: "bool".to_string(),
            ts_parse: format!("asBool({VALUE_TOKEN})"),
            py_parse: format!("_as_bool({VALUE_TOKEN})"),
            class_name: None,
        },
        "null" => TyRef {
            ts: "null".to_string(),
            py: "Any".to_string(),
            ts_parse: VALUE_TOKEN.to_string(),
            py_parse: VALUE_TOKEN.to_string(),
            class_name: None,
        },
        _ => unknown_ty(),
    }
}

fn fallback_operation_id(method: &str, template: &str) -> String {
    let mut id = method.to_ascii_lowercase();
    for segment in template.split('/').filter(|segment| !segment.is_empty()) {
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            id.push_str("By");
            id.push_str(&type_name(name));
        } else {
            id.push_str(&type_name(segment));
        }
    }
    if id.is_empty() {
        method.to_ascii_lowercase()
    } else {
        id
    }
}

fn unique_name(base: &str, used: &mut HashSet<String>) -> String {
    let mut name = if base.is_empty() {
        "operation".to_string()
    } else {
        base.to_string()
    };
    let stem = name.clone();
    let mut suffix = 2u32;
    while !used.insert(name.clone()) {
        name = format!("{stem}_{suffix}");
        suffix += 1;
    }
    name
}

fn type_name(raw: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if capitalize {
                out.extend(ch.to_uppercase());
                capitalize = false;
            } else {
                out.push(ch);
            }
        } else {
            capitalize = true;
        }
    }
    if out.is_empty() || out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        format!("T{out}")
    } else {
        out
    }
}

fn field_ident(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let mut name = out.trim_matches('_').to_string();
    if name.is_empty() || name.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        name = format!("field_{name}");
    }
    if is_reserved(&name) {
        name.push('_');
    }
    name
}

fn is_reserved(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "case",
        "catch", "class", "const", "continue", "def", "del", "elif", "else", "enum", "except",
        "false", "finally", "for", "from", "function", "global", "if", "import", "in",
        "instanceof", "interface", "is", "lambda", "let", "match", "new", "not", "null", "or",
        "pass", "raise", "return", "switch", "this", "throw", "true", "try", "type", "typeof",
        "var", "void", "while", "with", "yield", "any", "boolean", "number", "string", "object",
        "unknown", "never", "undefined", "symbol", "bigint",
    ];
    RESERVED.contains(&name)
}

fn js_ident(raw: &str) -> String {
    if is_js_ident(raw) && !matches!(raw, "call" | "constructor" | "prototype") {
        return raw.to_string();
    }
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    if out.is_empty() || out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out = format!("op_{out}");
    }
    if matches!(out.as_str(), "call" | "constructor" | "prototype") {
        out.push_str("_op");
    }
    out
}

fn is_js_ident(raw: &str) -> bool {
    let mut chars = raw.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' || first == '$' => {
            chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
        }
        _ => false,
    }
}

fn snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (index, ch) in chars.iter().enumerate() {
        if ch.is_ascii_uppercase() {
            let boundary = index > 0
                && (chars[index - 1].is_ascii_lowercase()
                    || chars
                        .get(index + 1)
                        .is_some_and(|next| next.is_ascii_lowercase()));
            if boundary && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(*ch);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let mut name = out.trim_matches('_').to_string();
    if name.is_empty() {
        name = "operation".to_string();
    }
    if is_reserved(&name) || matches!(name.as_str(), "client" | "request") {
        name.push('_');
    }
    name
}
