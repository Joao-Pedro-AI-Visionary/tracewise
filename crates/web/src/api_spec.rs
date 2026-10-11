//! Infer an OpenAPI 3.1 document from redacted network-capture evidence.
//!
//! Credential values never enter the document. `inspect_web_network_capture`
//! strips them first; this module only reads that redacted evidence and records
//! the missing authentication scheme as a residual unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceLocation,
    EvidenceObservation, EvidenceProvider, EvidenceSubject,
};
use tracewise_domain::unknown::{Probe, RecordUnknownInput, Relationship, UnknownSeverity};

use crate::api_spec_schema::{
    annotate, evidence_array, is_param_segment, is_uuid, schema_from_samples, stringly_schema,
    EvidenceRef,
};
use crate::error::WebError;
use crate::har::InspectWebNetworkCaptureInput;

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferApiSpecInput {
    pub evidence_ids: Option<Vec<String>>,
    pub capture_path: Option<String>,
    pub base_url: Option<String>,
    pub title: Option<String>,
    pub output_path: Option<String>,
}

pub struct InferredApiSpec {
    pub evidence: Evidence,
    pub unknowns: Vec<RecordUnknownInput>,
}

#[derive(Clone)]
struct Exchange {
    evidence: EvidenceRef,
    method: String,
    url: String,
    path: String,
    query: Vec<(String, String)>,
    request_mime: Option<String>,
    request_json: Option<Value>,
    request_unparsed: bool,
    status: u16,
    response_mime: Option<String>,
    response_json: Option<Value>,
    response_unparsed: bool,
    redacted_request: BTreeSet<String>,
    redacted_response: BTreeSet<String>,
    param_values: Vec<String>,
}

pub fn inspect_capture_for_spec(capture_path: &str) -> Result<Evidence, WebError> {
    let path = Path::new(capture_path);
    if !path.is_absolute() {
        return Err(input_error(
            "capture_path",
            "Expected an absolute filesystem path on this host.",
        ));
    }
    let format = detect_format(path)?;
    let input = InspectWebNetworkCaptureInput {
        capture_path: capture_path.to_string(),
        format: format.to_string(),
        record_ordinals: None,
        sensitive_values: Vec::new(),
    };
    match format {
        "har" => crate::har::inspect_har_capture(input),
        "mitmproxy" => crate::mitmproxy::inspect_mitmproxy_capture(input),
        other => Err(input_error(
            "capture_path",
            &format!("Unsupported capture format '{other}'."),
        )),
    }
}

pub fn infer_from_captures(
    input: &InferApiSpecInput,
    sources: &[Evidence],
) -> Result<InferredApiSpec, WebError> {
    if sources.is_empty() {
        return Err(input_error(
            "evidence_ids",
            "At least one inspect_web_network_capture evidence record is required.",
        ));
    }
    for source in sources {
        if source.operation != "inspect_web_network_capture" {
            return Err(input_error(
                "evidence_ids",
                &format!(
                    "Evidence {} is operation '{}', not inspect_web_network_capture.",
                    source.evidence_id, source.operation
                ),
            ));
        }
    }

    let mut exchanges = Vec::new();
    for source in sources {
        exchanges.extend(exchanges_from_evidence(source)?);
    }
    if let Some(base) = input.base_url.as_deref() {
        let prefix = base.trim_end_matches('/');
        exchanges.retain(|exchange| exchange.url == prefix || exchange.url.starts_with(&format!("{prefix}/")));
        for exchange in &mut exchanges {
            exchange.path = relativize_path(&exchange.path, base);
        }
    }
    if exchanges.is_empty() {
        return Err(input_error(
            "capture_path",
            "The capture has no HTTP records to infer an API spec from.",
        ));
    }

    let endpoints = group_endpoints(&exchanges);
    let unknowns_questions = unknown_questions(&exchanges);
    let openapi = build_openapi(input, &endpoints, &unknowns_questions)?;
    let openapi = sort_value(openapi);
    audit_openapi(&openapi)?;
    reject_secrets(&openapi)?;

    if let Some(output_path) = input.output_path.as_deref() {
        write_spec(Path::new(output_path), &openapi)?;
    }

    let source_ids: Vec<String> = sources.iter().map(|s| s.evidence_id.clone()).collect();
    let mut source_ids_sorted = source_ids.clone();
    source_ids_sorted.sort();
    source_ids_sorted.dedup();

    let evidence = build_evidence(input, sources, &openapi, &source_ids_sorted)?;
    let unknowns = unknowns_questions
        .into_iter()
        .map(|(question, severity)| residual_input(question, severity, &source_ids_sorted))
        .collect();
    Ok(InferredApiSpec { evidence, unknowns })
}

fn detect_format(path: &Path) -> Result<&'static str, WebError> {
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "har" {
        return Ok("har");
    }
    if ext == "mitm" || ext == "mitmproxy" {
        return Ok("mitmproxy");
    }
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') && trimmed.contains("\"log\"") && trimmed.contains("\"entries\"") {
        Ok("har")
    } else {
        Ok("mitmproxy")
    }
}

fn exchanges_from_evidence(source: &Evidence) -> Result<Vec<Exchange>, WebError> {
    let records = source
        .normalized_result
        .get("records")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            WebError::Format(format!(
                "Evidence {} has no capture records.",
                source.evidence_id
            ))
        })?;
    let mut exchanges = Vec::new();
    for record in records {
        let ordinal = record.get("ordinal").and_then(|v| v.as_u64()).ok_or_else(|| {
            WebError::Format(format!(
                "Evidence {} has a record without an ordinal.",
                source.evidence_id
            ))
        })?;
        let Some(reported) = record.get("reported") else {
            continue;
        };
        if reported.is_null() {
            continue;
        }
        if let Some(exchange) = exchange_from_reported(&source.evidence_id, ordinal, reported)? {
            exchanges.push(exchange);
        }
    }
    Ok(exchanges)
}

fn exchange_from_reported(
    evidence_id: &str,
    ordinal: u64,
    reported: &Value,
) -> Result<Option<Exchange>, WebError> {
    let request = reported.get("request").ok_or_else(|| {
        WebError::Format(format!(
            "Record {ordinal} in {evidence_id} has no request."
        ))
    })?;
    let response = reported.get("response").ok_or_else(|| {
        WebError::Format(format!(
            "Record {ordinal} in {evidence_id} has no response."
        ))
    })?;
    let method = request
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let Some(url) = request_url(request)? else {
        return Ok(None);
    };
    let parsed = url::Url::parse(&url).map_err(|_| {
        WebError::Format(format!("Record {ordinal} in {evidence_id} has an invalid URL."))
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Ok(None);
    }
    let path = parsed.path().to_string();
    let query = if let Some(pairs) = request.get("queryString").and_then(|v| v.as_array()) {
        if pairs.is_empty() {
            parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        } else {
            pairs
                .iter()
                .filter_map(|pair| {
                    let name = pair.get("name").and_then(|v| v.as_str())?;
                    let value = scalar_string(pair.get("value")?)?;
                    Some((name.to_string(), value))
                })
                .collect()
        }
    } else {
        parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    };

    let request_headers = header_pairs(request.get("headers"));
    let response_headers = header_pairs(response.get("headers"));
    let request_mime = mime_of(
        request.get("postData").and_then(|v| v.get("mimeType")),
        &request_headers,
    );
    let response_mime = mime_of(
        response.get("content").and_then(|v| v.get("mimeType")),
        &response_headers,
    );
    let request_text = body_text(request.get("postData").and_then(|v| v.get("text")))
        .or_else(|| body_text(request.get("content")));
    let response_text = body_text(response.get("content").and_then(|v| v.get("text")))
        .or_else(|| body_text(response.get("content")));
    let (request_json, request_unparsed) = parse_body(request_mime.as_deref(), request_text.as_deref());
    let (response_json, response_unparsed) =
        parse_body(response_mime.as_deref(), response_text.as_deref());
    let status = response
        .get("status")
        .and_then(|v| v.as_u64())
        .or_else(|| response.get("status_code").and_then(|v| v.as_u64()))
        .ok_or_else(|| {
            WebError::Format(format!(
                "Record {ordinal} in {evidence_id} has no HTTP status."
            ))
        })?;
    if status > u64::from(u16::MAX) {
        return Err(WebError::Format(format!(
            "Record {ordinal} in {evidence_id} has an invalid HTTP status."
        )));
    }

    let mut redacted_request = redacted_header_names(&request_headers);
    if cookies_redacted(request.get("cookies")) {
        redacted_request.insert("cookie".to_string());
    }
    let mut redacted_response = redacted_header_names(&response_headers);
    if cookies_redacted(response.get("cookies")) {
        redacted_response.insert("set-cookie".to_string());
    }

    Ok(Some(Exchange {
        evidence: EvidenceRef {
            evidence_id: evidence_id.to_string(),
            ordinal,
        },
        method,
        url,
        path,
        query,
        request_mime,
        request_json,
        request_unparsed,
        status: status as u16,
        response_mime,
        response_json,
        response_unparsed,
        redacted_request,
        redacted_response,
        param_values: Vec::new(),
    }))
}

fn request_url(request: &Value) -> Result<Option<String>, WebError> {
    if let Some(url) = request.get("url").and_then(|v| v.as_str()) {
        if url.is_empty() {
            return Ok(None);
        }
        return Ok(Some(url.to_string()));
    }
    let Some(path) = request.get("path").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let scheme = request.get("scheme").and_then(|v| v.as_str()).unwrap_or("http");
    let host = request.get("host").and_then(|v| v.as_str()).unwrap_or("");
    if host.is_empty() {
        return Ok(None);
    }
    let port = request.get("port").and_then(|v| v.as_u64());
    let default_port = (scheme == "http" && port == Some(80)) || (scheme == "https" && port == Some(443));
    let port_text = match port {
        Some(port) if !default_port => format!(":{port}"),
        _ => String::new(),
    };
    let path = if path.starts_with('/') || path.starts_with('?') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Some(format!("{scheme}://{host}{port_text}{path}")))
}

fn relativize_path(path: &str, base_url: &str) -> String {
    let Ok(base) = url::Url::parse(base_url) else {
        return path.to_string();
    };
    let prefix = base.path().trim_end_matches('/');
    if prefix.is_empty() || prefix == "/" {
        return path.to_string();
    }
    if path == prefix {
        return "/".to_string();
    }
    path.strip_prefix(prefix)
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(path)
        .to_string()
}

fn group_endpoints(exchanges: &[Exchange]) -> BTreeMap<(String, String), Vec<Exchange>> {
    let mut groups: BTreeMap<(String, String), Vec<Exchange>> = BTreeMap::new();
    for exchange in exchanges {
        let (template, values) = template_path(&exchange.path);
        let mut tagged = exchange.clone();
        tagged.param_values = values;
        groups
            .entry((exchange.method.clone(), template))
            .or_default()
            .push(tagged);
    }
    groups
}

fn template_path(path: &str) -> (String, Vec<String>) {
    let mut names_used = 0u32;
    let mut values = Vec::new();
    let mut parts = Vec::new();
    for segment in path.split('/') {
        if is_param_segment(segment) {
            names_used += 1;
            let name = if names_used == 1 {
                "id".to_string()
            } else {
                format!("id{names_used}")
            };
            values.push(segment.to_string());
            parts.push(format!("{{{name}}}"));
        } else {
            parts.push(segment.to_string());
        }
    }
    (parts.join("/"), values)
}

fn param_names(template: &str) -> Vec<String> {
    template
        .split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
                .map(|name| name.to_string())
        })
        .collect()
}

fn build_openapi(
    input: &InferApiSpecInput,
    endpoints: &BTreeMap<(String, String), Vec<Exchange>>,
    questions: &[(String, UnknownSeverity)],
) -> Result<Value, WebError> {
    let mut paths = Map::new();
    let mut operation_ids = BTreeSet::new();
    let mut all_refs = Vec::new();
    for ((method, template), samples) in endpoints {
        all_refs.extend(samples.iter().map(|s| s.evidence.clone()));
        let operation = build_operation(method, template, samples, &mut operation_ids)?;
        let path_item = paths
            .entry(template.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(item) = path_item.as_object_mut() {
            item.insert(method.to_ascii_lowercase(), operation);
        }
    }

    let mut servers = BTreeSet::new();
    if let Some(base) = input.base_url.as_deref() {
        servers.insert(base.trim_end_matches('/').to_string());
    } else {
        for samples in endpoints.values() {
            for sample in samples {
                if let Ok(url) = url::Url::parse(&sample.url) {
                    servers.insert(url.origin().ascii_serialization());
                }
            }
        }
    }
    let server_list: Vec<Value> = servers
        .into_iter()
        .map(|url| json!({ "url": url }))
        .collect();

    let schemes = security_schemes(endpoints);
    let mut doc = Map::new();
    doc.insert("openapi".to_string(), Value::String("3.1.0".to_string()));
    doc.insert(
        "info".to_string(),
        json!({
            "title": input.title.clone().unwrap_or_else(|| "Inferred API".to_string()),
            "version": "0.0.0",
            "description": "OpenAPI 3.1 document inferred from redacted network captures. Credential values are omitted. Unobserved aspects are residual unknowns."
        }),
    );
    doc.insert("servers".to_string(), Value::Array(server_list));
    doc.insert("paths".to_string(), Value::Object(paths));
    if !schemes.is_empty() {
        doc.insert(
            "components".to_string(),
            json!({ "securitySchemes": schemes }),
        );
    }
    doc.insert(
        "x-tracewise-unknowns".to_string(),
        Value::Array(
            questions
                .iter()
                .map(|(question, _)| Value::String(question.clone()))
                .collect(),
        ),
    );
    doc.insert(
        "x-tracewise-evidence".to_string(),
        evidence_array(&all_refs),
    );
    doc.insert(
        "x-tracewise-confidence".to_string(),
        Value::String("inferred".to_string()),
    );
    Ok(Value::Object(doc))
}

fn build_operation(
    method: &str,
    template: &str,
    samples: &[Exchange],
    operation_ids: &mut BTreeSet<String>,
) -> Result<Value, WebError> {
    let names = param_names(template);
    let refs: Vec<_> = samples.iter().map(|s| s.evidence.clone()).collect();
    let templated = !names.is_empty();
    let mut parameters = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let values: Vec<String> = samples
            .iter()
            .filter_map(|sample| sample.param_values.get(index).cloned())
            .collect();
        let format = if values.iter().all(|v| is_uuid(v)) {
            Some("uuid")
        } else {
            None
        };
        parameters.push(json!({
            "name": name,
            "in": "path",
            "required": true,
            "schema": stringly_schema(&values, &refs, format),
            "x-tracewise-evidence": evidence_array(&refs),
            "x-tracewise-confidence": "inferred",
        }));
    }
    parameters.extend(query_parameters(samples)?);

    let mut operation = Map::new();
    operation.insert(
        "operationId".to_string(),
        Value::String(unique_operation_id(method, template, operation_ids)),
    );
    operation.insert(
        "description".to_string(),
        Value::String("Inferred from captured network records.".to_string()),
    );
    if !parameters.is_empty() {
        operation.insert("parameters".to_string(), Value::Array(parameters));
    }
    if let Some(body) = request_body(samples)? {
        operation.insert("requestBody".to_string(), body);
    }
    operation.insert("responses".to_string(), responses(samples)?);
    if let Some(security) = operation_security(samples) {
        operation.insert("security".to_string(), security);
    }
    let confidence = if templated { "inferred" } else { "observed" };
    Ok(annotate(operation, &refs, confidence))
}

fn query_parameters(samples: &[Exchange]) -> Result<Vec<Value>, WebError> {
    let mut names = BTreeSet::new();
    for sample in samples {
        for (name, _) in &sample.query {
            names.insert(name.clone());
        }
    }
    let mut parameters = Vec::new();
    for name in names {
        let mut values = Vec::new();
        let mut refs = Vec::new();
        let mut present = 0usize;
        for sample in samples {
            let matched: Vec<_> = sample
                .query
                .iter()
                .filter(|(query_name, _)| query_name == &name)
                .map(|(_, value)| value.clone())
                .collect();
            if !matched.is_empty() {
                present += 1;
                refs.push(sample.evidence.clone());
                values.extend(matched);
            }
        }
        parameters.push(json!({
            "name": name,
            "in": "query",
            "required": present == samples.len(),
            "schema": stringly_schema(&values, &refs, None),
            "x-tracewise-evidence": evidence_array(&refs),
            "x-tracewise-confidence": "inferred",
        }));
    }
    Ok(parameters)
}

fn request_body(samples: &[Exchange]) -> Result<Option<Value>, WebError> {
    let mut by_mime: BTreeMap<String, Vec<(Value, EvidenceRef)>> = BTreeMap::new();
    let mut refs = Vec::new();
    let mut with_body = 0usize;
    for sample in samples {
        if sample.request_json.is_some() || sample.request_unparsed {
            with_body += 1;
        }
        if let Some(body) = &sample.request_json {
            let mime = sample
                .request_mime
                .clone()
                .unwrap_or_else(|| "application/json".to_string());
            refs.push(sample.evidence.clone());
            by_mime
                .entry(mime)
                .or_default()
                .push((body.clone(), sample.evidence.clone()));
        }
    }
    if by_mime.is_empty() {
        return Ok(None);
    }
    let mut content = Map::new();
    for (mime, bodies) in by_mime {
        content.insert(
            mime,
            json!({ "schema": schema_from_samples(&bodies)? }),
        );
    }
    let mut body = Map::new();
    body.insert(
        "required".to_string(),
        Value::Bool(with_body == samples.len()),
    );
    body.insert("content".to_string(), Value::Object(content));
    Ok(Some(annotate(body, &refs, "inferred")))
}

fn responses(samples: &[Exchange]) -> Result<Value, WebError> {
    let mut by_status: BTreeMap<u16, Vec<&Exchange>> = BTreeMap::new();
    for sample in samples {
        by_status.entry(sample.status).or_default().push(sample);
    }
    let mut responses = Map::new();
    for (status, group) in by_status {
        let refs: Vec<_> = group.iter().map(|s| s.evidence.clone()).collect();
        let mut by_mime: BTreeMap<String, Vec<(Value, EvidenceRef)>> = BTreeMap::new();
        for sample in group {
            if let Some(body) = &sample.response_json {
                let mime = sample
                    .response_mime
                    .clone()
                    .unwrap_or_else(|| "application/json".to_string());
                by_mime
                    .entry(mime)
                    .or_default()
                    .push((body.clone(), sample.evidence.clone()));
            }
        }
        let mut response = Map::new();
        response.insert(
            "description".to_string(),
            Value::String(format!("Observed {status} response.")),
        );
        if !by_mime.is_empty() {
            let mut content = Map::new();
            for (mime, bodies) in by_mime {
                content.insert(
                    mime,
                    json!({ "schema": schema_from_samples(&bodies)? }),
                );
            }
            response.insert("content".to_string(), Value::Object(content));
        }
        responses.insert(status.to_string(), annotate(response, &refs, "observed"));
    }
    Ok(Value::Object(responses))
}

fn security_schemes(endpoints: &BTreeMap<(String, String), Vec<Exchange>>) -> Map<String, Value> {
    let mut schemes = Map::new();
    let mut authorization = Vec::new();
    let mut proxy = Vec::new();
    let mut cookie = Vec::new();
    for samples in endpoints.values() {
        for sample in samples {
            if sample.redacted_request.contains("authorization") {
                authorization.push(sample.evidence.clone());
            }
            if sample.redacted_request.contains("proxy-authorization") {
                proxy.push(sample.evidence.clone());
            }
            if sample.redacted_request.contains("cookie") {
                cookie.push(sample.evidence.clone());
            }
        }
    }
    if !authorization.is_empty() {
        schemes.insert(
            "authorization".to_string(),
            scheme_object(
                json!({
                    "type": "http",
                    "scheme": "unknown",
                    "description": "Authorization header was observed with a redacted value. The authentication scheme is unknown."
                }),
                &authorization,
            ),
        );
    }
    if !proxy.is_empty() {
        schemes.insert(
            "proxyAuthorization".to_string(),
            scheme_object(
                json!({
                    "type": "http",
                    "scheme": "unknown",
                    "description": "Proxy-Authorization header was observed with a redacted value. The authentication scheme is unknown."
                }),
                &proxy,
            ),
        );
    }
    if !cookie.is_empty() {
        schemes.insert(
            "cookie".to_string(),
            scheme_object(
                json!({
                    "type": "apiKey",
                    "in": "header",
                    "name": "Cookie",
                    "description": "Cookie header was observed with a redacted value. The cookie name and authentication scheme are unknown."
                }),
                &cookie,
            ),
        );
    }
    schemes
}

fn scheme_object(mut base: Value, refs: &[EvidenceRef]) -> Value {
    if let Some(obj) = base.as_object_mut() {
        obj.insert(
            "x-tracewise-evidence".to_string(),
            evidence_array(refs),
        );
        obj.insert(
            "x-tracewise-confidence".to_string(),
            Value::String("inferred".to_string()),
        );
    }
    base
}

fn operation_security(samples: &[Exchange]) -> Option<Value> {
    let mut requirement = Map::new();
    if samples.iter().any(|s| s.redacted_request.contains("authorization")) {
        requirement.insert("authorization".to_string(), json!([]));
    }
    if samples
        .iter()
        .any(|s| s.redacted_request.contains("proxy-authorization"))
    {
        requirement.insert("proxyAuthorization".to_string(), json!([]));
    }
    if samples.iter().any(|s| s.redacted_request.contains("cookie")) {
        requirement.insert("cookie".to_string(), json!([]));
    }
    if requirement.is_empty() {
        None
    } else {
        Some(Value::Array(vec![Value::Object(requirement)]))
    }
}

fn unknown_questions(exchanges: &[Exchange]) -> Vec<(String, UnknownSeverity)> {
    let mut questions = Vec::new();
    if exchanges.iter().any(|e| e.redacted_request.contains("authorization")) {
        questions.push((
            "The authentication scheme for the redacted Authorization header is unknown.".to_string(),
            UnknownSeverity::High,
        ));
    }
    if exchanges
        .iter()
        .any(|e| e.redacted_request.contains("proxy-authorization"))
    {
        questions.push((
            "The authentication scheme for the redacted Proxy-Authorization header is unknown."
                .to_string(),
            UnknownSeverity::High,
        ));
    }
    if exchanges.iter().any(|e| e.redacted_request.contains("cookie")) {
        questions.push((
            "The cookie name and attributes for the redacted Cookie header are unknown.".to_string(),
            UnknownSeverity::High,
        ));
    }
    if exchanges.iter().any(|e| e.redacted_response.contains("set-cookie")) {
        questions.push((
            "The Set-Cookie contract is unknown because response cookie values were redacted."
                .to_string(),
            UnknownSeverity::Medium,
        ));
    }
    let mut statuses: Vec<String> = exchanges
        .iter()
        .map(|e| e.status.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    statuses.sort();
    questions.push((
        format!(
            "Response shapes for status codes other than {} are unknown.",
            join_and(&statuses)
        ),
        UnknownSeverity::Medium,
    ));
    if exchanges.iter().any(|exchange| {
        exchange.request_json.as_ref().is_some_and(value_has_string)
            || exchange.response_json.as_ref().is_some_and(value_has_string)
    }) {
        questions.push((
            "Whether observed string values form a complete enumeration is unknown.".to_string(),
            UnknownSeverity::Low,
        ));
    }
    if exchanges.iter().any(|exchange| {
        exchange.request_json.as_ref().is_some_and(value_has_object)
            || exchange.response_json.as_ref().is_some_and(value_has_object)
    }) {
        questions.push((
            "Object properties absent from every captured sample are unknown.".to_string(),
            UnknownSeverity::Medium,
        ));
    }
    questions.push((
        "Query parameters absent from the captured samples are unknown.".to_string(),
        UnknownSeverity::Low,
    ));
    if exchanges.iter().any(|e| e.request_unparsed || e.response_unparsed) {
        questions.push((
            "Non-JSON request or response bodies have no structural schema.".to_string(),
            UnknownSeverity::Medium,
        ));
    }
    questions
}

fn value_has_string(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(items) => items.iter().any(value_has_string),
        Value::Object(map) => map.values().any(value_has_string),
        _ => false,
    }
}

fn value_has_object(value: &Value) -> bool {
    match value {
        Value::Object(_) => true,
        Value::Array(items) => items.iter().any(value_has_object),
        _ => false,
    }
}

fn residual_input(
    question: String,
    severity: UnknownSeverity,
    supporting_evidence_ids: &[String],
) -> RecordUnknownInput {
    RecordUnknownInput {
        question,
        severity,
        domain: "tracewise.api-spec".to_string(),
        supporting_evidence_ids: supporting_evidence_ids.to_vec(),
        contradicting_evidence_ids: Vec::new(),
        required_authority: None,
        required_confidence: EvidenceConfidence::Observed,
        required_environment: None,
        recommended_probes: vec![Probe {
            operation: "infer_api_spec".to_string(),
            rationale: "Capture another redacted sample that observes this aspect without copying credential values.".to_string(),
        }],
        relationships: Vec::<Relationship>::new(),
    }
}

fn build_evidence(
    input: &InferApiSpecInput,
    sources: &[Evidence],
    openapi: &Value,
    source_ids: &[String],
) -> Result<Evidence, WebError> {
    let mut parameters = Map::new();
    if let Some(path) = &input.capture_path {
        parameters.insert("capture_path".to_string(), Value::String(path.clone()));
    }
    parameters.insert(
        "evidence_ids".to_string(),
        Value::Array(source_ids.iter().cloned().map(Value::String).collect()),
    );
    if let Some(base) = &input.base_url {
        parameters.insert("base_url".to_string(), Value::String(base.clone()));
    }
    if let Some(title) = &input.title {
        parameters.insert("title".to_string(), Value::String(title.clone()));
    }
    if let Some(output) = &input.output_path {
        parameters.insert("output_path".to_string(), Value::String(output.clone()));
    }

    let mut locations = Vec::new();
    for source in sources {
        for location in &source.locations {
            if !locations.contains(location) {
                locations.push(location.clone());
            }
        }
    }
    if let Some(output) = &input.output_path {
        let location = EvidenceLocation::ArtifactPath {
            path: output.clone(),
        };
        if !locations.contains(&location) {
            locations.push(location);
        }
    }

    let limitations = vec![
        "The OpenAPI document is inferred from redacted captures. Credential values are never copied; authentication schemes stay unknown.".to_string(),
        "Path templates, merged JSON types and required fields are inferences from the captured samples, not a declared contract.".to_string(),
        "Status codes, fields, query parameters and enum members absent from the samples are residual unknowns.".to_string(),
    ];

    let observation = EvidenceObservation {
        predicate_type: Some("tracewise.api-spec".to_string()),
        operation: "infer_api_spec".to_string(),
        parameters: Value::Object(parameters),
        normalized_result: openapi.clone(),
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Inferred),
        authority: Some(EvidenceAuthority::AnalystInference),
        environment: None,
        limitations: Some(limitations),
        locations: Some(locations),
        evidence_links: Some(source_ids.to_vec()),
    };

    create_evidence(
        shared_subject(sources),
        EvidenceProvider {
            id: "tracewise.infer-api-spec".to_string(),
            name: "Tracewise API spec inference".to_string(),
            version: Some("0.1.0".to_string()),
        },
        observation,
    )
    .map_err(WebError::from)
}

fn shared_subject(sources: &[Evidence]) -> Option<EvidenceSubject> {
    let subjects: Vec<_> = sources.iter().filter_map(|s| s.subject.clone()).collect();
    let first = subjects.first()?;
    if subjects.iter().all(|s| s.digest.sha256 == first.digest.sha256) {
        Some(first.clone())
    } else {
        None
    }
}

fn unique_operation_id(method: &str, template: &str, used: &mut BTreeSet<String>) -> String {
    let mut id = method.to_ascii_lowercase();
    for segment in template.split('/').filter(|s| !s.is_empty()) {
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            id.push_str("By");
            id.push_str(&pascal(name));
        } else {
            id.push_str(&pascal(segment));
        }
    }
    if id.is_empty() {
        id = method.to_ascii_lowercase();
    }
    let base = id.clone();
    let mut suffix = 2u32;
    while !used.insert(id.clone()) {
        id = format!("{base}_{suffix}");
        suffix += 1;
    }
    id
}

fn pascal(value: &str) -> String {
    let mut out = String::new();
    let mut capitalize = true;
    for ch in value.chars() {
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
    out
}

fn header_pairs(headers: Option<&Value>) -> Vec<(String, Option<String>)> {
    let Some(Value::Array(items)) = headers else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for item in items {
        if let Some(obj) = item.as_object() {
            if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
                let value = obj.get("value").and_then(scalar_string);
                pairs.push((name.to_string(), value));
            }
        } else if let Some(pair) = item.as_array() {
            if pair.len() >= 2 {
                if let Some(name) = pair[0].as_str() {
                    pairs.push((name.to_string(), scalar_string(&pair[1])));
                }
            }
        }
    }
    pairs
}

fn redacted_header_names(headers: &[(String, Option<String>)]) -> BTreeSet<String> {
    const CREDENTIALS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ];
    headers
        .iter()
        .filter(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            CREDENTIALS.contains(&lower.as_str()) && value.is_none()
        })
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect()
}

fn cookies_redacted(cookies: Option<&Value>) -> bool {
    cookies
        .and_then(|v| v.as_array())
        .map(|items| {
            items.iter().any(|cookie| {
                cookie
                    .get("value")
                    .map(|value| value.is_null())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn mime_of(explicit: Option<&Value>, headers: &[(String, Option<String>)]) -> Option<String> {
    explicit
        .and_then(|v| v.as_str())
        .or_else(|| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .and_then(|(_, value)| value.as_deref())
        })
        .map(media_type)
        .filter(|mime| !mime.is_empty())
}

fn media_type(mime: &str) -> String {
    mime.split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase()
}

fn body_text(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if value.is_null() {
        return None;
    }
    scalar_string(value).filter(|text| !text.is_empty())
}

fn parse_body(mime: Option<&str>, text: Option<&str>) -> (Option<Value>, bool) {
    let Some(text) = text else {
        return (None, false);
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return (None, false);
    }
    let json_mime = mime.is_some_and(|mime| mime.contains("json"));
    let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');
    if json_mime || looks_json {
        return match serde_json::from_str(trimmed) {
            Ok(value) => (Some(value), false),
            Err(_) => (None, true),
        };
    }
    (None, true)
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null => None,
        _ => None,
    }
}

fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [first, second] => format!("{first} and {second}"),
        _ => {
            let head = items[..items.len() - 1].join(", ");
            format!("{head} and {}", items[items.len() - 1])
        }
    }
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(child) = map.get(&key) {
                    sorted.insert(key, sort_value(child.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_value).collect()),
        other => other,
    }
}

fn audit_openapi(spec: &Value) -> Result<(), WebError> {
    let paths = spec.get("paths").and_then(|v| v.as_object()).ok_or_else(|| {
        WebError::Format("Inferred document is missing paths.".to_string())
    })?;
    for (path, item) in paths {
        let item = item.as_object().ok_or_else(|| {
            WebError::Format(format!("Path {path} is not an object."))
        })?;
        for method in HTTP_METHODS {
            if let Some(operation) = item.get(*method) {
                require_trace(operation, &format!("{method} {path}"))?;
                if let Some(parameters) = operation.get("parameters").and_then(|v| v.as_array()) {
                    for parameter in parameters {
                        require_trace(parameter, &format!("parameter on {method} {path}"))?;
                        if let Some(schema) = parameter.get("schema") {
                            require_trace(schema, &format!("parameter schema on {method} {path}"))?;
                        }
                    }
                }
                audit_schemas(operation, &format!("{method} {path}"))?;
            }
        }
    }
    Ok(())
}

fn audit_schemas(value: &Value, context: &str) -> Result<(), WebError> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    if let Some(properties) = obj.get("properties").and_then(|v| v.as_object()) {
        require_trace(value, context)?;
        for (name, property) in properties {
            require_trace(property, &format!("property {name} of {context}"))?;
            audit_schemas(property, &format!("property {name} of {context}"))?;
        }
    }
    if let Some(items) = obj.get("items") {
        audit_schemas(items, &format!("items of {context}"))?;
    }
    if let Some(variants) = obj.get("anyOf").and_then(|v| v.as_array()) {
        for variant in variants {
            audit_schemas(variant, context)?;
        }
    }
    if let Some(content) = obj.get("content").and_then(|v| v.as_object()) {
        for (mime, media) in content {
            if let Some(schema) = media.get("schema") {
                audit_schemas(schema, &format!("{mime} schema of {context}"))?;
            }
        }
    }
    if let Some(responses) = obj.get("responses").and_then(|v| v.as_object()) {
        for (status, response) in responses {
            require_trace(response, &format!("response {status} of {context}"))?;
            audit_schemas(response, &format!("response {status} of {context}"))?;
        }
    }
    if let Some(body) = obj.get("requestBody") {
        require_trace(body, &format!("request body of {context}"))?;
        audit_schemas(body, &format!("request body of {context}"))?;
    }
    Ok(())
}

fn require_trace(value: &Value, context: &str) -> Result<(), WebError> {
    let obj = value.as_object().ok_or_else(|| {
        WebError::Format(format!("{context} is not an object."))
    })?;
    let confidence = obj
        .get("x-tracewise-confidence")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WebError::Format(format!("{context} is missing x-tracewise-confidence.")))?;
    if confidence != "observed" && confidence != "inferred" {
        return Err(WebError::Format(format!(
            "{context} has confidence '{confidence}'."
        )));
    }
    let evidence = obj
        .get("x-tracewise-evidence")
        .and_then(|v| v.as_array())
        .ok_or_else(|| WebError::Format(format!("{context} is missing x-tracewise-evidence.")))?;
    if evidence.is_empty() {
        return Err(WebError::Format(format!(
            "{context} has no x-tracewise-evidence entries."
        )));
    }
    Ok(())
}

fn reject_secrets(value: &Value) -> Result<(), WebError> {
    let text = serde_json::to_string(value)?;
    if text.contains("SECRET-") {
        return Err(WebError::Format(
            "Inferred API spec contained a credential marker and was discarded.".to_string(),
        ));
    }
    Ok(())
}

fn write_spec(path: &Path, spec: &Value) -> Result<(), WebError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut text = serde_json::to_string_pretty(spec)?;
    text.push('\n');
    std::fs::write(path, text)?;
    Ok(())
}

fn input_error(field: &str, message: &str) -> WebError {
    WebError::Input {
        operation: "infer_api_spec".to_string(),
        path: vec![field.to_string()],
        reason: "invalid_format".to_string(),
        message: message.to_string(),
    }
}
