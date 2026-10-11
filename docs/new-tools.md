# Tracewise-owned tools

These tools are not part of REA. `tools/list` returns **28** tools: the 27 REA tools, byte-identical to the REA catalog, then the tools in this document. The machine-readable contract is [`crates/contracts/tracewise_tools.json`](../crates/contracts/tracewise_tools.json).

## infer_api_spec

| Field | Value |
| --- | --- |
| name | `infer_api_spec` |
| title | Infer API Spec |
| annotations | `readOnlyHint: false`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false` |

### Description

Infer an OpenAPI 3.1 document from redacted HAR or mitmproxy captures. Pass `capture_path` to inspect the capture with credential redaction first, or `evidence_ids` of existing `inspect_web_network_capture` evidence. Groups requests by method and templated path (numeric, UUID and long hex segments become `{id}`-style parameters), infers query parameters and JSON schemas for request bodies and responses, and marks a field required only when it appears in every sample. Every operation, parameter and schema property carries `x-tracewise-evidence` (evidence ids and record ordinals) and `x-tracewise-confidence` (`observed` or `inferred`). Aspects that were not observed, including redacted authentication schemes, unseen status codes and enum completeness, are recorded as residual unknowns. Emits Evidence with `predicate_type` `tracewise.api-spec`, confidence `inferred`, and `evidence_links` to the source network evidence. Credential values are never copied into the document.

### inputSchema

Exactly one of `evidence_ids` or `capture_path` is required. Additional properties are rejected.

```json
{
  "type": "object",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "evidence_ids": {
      "type": "array",
      "minItems": 1,
      "items": { "type": "string", "pattern": "^ev_[a-f0-9]{64}$" },
      "description": "Session evidence ids produced by inspect_web_network_capture."
    },
    "capture_path": {
      "type": "string",
      "minLength": 1,
      "description": "Absolute local HAR or mitmproxy capture path. Inspected with credential redaction before inference."
    },
    "base_url": {
      "type": "string",
      "minLength": 1,
      "description": "Optional server URL. Requests outside this prefix are ignored and paths are made relative to it."
    },
    "title": {
      "type": "string",
      "minLength": 1,
      "description": "OpenAPI info.title. Defaults to Inferred API."
    },
    "output_path": {
      "type": "string",
      "minLength": 1,
      "description": "Optional path where the OpenAPI document is written."
    }
  },
  "oneOf": [
    { "required": ["evidence_ids"], "not": { "required": ["capture_path"] } },
    { "required": ["capture_path"], "not": { "required": ["evidence_ids"] } }
  ]
}
```

### outputSchema

The tool result is Evidence. `normalized_result` is the OpenAPI 3.1 document. `confidence` is `inferred` and `authority` is `analyst-inference`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "evidence_id", "subject", "provider", "analysis_profile", "predicate_type",
    "operation", "parameters", "raw_result", "normalized_result", "confidence",
    "authority", "environment", "limitations", "locations", "evidence_links"
  ],
  "properties": {
    "evidence_id": { "type": "string", "pattern": "^ev_[a-f0-9]{64}$" },
    "subject": { "type": ["object", "null"] },
    "provider": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "name", "version"],
      "properties": {
        "id": { "type": "string" },
        "name": { "type": "string" },
        "version": { "type": ["string", "null"] }
      }
    },
    "analysis_profile": {},
    "predicate_type": { "const": "tracewise.api-spec" },
    "operation": { "const": "infer_api_spec" },
    "parameters": { "type": "object" },
    "raw_result": {},
    "normalized_result": {
      "type": "object",
      "required": [
        "openapi", "info", "paths",
        "x-tracewise-evidence", "x-tracewise-confidence", "x-tracewise-unknowns"
      ],
      "properties": {
        "openapi": { "const": "3.1.0" },
        "info": { "type": "object" },
        "servers": { "type": "array" },
        "paths": { "type": "object" },
        "components": { "type": "object" },
        "x-tracewise-evidence": { "type": "array", "minItems": 1 },
        "x-tracewise-confidence": { "const": "inferred" },
        "x-tracewise-unknowns": { "type": "array", "items": { "type": "string" } }
      }
    },
    "confidence": { "const": "inferred" },
    "authority": { "const": "analyst-inference" },
    "environment": {},
    "limitations": { "type": "array", "items": { "type": "string" } },
    "locations": { "type": "array" },
    "evidence_links": {
      "type": "array",
      "minItems": 1,
      "items": { "type": "string", "pattern": "^ev_[a-f0-9]{64}$" }
    }
  }
}
```

### CLI

```bash
tracewise infer-api-spec <capture> -o spec.json
```

Optional flags: `--base-url` and `--title`. The file written by `-o` is the OpenAPI document (`normalized_result`), not the Evidence wrapper.

### Evidence extensions

- `x-tracewise-evidence`: array of `{ "evidence_id", "ordinal" }` pointing at the redacted capture records that support the node.
- `x-tracewise-confidence`: `observed` when the value was seen directly, `inferred` for templated parameters, merged types and required-ness.
- Redacted `Authorization`, `Proxy-Authorization` and `Cookie` headers become security schemes whose scheme is `unknown`. The concrete credential is not stored.
