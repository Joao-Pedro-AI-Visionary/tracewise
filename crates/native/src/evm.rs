//! `inspect_evm_interface` (port of REA `evm/*`): selector, argument and
//! mutability inference over flat EVM bytecode with the `evmole` 0.9.3 crate,
//! the Rust sources of the engine REA ships as WASM.

use std::path::Path;
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ArtifactReason, InputIssue, NativeError, NativeResult};
use crate::pe_resources::read_stable_artifact;
use crate::plistjs::js_number;

const OPERATION: &str = "inspect_evm_interface";
pub const EVM_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const EVM_TIMEOUT_MS: u64 = 30_000;

pub const EVMOLE_PROVIDER_ID: &str = "evmole-interface";
pub const EVMOLE_PROVIDER_NAME: &str = "REA EVM interface adapter";
pub const EVMOLE_PROVIDER_VERSION: &str = "evmole@0.9.3";

fn empty_output() -> Value {
    json!({"stdout": "", "stderr": "", "truncated": false})
}

fn captured(error: NativeError) -> NativeError {
    NativeError::Captured {
        inner: Box::new(error),
        output: empty_output(),
    }
}

/// Decode only the explicitly selected representation; source carrier bytes are retained separately.
pub fn decode_evm_bytecode_carrier(bytes: &[u8], encoding: &str) -> Result<Vec<u8>, String> {
    if encoding == "raw" {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Hex carrier must be valid UTF-8.".to_string())?;
    let is_space = |c: char| matches!(c, '\u{9}'..='\u{d}' | ' ');
    let trimmed = text.trim_matches(is_space);
    let code = if trimmed.get(..2).map(|prefix| prefix.eq_ignore_ascii_case("0x")).unwrap_or(false) {
        &trimmed[2..]
    } else {
        trimmed
    };
    if code.len() % 2 != 0 || !code.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid.".to_string());
    }
    Ok(hex::decode(code).unwrap_or_default())
}

fn cbor_value(value: &evmole::CborValue) -> Value {
    match value {
        evmole::CborValue::String(text) => json!({"type": "string", "value": text}),
        evmole::CborValue::Integer(number) => json!({"type": "integer", "value": js_number(*number as f64)}),
        evmole::CborValue::Bytes(bytes) => json!({"type": "bytes", "value": hex::encode(bytes)}),
        evmole::CborValue::Bool(flag) => json!({"type": "bool", "value": flag}),
        evmole::CborValue::Undecoded(bytes) => json!({"type": "undecoded", "value": hex::encode(bytes)}),
    }
}

/// The engine reply in the exact producer representation (`functions` and `metadata` only).
fn engine_reply(code: &[u8]) -> Value {
    let contract = evmole::contract_info(
        evmole::ContractInfoArgs::new(code)
            .with_selectors()
            .with_arguments()
            .with_state_mutability(),
    );
    let mut raw = serde_json::Map::new();
    if let Some(metadata) = &contract.metadata {
        raw.insert(
            "metadata".into(),
            json!({
                "bytecodeOffset": metadata.bytecode_offset,
                "cborLength": metadata.cbor_length,
                "entries": metadata.entries.iter().map(|entry| json!({
                    "key": entry.key,
                    "value": cbor_value(&entry.value),
                })).collect::<Vec<_>>(),
            }),
        );
    }
    let functions: Vec<Value> = contract
        .functions
        .unwrap_or_default()
        .iter()
        .map(|function| {
            let mut item = serde_json::Map::new();
            item.insert("selector".into(), json!(hex::encode(function.selector)));
            item.insert("bytecodeOffset".into(), json!(function.bytecode_offset));
            item.insert("dispatch".into(), json!(function.dispatch.as_str()));
            if let Some(arguments) = &function.arguments {
                item.insert(
                    "arguments".into(),
                    json!(arguments
                        .iter()
                        .map(|t| t.sol_type_name().to_string())
                        .collect::<Vec<_>>()
                        .join(",")),
                );
            }
            if let Some(mutability) = &function.state_mutability {
                item.insert("stateMutability".into(), json!(mutability.as_json_str()));
            }
            Value::Object(item)
        })
        .collect();
    raw.insert("functions".into(), Value::Array(functions));
    Value::Object(raw)
}

pub struct EvmOutcome {
    pub report: Value,
    pub raw: Value,
    pub carrier_sha256: String,
    pub limitations: Vec<String>,
}

pub struct EvmRequest<'a> {
    pub path: &'a str,
    pub encoding: &'a str,
}

fn limitations() -> Vec<String> {
    vec![
        format!("The inference runs in-process with the evmole 0.9.3 Rust crate (the sources of the engine REA ships as WASM) under a {}-second deadline and a {}-byte input limit; there is no separate resource-limited worker process.", EVM_TIMEOUT_MS / 1000, EVM_INPUT_BYTES),
        "Upstream may also report terminal metadata while recovering selectors. Its reported values are retained in raw_result; integer values are emitted as JSON numbers and may lose precision beyond 2^53, and non-text-key coverage is unknown; complete original bytecode remains available.".to_string(),
        "Recovered selectors, argument strings and mutability are upstream inferences, not verified ABI signatures or names. Empty results do not prove the absence of callable dispatch.".to_string(),
        "Bytecode kind, hardfork and deployed-contract authenticity are unknown. This inspection performs no target runtime execution, chain/RPC lookup or network request.".to_string(),
        "Original carrier and decoded bytecode SHA-256 are distinct identities; SHA-256 is not the Ethereum Keccak code hash.".to_string(),
    ]
}

/// Read the carrier, infer the interface and project the Evidence payload.
/// Engine threads that are still running. `evmole` has no cancellation hook, so a thread that
/// outlives its timeout cannot be stopped; the cap stops repeated pathological inputs from
/// piling up runaway threads.
static RUNNING_ENGINES: AtomicUsize = AtomicUsize::new(0);
const MAX_RUNNING_ENGINES: usize = 2;
/// How often the waiting analysis looks at its cancellation token.
const CANCEL_POLL: Duration = Duration::from_millis(25);

struct EngineSlot;

impl EngineSlot {
    fn take() -> Option<Self> {
        let mut current = RUNNING_ENGINES.load(Ordering::Acquire);
        loop {
            if current >= MAX_RUNNING_ENGINES {
                return None;
            }
            match RUNNING_ENGINES.compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(EngineSlot),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for EngineSlot {
    fn drop(&mut self) {
        RUNNING_ENGINES.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Run the engine on its own thread with a deadline. The calling thread is a blocking-pool
/// worker (see the server track), so waiting here does not stall the async runtime; it stops
/// waiting when the request is cancelled or the deadline passes.
fn run_engine(bytes: &[u8]) -> NativeResult<Value> {
    let Some(slot) = EngineSlot::take() else {
        return Err(captured(NativeError::Resource {
            operation: OPERATION.to_string(),
            resource: "memory".to_string(),
            reason: "Earlier EVM analyses are still running; retry when they finish.".to_string(),
            reported_limits: json!({ "max_concurrent_engines": MAX_RUNNING_ENGINES }),
        }));
    };
    let (sender, receiver) = mpsc::channel();
    let worker_bytes = bytes.to_vec();
    std::thread::Builder::new()
        .name("evm-interface-engine".to_string())
        .spawn(move || {
            // The slot is held until the engine really returns, even when nobody is waiting.
            let _slot = slot;
            let outcome = std::panic::catch_unwind(|| engine_reply(&worker_bytes));
            let _ = sender.send(outcome);
        })
        .map_err(|error| captured(NativeError::output(OPERATION, format!("could not start the engine thread: {error}"))))?;
    let deadline = Instant::now() + Duration::from_millis(EVM_TIMEOUT_MS);
    loop {
        match receiver.recv_timeout(CANCEL_POLL) {
            Ok(Ok(raw)) => return Ok(raw),
            Ok(Err(_)) => {
                return Err(captured(NativeError::output(
                    OPERATION,
                    "The EVM interface engine terminated abnormally while analysing the bytecode.",
                )))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(captured(NativeError::output(
                    OPERATION,
                    "The EVM interface engine terminated abnormally while analysing the bytecode.",
                )))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if crate::cancel::cancelled() {
                    return Err(NativeError::Cancelled { operation: OPERATION.to_string() });
                }
                if Instant::now() >= deadline {
                    return Err(captured(NativeError::Timeout {
                        operation: OPERATION.to_string(),
                        timeout_ms: EVM_TIMEOUT_MS,
                    }));
                }
            }
        }
    }
}

pub fn inspect_evm_interface(request: &EvmRequest<'_>) -> NativeResult<EvmOutcome> {
    let (carrier, carrier_sha256) = match read_stable_artifact(Path::new(request.path), EVM_INPUT_BYTES, OPERATION) {
        Ok(read) => read,
        Err(NativeError::Artifact { reason, detail, .. }) => {
            let message = detail.unwrap_or_default();
            return Err(match reason {
                ArtifactReason::Integrity => NativeError::ArtifactChanged {
                    operation: OPERATION.to_string(),
                    path: request.path.to_string(),
                    reason: message,
                },
                ArtifactReason::Limit | ArtifactReason::Path | ArtifactReason::Format => NativeError::Input {
                    operation: OPERATION.to_string(),
                    issues: vec![InputIssue {
                        path: vec![json!("path")],
                        reason: if reason == ArtifactReason::Limit { "out_of_range" } else { "invalid_format" }.to_string(),
                        message: Some(message),
                        expected: None,
                    }],
                },
                _ => {
                    // Node-shaped fs failures keep the carrier path in the message.
                    if message.starts_with("ENOENT") || message.starts_with("ENOTDIR") {
                        let code = message.split(':').next().unwrap_or("ENOENT").to_string();
                        NativeError::Input {
                            operation: OPERATION.to_string(),
                            issues: vec![InputIssue::invalid(
                                vec![json!("path")],
                                format!("Selected bytecode carrier could not be read ({code}): {}.", request.path),
                            )],
                        }
                    } else {
                        NativeError::Artifact {
                            operation: OPERATION.to_string(),
                            reason,
                            detail: Some(message),
                        }
                    }
                }
            });
        }
        Err(other) => return Err(other),
    };
    let bytes = decode_evm_bytecode_carrier(&carrier, request.encoding).map_err(|message| {
        captured(NativeError::Input {
            operation: OPERATION.to_string(),
            issues: vec![InputIssue {
                path: vec![json!("path")],
                reason: "invalid_format".to_string(),
                message: Some(message),
                expected: None,
            }],
        })
    })?;
    if bytes.len() >= 2 && bytes[0] == 0xef && bytes[1] == 0x00 {
        return Err(captured(NativeError::UnsupportedTarget {
            operation: OPERATION.to_string(),
            path: request.path.to_string(),
            reason: "Container marker EF00 is outside the verified flat-bytecode interface profile.".to_string(),
            remediation: None,
        }));
    }
    let raw = run_engine(&bytes)?;
    let decoded_sha = hex::encode(Sha256::digest(&bytes));
    let functions: Vec<Value> = raw["functions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|function| {
            json!({
                "selector": format!("0x{}", function["selector"].as_str().unwrap_or("")),
                "bytecode_offset": function["bytecodeOffset"],
                "dispatch": function["dispatch"],
                "inferred_arguments": function.get("arguments").cloned().unwrap_or(Value::Null),
                "inferred_state_mutability": function.get("stateMutability").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    for function in &functions {
        if function["bytecode_offset"].as_u64().unwrap_or(0) >= bytes.len() as u64 {
            return Err(captured(NativeError::output(
                OPERATION,
                "Interface worker returned invalid bytecode-relative evidence: Inferred body offset lies outside the selected bytecode.",
            )));
        }
    }
    let limitations = limitations();
    let report = json!({
        "artifact": {
            "path": request.path,
            "sha256": carrier_sha256,
            "bytes": carrier.len(),
            "encoding": request.encoding,
        },
        "bytecode": {
            "sha256": decoded_sha,
            "bytes": bytes.len(),
            "hex": hex::encode(&bytes),
            "digest_algorithm": "sha256",
            "kind": "unknown",
            "deployment_authenticity": "unknown",
            "hardfork": "unknown",
        },
        "evidence_kind": "inferred",
        "functions": functions,
        "discovery_completeness": "unknown",
        "runtime_execution": "not-performed",
        "diagnostics": empty_output(),
        "limitations": limitations.clone(),
    });
    Ok(EvmOutcome {
        report,
        raw,
        carrier_sha256,
        limitations,
    })
}
