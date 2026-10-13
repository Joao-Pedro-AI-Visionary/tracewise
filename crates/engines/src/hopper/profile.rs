//! Hopper open semantics committed to the analysis profile (port of `HopperAnalysisProfile.ts`).

use std::io::Read;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::{create_analysis_profile, AnalysisProfile, CommittedProviderIdentity};

use crate::error::AnalysisError;
use crate::target::BinaryTarget;

fn architecture_flag(architecture: &str) -> &'static str {
    match architecture {
        "x86" => "--intel-32",
        "x86_64" => "--intel-64",
        "arm" => "--armv7",
        _ => "--aarch64",
    }
}

/// Derive Hopper's complete non-interactive CLI loader selection.
pub fn loader_args_for_target(
    target: &BinaryTarget,
    macho_container: Option<&str>,
) -> Result<Vec<String>, AnalysisError> {
    if target.kind == "database" {
        return Ok(Vec::new());
    }
    if target.kind != "executable" {
        return Err(AnalysisError::adapter("hopper", "resolve_analysis_profile"));
    }
    let architecture = target.architecture.as_deref().unwrap_or("");
    if architecture == "mips" {
        return Err(AnalysisError::capability_unavailable(
            "hopper",
            "resolve_analysis_profile",
            "REA's Hopper adapter does not admit MIPS targets. Select a verified Ghidra MIPS profile instead.",
        ));
    }
    let flag = architecture_flag(architecture).to_string();
    let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    match target.format.as_str() {
        "mach-o" => match macho_container {
            None => Err(AnalysisError::capability_unavailable(
                "hopper",
                "resolve_analysis_profile",
                "Mach-O container kind is unknown; resolve the Hopper analysis profile before starting its client.",
            )),
            Some("fat32") | Some("fat64") => {
                let mut v = args(&["-l", "FAT"]);
                v.push(flag);
                v.extend(args(&["-l", "Mach-O"]));
                Ok(v)
            }
            Some(_) => {
                let mut v = args(&["-l", "Mach-O"]);
                v.push(flag);
                Ok(v)
            }
        },
        "elf" => {
            let mut v = args(&["-l", "ELF"]);
            v.push(flag);
            Ok(v)
        }
        "pe" => {
            let mut v = args(&["-l", "WinPE"]);
            v.push(flag);
            Ok(v)
        }
        _ => Err(AnalysisError::adapter("hopper", "resolve_analysis_profile")),
    }
}

fn read_macho_magic(path: &str) -> Result<u32, AnalysisError> {
    let mut file = std::fs::File::open(path).map_err(|e| AnalysisError::BinaryTarget {
        path: path.to_string(),
        reason: format!("Cannot read the Mach-O container header: {e}"),
        constraint: None,
        system_code: None,
    })?;
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes).map_err(|_| AnalysisError::BinaryTarget {
        path: path.to_string(),
        reason: "Mach-O header became truncated before Hopper loader selection".to_string(),
        constraint: None,
        system_code: None,
    })?;
    Ok(u32::from_be_bytes(bytes))
}

fn sha256_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

/// Resolve Hopper open semantics without placing its CLI flags in `BinaryTarget`.
pub fn resolve(
    target: &BinaryTarget,
    launcher_path: &str,
    loader_args_override: &[String],
) -> Result<Option<AnalysisProfile>, AnalysisError> {
    if target.kind != "executable" && target.kind != "database" {
        return Ok(None);
    }
    let mut macho_container: Option<&str> = None;
    if target.kind == "executable" && target.format == "mach-o" {
        let magic = read_macho_magic(&target.path)?;
        macho_container = Some(if [0xcafebabf, 0xbfbafeca].contains(&magic) {
            "fat64"
        } else if [0xcafebabe, 0xbebafeca].contains(&magic) {
            "fat32"
        } else {
            "thin"
        });
        if macho_container == Some("fat64") && loader_args_override.is_empty() {
            return Err(AnalysisError::capability_unavailable(
                "hopper",
                "resolve_analysis_profile",
                "FAT64 Mach-O slices need a prepared thin image, which tracewise does not port yet; thin the Mach-O or supply HOPPER_LOADER_ARGS_JSON.",
            ));
        }
    }
    let derived = loader_args_for_target(target, macho_container)?;
    let loader_args: Vec<String> = if loader_args_override.is_empty() {
        derived
    } else {
        loader_args_override.to_vec()
    };
    let Some(digest) = sha256_file(launcher_path) else {
        return Ok(None);
    };
    let provider = CommittedProviderIdentity {
        id: "hopper".to_string(),
        name: "Hopper Disassembler".to_string(),
        version: format!("launcher-sha256:{digest}"),
    };
    let mut available = target.available_architectures.clone();
    available.sort();
    let mut parameters = Map::new();
    parameters.insert("target_kind".into(), json!(target.kind));
    parameters.insert("target_format".into(), json!(target.format));
    parameters.insert("architecture".into(), json!(target.architecture));
    parameters.insert("available_architectures".into(), json!(available));
    if let Some(container) = macho_container {
        parameters.insert("macho_container".into(), json!(container));
    }
    parameters.insert(
        "loader".into(),
        json!({
            "source": if loader_args_override.is_empty() { "derived" } else { "configured_override" },
            "arguments": loader_args,
        }),
    );
    create_analysis_profile(provider, Value::Object(parameters))
        .map(Some)
        .map_err(|e| AnalysisError::adapter_with("hopper", "resolve_analysis_profile", json!({ "reason": e.to_string() })))
}
