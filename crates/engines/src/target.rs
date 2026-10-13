//! Provider-neutral target classification (subset of `domain/binaryTarget.ts`).
//!
//! The session (phase 0) already hashes the file and names its format and CPU. The
//! engines need a little more: the exact set of Mach-O slices and the PE role, because
//! provider support and the analysis profile commit to them.

use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};

/// CPU families REA admits at the provider boundary.
pub const ARCHITECTURES: [&str; 5] = ["x86", "x86_64", "arm", "arm64", "mips"];

#[derive(Debug, Clone, PartialEq)]
pub struct BinaryTarget {
    pub path: String,
    pub kind: String,
    pub format: String,
    pub architecture: Option<String>,
    pub available_architectures: Vec<String>,
    pub sha256: String,
    /// PE only: `application`, `shared-library` or `non-executable`.
    pub executable_role: Option<String>,
    /// PE only: whether a CLI header is declared.
    pub managed: Option<bool>,
    /// Raw ELF class/type/flags for MIPS targets (family recognition only).
    pub mips_elf: Option<MipsElf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MipsElf {
    pub elf_class: u8,
    pub big_endian: bool,
    pub e_type: u16,
    pub flags: u32,
}

impl BinaryTarget {
    /// Build a target from the session subject plus the file's header.
    pub fn from_session(
        local_path: &str,
        format: &str,
        architecture: Option<&str>,
        sha256: &str,
    ) -> Self {
        let kind = match format {
            "zip" | "ipa" | "apk" | "msix" | "appx" | "asar" | "dmg" | "pkg" => "archive",
            "analysis-database" | "hopper" => "database",
            "source-map" | "plist" | "javascript" => "artifact",
            "directory" => "directory",
            _ => "executable",
        };
        let mut target = Self {
            path: local_path.to_string(),
            kind: kind.to_string(),
            format: format.to_string(),
            architecture: architecture.map(str::to_string),
            available_architectures: architecture.map(|a| vec![a.to_string()]).unwrap_or_default(),
            sha256: sha256.to_string(),
            executable_role: None,
            managed: None,
            mips_elf: None,
        };
        if kind == "executable" {
            if let Some(header) = read_header(local_path, 4096) {
                target.refine(&header);
            }
        }
        target
    }

    fn refine(&mut self, header: &[u8]) {
        match self.format.as_str() {
            "elf" => {
                if header.len() >= 20 && header.starts_with(b"\x7fELF") {
                    let big = header[5] == 2;
                    let u16_at = |o: usize| {
                        if big {
                            u16::from_be_bytes([header[o], header[o + 1]])
                        } else {
                            u16::from_le_bytes([header[o], header[o + 1]])
                        }
                    };
                    if u16_at(18) == 8 {
                        // EM_MIPS: family recognized, no ISA/ABI support claimed.
                        self.architecture = Some("mips".to_string());
                        self.available_architectures = vec!["mips".to_string()];
                        let flags = if header.len() >= 52 {
                            let b = &header[36..40];
                            if big {
                                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
                            } else {
                                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                            }
                        } else {
                            0
                        };
                        self.mips_elf = Some(MipsElf {
                            elf_class: if header[4] == 2 { 64 } else { 32 },
                            big_endian: big,
                            e_type: u16_at(16),
                            flags,
                        });
                    }
                }
            }
            "mach-o" => {
                if header.len() >= 8 {
                    let magic = [header[0], header[1], header[2], header[3]];
                    if magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xca, 0xfe, 0xba, 0xbf] {
                        let count = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
                        let stride = if magic[3] == 0xbf { 32 } else { 20 };
                        let mut found: Vec<String> = Vec::new();
                        for index in 0..count.min(32) {
                            let o = 8 + index * stride;
                            if header.len() < o + 4 {
                                break;
                            }
                            let cpu = u32::from_be_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]);
                            if let Some(name) = macho_cpu(cpu) {
                                if !found.iter().any(|f| f == name) {
                                    found.push(name.to_string());
                                }
                            }
                        }
                        if !found.is_empty() {
                            self.available_architectures = found;
                        }
                    }
                }
            }
            "pe" if header.len() >= 0x40 => {
                {
                    let pe = u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as usize;
                    if header.len() >= pe + 24 + 96 && &header[pe..pe + 4] == b"PE\0\0" {
                        let characteristics = u16::from_le_bytes([header[pe + 22], header[pe + 23]]);
                        let optional = pe + 24;
                        let magic = u16::from_le_bytes([header[optional], header[optional + 1]]);
                        let dirs_offset = if magic == 0x20b { optional + 112 } else { optional + 96 };
                        let cli_entry = dirs_offset + 14 * 8;
                        let managed = header.len() >= cli_entry + 8
                            && u32::from_le_bytes([
                                header[cli_entry],
                                header[cli_entry + 1],
                                header[cli_entry + 2],
                                header[cli_entry + 3],
                            ]) != 0;
                        self.managed = Some(managed);
                        let executable = characteristics & 0x0002 != 0;
                        let dll = characteristics & 0x2000 != 0;
                        self.executable_role = Some(
                            if !executable {
                                "non-executable"
                            } else if dll {
                                "shared-library"
                            } else {
                                "application"
                            }
                            .to_string(),
                        );
                    } else {
                        // Header larger than the probe: fall back to a conservative PE application.
                        self.managed = Some(false);
                        self.executable_role = Some("application".to_string());
                    }
                }
            }
            _ => {}
        }
    }

    pub fn file_name(&self) -> String {
        Path::new(&self.path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| self.path.clone())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "kind": self.kind,
            "format": self.format,
            "architecture": self.architecture,
            "available_architectures": self.available_architectures,
            "sha256": self.sha256,
        })
    }
}

fn macho_cpu(cpu: u32) -> Option<&'static str> {
    match cpu {
        0x0100_0007 => Some("x86_64"),
        0x0100_000c => Some("arm64"),
        7 => Some("x86"),
        12 => Some("arm"),
        _ => None,
    }
}

fn read_header(path: &str, limit: usize) -> Option<Vec<u8>> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; limit];
    let mut total = 0;
    while total < limit {
        match file.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => return None,
        }
    }
    buffer.truncate(total);
    Some(buffer)
}
