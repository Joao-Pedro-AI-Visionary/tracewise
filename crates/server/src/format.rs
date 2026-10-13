use std::path::Path;
use sha2::{Digest, Sha256};

pub struct BinaryInfo {
    pub format: String,
    pub architecture: Option<String>,
    pub sha256: String,
}

pub fn inspect_binary_file(path: &Path) -> Result<BinaryInfo, std::io::Error> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = hex::encode(hasher.finalize());

    let (format, architecture) = detect_format_and_arch(&bytes);

    Ok(BinaryInfo {
        format,
        architecture,
        sha256,
    })
}

/// Architecture of the first Mach-O slice, in the vocabulary of `BinaryTarget.architecture`.
pub(crate) fn mach_o_architecture(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let size = file.metadata().ok()?.len();
    match tracewise_native::macho_dyld::read_macho_image(&file, size).ok()? {
        tracewise_native::macho_dyld::ImageFacts::Parsed(slices) => {
            let first = slices.first()?;
            Some(
                match first.architecture.as_str() {
                    "arm64" | "arm64e" | "arm64_32" => "arm64",
                    "x86_64" | "x86_64h" => "x86_64",
                    "i386" => "x86",
                    "arm" => "arm",
                    _ => return None,
                }
                .to_string(),
            )
        }
        _ => None,
    }
}

/// Like [`inspect_binary_file`], with the Mach-O header read by the native parser (the slice
/// architecture of a universal binary, which the byte sniffing below cannot tell). Used for the
/// program file a bundle declares and for Mach-O targets in general.
pub(crate) fn inspect_executable_file(path: &Path) -> Result<BinaryInfo, std::io::Error> {
    use std::io::Read;
    let mut info = inspect_binary_file(path)?;
    let mut head = [0u8; 4];
    let read = std::fs::File::open(path)?.read(&mut head)?;
    if tracewise_native::macho_dyld::has_macho_magic(&head[..read]) {
        info.format = "mach-o".to_string();
        info.architecture = mach_o_architecture(path);
    }
    Ok(info)
}

fn detect_format_and_arch(bytes: &[u8]) -> (String, Option<String>) {
    if bytes.len() >= 4 {
        // ELF: 0x7f, 'E', 'L', 'F'
        if bytes.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
            let arch = if bytes.len() >= 20 {
                // e_machine at byte 18..20
                let machine = if bytes[5] == 1 {
                    // little endian
                    u16::from_le_bytes([bytes[18], bytes[19]])
                } else {
                    // big endian
                    u16::from_be_bytes([bytes[18], bytes[19]])
                };
                match machine {
                    62 => Some("x86_64".to_string()),
                    183 => Some("arm64".to_string()),
                    3 => Some("x86".to_string()),
                    40 => Some("arm".to_string()),
                    _ => None,
                }
            } else {
                None
            };
            return ("elf".to_string(), arch);
        }

        // Mach-O
        let magic = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic == 0xfeedface
            || magic == 0xcefaedfe
            || magic == 0xfeedfacf
            || magic == 0xcffaedfe
            || magic == 0xcafebabe
            || magic == 0xbebafeca
        {
            let arch = if bytes.len() >= 8 {
                let cputype = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                match cputype {
                    0x01000007 => Some("x86_64".to_string()),
                    0x0100000c => Some("arm64".to_string()),
                    7 => Some("x86".to_string()),
                    12 => Some("arm".to_string()),
                    _ => None,
                }
            } else {
                None
            };
            return ("mach-o".to_string(), arch);
        }

        // ZIP: 'P', 'K', 0x03, 0x04 or 0x05, 0x06
        if bytes.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || bytes.starts_with(&[0x50, 0x4b, 0x05, 0x06])
            || bytes.starts_with(&[0x50, 0x4b, 0x07, 0x08])
        {
            return ("zip".to_string(), None);
        }

        // Electron ASAR header pickle
        if bytes.len() >= 17
            && bytes[0..4] == [4, 0, 0, 0]
            && bytes[16] == 0x7b
        {
            return ("asar".to_string(), None);
        }

        // PE / MZ
        if bytes.starts_with(&[0x4d, 0x5a]) {
            if bytes.len() >= 0x40 {
                let pe_offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
                if bytes.len() >= pe_offset + 6 && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
                    let machine = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);
                    let arch = match machine {
                        0x8664 => Some("x86_64".to_string()),
                        0xaa64 => Some("arm64".to_string()),
                        0x014c => Some("x86".to_string()),
                        _ => None,
                    };
                    return ("pe".to_string(), arch);
                }
            }
            return ("dos-mz".to_string(), None);
        }
    }

    ("file".to_string(), None)
}
