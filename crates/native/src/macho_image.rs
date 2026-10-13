//! Mach-O container and image reader for the native inspection tools
//! (`list_architectures`, `inspect_macho`, `inspect_signature`).
//!
//! Replaces the Apple command-line tools REA drives (`lipo`, `otool`, `nm`, `dyld_info`,
//! `dwarfdump`, `file`): the file is read directly, nothing is executed.

use std::fmt;

pub const MH_MAGIC: u32 = 0xfeed_face;
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM: u32 = 0xcefa_edfe;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;

pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
pub const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
pub const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;

/// Failure to interpret the bytes as a Mach-O container or image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachoError(pub String);

impl fmt::Display for MachoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MachoError {}

pub type MachoResult<T> = Result<T, MachoError>;

pub fn fail<T>(message: impl Into<String>) -> MachoResult<T> {
    Err(MachoError(message.into()))
}

// ---------------------------------------------------------------------------
// Byte readers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Bytes<'a> {
    pub data: &'a [u8],
    pub big: bool,
}

impl<'a> Bytes<'a> {
    pub fn new(data: &'a [u8], big: bool) -> Self {
        Self { data, big }
    }

    pub fn u8(&self, at: usize) -> MachoResult<u8> {
        self.data
            .get(at)
            .copied()
            .ok_or_else(|| MachoError(format!("read past end at {at}")))
    }

    pub fn u16(&self, at: usize) -> MachoResult<u16> {
        let raw: [u8; 2] = self.slice(at, 2)?.try_into().unwrap();
        Ok(if self.big { u16::from_be_bytes(raw) } else { u16::from_le_bytes(raw) })
    }

    pub fn u32(&self, at: usize) -> MachoResult<u32> {
        let raw: [u8; 4] = self.slice(at, 4)?.try_into().unwrap();
        Ok(if self.big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    }

    pub fn u64(&self, at: usize) -> MachoResult<u64> {
        let raw: [u8; 8] = self.slice(at, 8)?.try_into().unwrap();
        Ok(if self.big { u64::from_be_bytes(raw) } else { u64::from_le_bytes(raw) })
    }

    pub fn slice(&self, at: usize, length: usize) -> MachoResult<&'a [u8]> {
        let end = at.checked_add(length).ok_or_else(|| MachoError("offset overflow".into()))?;
        self.data
            .get(at..end)
            .ok_or_else(|| MachoError(format!("read of {length} bytes at {at} passes the end ({})", self.data.len())))
    }

    /// Fixed-width NUL-padded name (segment and section names).
    pub fn name16(&self, at: usize) -> MachoResult<String> {
        let raw = self.slice(at, 16)?;
        let end = raw.iter().position(|b| *b == 0).unwrap_or(16);
        Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    /// NUL-terminated string at an absolute offset (lossy UTF-8).
    pub fn cstring(&self, at: usize) -> MachoResult<String> {
        let tail = self.data.get(at..).ok_or_else(|| MachoError(format!("string offset {at} passes the end")))?;
        let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
        Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
    }
}

// ---------------------------------------------------------------------------
// Fat container
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Container {
    Thin,
    Fat { wide: bool, arches: Vec<FatArch> },
}

const MAX_FAT_ARCHES: u32 = 128;

/// Parse a universal header, or report a thin image (any Mach-O magic).
pub fn parse_container(data: &[u8]) -> MachoResult<Container> {
    if data.len() < 4 {
        return fail("file is too small to be a Mach-O");
    }
    let be = Bytes::new(data, true);
    let magic = be.u32(0)?;
    match magic {
        FAT_MAGIC | FAT_MAGIC_64 => {
            let wide = magic == FAT_MAGIC_64;
            let count = be.u32(4)?;
            if count == 0 || count > MAX_FAT_ARCHES {
                return fail(format!("universal header declares {count} architectures"));
            }
            let stride = if wide { 32 } else { 20 };
            let mut arches = Vec::new();
            for index in 0..count as usize {
                let at = 8 + index * stride;
                let arch = if wide {
                    FatArch {
                        cputype: be.u32(at)?,
                        cpusubtype: be.u32(at + 4)?,
                        offset: be.u64(at + 8)?,
                        size: be.u64(at + 16)?,
                        align: be.u32(at + 24)?,
                    }
                } else {
                    FatArch {
                        cputype: be.u32(at)?,
                        cpusubtype: be.u32(at + 4)?,
                        offset: u64::from(be.u32(at + 8)?),
                        size: u64::from(be.u32(at + 12)?),
                        align: be.u32(at + 16)?,
                    }
                };
                arches.push(arch);
            }
            Ok(Container::Fat { wide, arches })
        }
        MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64 => Ok(Container::Thin),
        0xbeba_feca | 0xbfba_feca => {
            // Little-endian universal headers do not occur in practice; lipo rejects them.
            fail("byte-swapped universal header")
        }
        other => fail(format!("unknown Mach-O magic 0x{other:08x}")),
    }
}

// ---------------------------------------------------------------------------
// lipo naming (cctools arch_flags table)
// ---------------------------------------------------------------------------

/// `lipo` slice name for a CPU type/subtype pair (`None` when lipo prints no name).
pub fn lipo_architecture_name(cputype: u32, cpusubtype: u32) -> Option<&'static str> {
    let subtype = cpusubtype & !CPU_SUBTYPE_MASK;
    Some(match cputype {
        CPU_TYPE_X86 => match subtype {
            3 => "i386",
            4 => "i486",
            0x84 => "i486SX",
            5 => "pentium",
            0x16 => "pentpro",
            0x26 => "pentIIm3",
            0x36 => "pentIIm5",
            0x0a => "pentium4",
            _ => "i386",
        },
        CPU_TYPE_X86_64 => match subtype {
            8 => "x86_64h",
            _ => "x86_64",
        },
        CPU_TYPE_ARM => match subtype {
            0 => "arm",
            5 => "armv4t",
            6 => "armv6",
            7 => "armv5",
            8 => "xscale",
            9 => "armv7",
            10 => "armv7f",
            11 => "armv7s",
            12 => "armv7k",
            13 => "armv8",
            14 => "armv6m",
            15 => "armv7m",
            16 => "armv7em",
            _ => return None,
        },
        CPU_TYPE_ARM64 => match subtype {
            0 => "arm64",
            1 => "arm64v8",
            2 => "arm64e",
            _ => return None,
        },
        CPU_TYPE_ARM64_32 => match subtype {
            0 => "arm64_32",
            1 => "arm64_32v8",
            _ => return None,
        },
        CPU_TYPE_POWERPC => match subtype {
            0 => "ppc",
            1 => "ppc601",
            2 => "ppc602",
            3 => "ppc603",
            4 => "ppc603e",
            5 => "ppc603ev",
            6 => "ppc604",
            7 => "ppc604e",
            8 => "ppc750",
            9 => "ppc7400",
            10 => "ppc7450",
            100 => "ppc970",
            _ => return None,
        },
        CPU_TYPE_POWERPC64 => match subtype {
            0 => "ppc64",
            100 => "ppc970-64",
            _ => return None,
        },
        _ => return None,
    })
}

/// `lipo -detailed_info` spelling of the CPU type.
pub fn lipo_cpu_type(cputype: u32) -> String {
    match cputype {
        CPU_TYPE_X86 => "CPU_TYPE_X86".to_string(),
        CPU_TYPE_X86_64 => "CPU_TYPE_X86_64".to_string(),
        CPU_TYPE_ARM => "CPU_TYPE_ARM".to_string(),
        CPU_TYPE_ARM64 => "CPU_TYPE_ARM64".to_string(),
        CPU_TYPE_ARM64_32 => "CPU_TYPE_ARM64_32".to_string(),
        CPU_TYPE_POWERPC => "CPU_TYPE_POWERPC".to_string(),
        CPU_TYPE_POWERPC64 => "CPU_TYPE_POWERPC64".to_string(),
        other => other.to_string(),
    }
}

/// `lipo -detailed_info` spelling of the CPU subtype (capability bits stripped).
pub fn lipo_cpu_subtype(cputype: u32, cpusubtype: u32) -> String {
    let subtype = cpusubtype & !CPU_SUBTYPE_MASK;
    let name = match (cputype, subtype) {
        (CPU_TYPE_X86, 3) => Some("CPU_SUBTYPE_X86_ALL"),
        (CPU_TYPE_X86_64, 3) => Some("CPU_SUBTYPE_X86_64_ALL"),
        (CPU_TYPE_X86_64, 8) => Some("CPU_SUBTYPE_X86_64_H"),
        (CPU_TYPE_ARM64, 0) => Some("CPU_SUBTYPE_ARM64_ALL"),
        (CPU_TYPE_ARM64, 1) => Some("CPU_SUBTYPE_ARM64_V8"),
        (CPU_TYPE_ARM64, 2) => Some("CPU_SUBTYPE_ARM64E"),
        (CPU_TYPE_ARM64_32, 0) => Some("CPU_SUBTYPE_ARM64_32_ALL"),
        (CPU_TYPE_ARM64_32, 1) => Some("CPU_SUBTYPE_ARM64_32_V8"),
        (CPU_TYPE_ARM, 9) => Some("CPU_SUBTYPE_ARM_V7"),
        (CPU_TYPE_ARM, 11) => Some("CPU_SUBTYPE_ARM_V7S"),
        (CPU_TYPE_ARM, 12) => Some("CPU_SUBTYPE_ARM_V7K"),
        (CPU_TYPE_POWERPC, 0) => Some("CPU_SUBTYPE_POWERPC_ALL"),
        (CPU_TYPE_POWERPC, 100) => Some("CPU_SUBTYPE_POWERPC_970"),
        _ => None,
    };
    match name {
        Some(text) => text.to_string(),
        None => subtype.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Thin image
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Header {
    pub big: bool,
    pub is64: bool,
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct LoadCommand {
    pub index: u32,
    pub cmd: u32,
    pub cmdsize: u32,
    /// Offset of the command inside the slice.
    pub offset: usize,
}

pub struct Image<'a> {
    /// The bytes of this slice only.
    pub data: &'a [u8],
    pub header: Header,
    pub commands: Vec<LoadCommand>,
}

pub const MAX_LOAD_COMMAND_BYTES: u32 = 16 * 1024 * 1024;

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> MachoResult<Self> {
        if data.len() < 28 {
            return fail("Mach-O image is smaller than its header");
        }
        let magic_be = Bytes::new(data, true).u32(0)?;
        let (big, is64) = match magic_be {
            MH_MAGIC => (true, false),
            MH_MAGIC_64 => (true, true),
            MH_CIGAM => (false, false),
            MH_CIGAM_64 => (false, true),
            other => return fail(format!("not a Mach-O image: magic 0x{other:08x}")),
        };
        let bytes = Bytes::new(data, big);
        let header_size = if is64 { 32 } else { 28 };
        if data.len() < header_size {
            return fail("Mach-O image is smaller than its header");
        }
        let header = Header {
            big,
            is64,
            magic: if big { magic_be } else { bytes.u32(0)? },
            cputype: bytes.u32(4)?,
            cpusubtype: bytes.u32(8)?,
            filetype: bytes.u32(12)?,
            ncmds: bytes.u32(16)?,
            sizeofcmds: bytes.u32(20)?,
            flags: bytes.u32(24)?,
        };
        if header.sizeofcmds > MAX_LOAD_COMMAND_BYTES {
            return fail(format!("load commands declare {} bytes", header.sizeofcmds));
        }
        let end = header_size + header.sizeofcmds as usize;
        if end > data.len() {
            return fail("load commands extend past the end of the image");
        }
        let mut commands = Vec::new();
        let mut at = header_size;
        for index in 0..header.ncmds {
            if at + 8 > end {
                return fail(format!("load command {index} starts past the declared command area"));
            }
            let cmd = bytes.u32(at)?;
            let cmdsize = bytes.u32(at + 4)?;
            if cmdsize < 8 || at + cmdsize as usize > end {
                return fail(format!("load command {index} has invalid size {cmdsize}"));
            }
            commands.push(LoadCommand { index, cmd, cmdsize, offset: at });
            at += cmdsize as usize;
        }
        Ok(Self { data, header, commands })
    }

    pub fn bytes(&self) -> Bytes<'a> {
        Bytes::new(self.data, self.header.big)
    }
}

/// Which slice bytes to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceSelection {
    /// Offset of the slice inside the file.
    pub offset: u64,
    pub size: u64,
    /// `lipo` architecture name, `None` for a thin file.
    pub name: Option<String>,
}

/// Choose the slice REA would analyse: the requested architecture of a universal file, or the
/// whole thin file. `requested` follows `BinaryTarget.architecture` (`x86` is lipo's `i386`).
pub fn select_slice(
    data: &[u8],
    container: &Container,
    requested: Option<&str>,
) -> MachoResult<SliceSelection> {
    match container {
        Container::Thin => Ok(SliceSelection { offset: 0, size: data.len() as u64, name: None }),
        Container::Fat { arches, .. } => {
            if arches.len() < 2 || requested.is_none() {
                let first = &arches[0];
                return Ok(SliceSelection {
                    offset: first.offset,
                    size: first.size,
                    name: if arches.len() < 2 {
                        None
                    } else {
                        lipo_architecture_name(first.cputype, first.cpusubtype).map(String::from)
                    },
                });
            }
            let requested = requested.unwrap();
            let normalized = if requested == "x86" { "i386" } else { requested };
            let names: Vec<Option<&'static str>> =
                arches.iter().map(|a| lipo_architecture_name(a.cputype, a.cpusubtype)).collect();
            let pick = |wanted: &str| names.iter().position(|n| *n == Some(wanted));
            let index = pick(normalized).or_else(|| if normalized == "arm64" { pick("arm64e") } else { None });
            match index {
                Some(i) => Ok(SliceSelection {
                    offset: arches[i].offset,
                    size: arches[i].size,
                    name: names[i].map(String::from),
                }),
                None => fail(format!("lipo did not list {normalized}; refusing to read another slice")),
            }
        }
    }
}

pub fn slice_bytes<'a>(data: &'a [u8], selection: &SliceSelection) -> MachoResult<&'a [u8]> {
    let start = selection.offset as usize;
    let end = start
        .checked_add(selection.size as usize)
        .ok_or_else(|| MachoError("slice range overflows".into()))?;
    data.get(start..end)
        .ok_or_else(|| MachoError(format!("slice [{start}, {end}) passes the end of the file ({})", data.len())))
}
