//! `inspect_pe_resources` (port of REA `native/pe/PeResourceParser.ts`,
//! `PeResourceLayout.ts`, `PeResourcesProvider.ts`, `PeResourcesService.ts`).

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ArtifactReason, NativeError, NativeResult};

const OPERATION: &str = "inspect_pe_resources";
const METADATA_BYTES: usize = 8 * 1024 * 1024;

/// Internal failure; `Format`/`Limit` mirror `ArtifactReaderFailure` reasons.
#[derive(Debug)]
pub enum PeFailure {
    Format(String),
    Limit(String),
}

fn pe_failure<T>(message: impl Into<String>) -> Result<T, PeFailure> {
    Err(PeFailure::Format(message.into()))
}

fn limit<T>(message: impl Into<String>) -> Result<T, PeFailure> {
    Err(PeFailure::Limit(message.into()))
}

fn require_range(bytes: &[u8], offset: i64, length: i64) -> Result<(), PeFailure> {
    if offset < 0 || length < 0 || offset > bytes.len() as i64 - length {
        return pe_failure(format!("PE range {offset} + {length} leaves the artifact."));
    }
    Ok(())
}

fn u16_at(bytes: &[u8], at: i64) -> Result<u16, PeFailure> {
    require_range(bytes, at, 2)?;
    let at = at as usize;
    Ok(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn u32_at(bytes: &[u8], at: i64) -> Result<u32, PeFailure> {
    require_range(bytes, at, 4)?;
    let at = at as usize;
    Ok(u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]))
}

#[derive(Clone, Copy)]
struct Section {
    rva: i64,
    virtual_size: i64,
    offset: i64,
    size: i64,
}

struct Layout {
    format: &'static str,
    machine: u16,
    directory_at: i64,
    rva: i64,
    size: i64,
    header_size: i64,
    sections: Vec<Section>,
}

fn read_layout(bytes: &[u8]) -> Result<Layout, PeFailure> {
    require_range(bytes, 0, 64)?;
    if u16_at(bytes, 0)? != 0x5a4d {
        return pe_failure("Expected an MZ PE image.");
    }
    let pe = i64::from(u32_at(bytes, 60)?);
    require_range(bytes, pe, 24)?;
    if u32_at(bytes, pe)? != 0x4550 {
        return pe_failure("Expected a PE signature.");
    }
    let section_count = i64::from(u16_at(bytes, pe + 6)?);
    let optional_size = i64::from(u16_at(bytes, pe + 20)?);
    let optional = pe + 24;
    require_range(bytes, optional, optional_size)?;
    if optional_size < 64 {
        return pe_failure("Truncated PE optional header.");
    }
    let magic = u16_at(bytes, optional)?;
    if magic != 0x10b && magic != 0x20b {
        return pe_failure("Unsupported PE optional header magic.");
    }
    let count_at = if magic == 0x10b { 92 } else { 108 };
    let directories_at = count_at + 4;
    if optional_size < directories_at {
        return pe_failure("Truncated PE data directory count.");
    }
    let directory_count = i64::from(u32_at(bytes, optional + count_at)?);
    if directory_count > (optional_size - directories_at) / 8 {
        return pe_failure("PE directory count exceeds its optional header.");
    }
    let header_size = i64::from(u32_at(bytes, optional + 60)?);
    let table = optional + optional_size;
    require_range(bytes, table, section_count * 40)?;
    if header_size < table + section_count * 40 || header_size > bytes.len() as i64 {
        return pe_failure("Invalid PE SizeOfHeaders.");
    }
    let mut sections: Vec<Section> = Vec::new();
    for index in 0..section_count {
        let at = table + index * 40;
        let section = Section {
            rva: i64::from(u32_at(bytes, at + 12)?),
            virtual_size: i64::from(u32_at(bytes, at + 8)?),
            offset: i64::from(u32_at(bytes, at + 20)?),
            size: i64::from(u32_at(bytes, at + 16)?),
        };
        if section.rva + section.virtual_size.max(section.size) > 0x1_0000_0000 {
            return pe_failure("PE section RVA range overflows.");
        }
        if section.size > 0 {
            require_range(bytes, section.offset, section.size)?;
            if section.offset < header_size {
                return pe_failure("PE section raw bytes overlap headers.");
            }
        }
        sections.push(section);
    }
    let mut backed: Vec<Section> = sections.iter().filter(|s| s.size > 0).copied().collect();
    backed.sort_by_key(|s| s.offset);
    for index in 1..backed.len() {
        let previous = backed[index - 1];
        let current = backed[index];
        if current.offset < previous.offset + previous.size {
            return pe_failure("PE sections have overlapping raw file ranges.");
        }
    }
    let directory_at = optional + directories_at + 16;
    let rva = if directory_count > 2 { i64::from(u32_at(bytes, directory_at)?) } else { 0 };
    let size = if directory_count > 2 { i64::from(u32_at(bytes, directory_at + 4)?) } else { 0 };
    if (rva == 0) != (size == 0) {
        return pe_failure("Inconsistent PE resource directory RVA/size.");
    }
    Ok(Layout {
        format: if magic == 0x10b { "pe32" } else { "pe32-plus" },
        machine: u16_at(bytes, pe + 4)?,
        directory_at,
        rva,
        size,
        header_size,
        sections,
    })
}

impl Layout {
    fn map(&self, bytes: &[u8], rva: i64, size: i64) -> Result<i64, PeFailure> {
        if rva + size > 0x1_0000_0000 {
            return pe_failure("Resource RVA range overflows.");
        }
        let candidates: Vec<&Section> = self
            .sections
            .iter()
            .filter(|s| rva >= s.rva && rva - s.rva < s.size.max(s.virtual_size))
            .collect();
        if rva < self.header_size {
            if self
                .sections
                .iter()
                .any(|s| s.rva < rva + size && s.rva + s.size.max(s.virtual_size) > rva)
                || size > self.header_size - rva
            {
                return pe_failure("Ambiguous resource header RVA mapping.");
            }
            require_range(bytes, rva, size)?;
            return Ok(rva);
        }
        if candidates.len() != 1 {
            return pe_failure("Resource RVA has missing or overlapping section mappings.");
        }
        let section = candidates[0];
        let within = rva - section.rva;
        if within > section.size || size > section.size - within {
            return pe_failure("Resource range is not entirely file-backed in one section.");
        }
        if self.sections.iter().any(|other| {
            !std::ptr::eq(other, section)
                && other.rva < rva + size
                && other.rva + other.size.max(other.virtual_size) > rva
        }) {
            return pe_failure("Resource interval intersects overlapping virtual sections.");
        }
        let offset = section.offset + within;
        require_range(bytes, offset, size)?;
        Ok(offset)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Range {
    offset: i64,
    bytes: i64,
}

impl Range {
    fn to_value(&self) -> Value {
        json!({"offset": self.offset, "bytes": self.bytes})
    }
}

#[derive(Clone, Debug)]
enum Identity {
    Id(u32),
    Name {
        name: String,
        utf16le_hex: String,
        location: Range,
    },
}

impl Identity {
    fn key(&self) -> String {
        match self {
            Identity::Id(id) => format!("id:{id}"),
            Identity::Name { utf16le_hex, .. } => format!("name:{utf16le_hex}"),
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Identity::Id(id) => json!({"kind": "id", "id": id}),
            Identity::Name {
                name,
                utf16le_hex,
                location,
            } => json!({
                "kind": "name",
                "name": name,
                "utf16le_hex": utf16le_hex,
                "location": location.to_value(),
            }),
        }
    }

    fn id(&self) -> Option<u32> {
        match self {
            Identity::Id(id) => Some(*id),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum OccupiedKind {
    Directory,
    Name,
    DataEntry,
    Payload,
}

struct Occupied {
    offset: i64,
    bytes: i64,
    kind: OccupiedKind,
}

struct Resource {
    index: usize,
    r#type: Identity,
    name: Identity,
    language: Identity,
    entry_locations: Vec<Range>,
    data_entry_location: Range,
    code_page: u32,
    reserved: u32,
    payload_rva: u32,
    payload_location: Range,
    payload_sha256: String,
}

impl Resource {
    fn to_value(&self) -> Value {
        json!({
            "index": self.index,
            "type": self.r#type.to_value(),
            "name": self.name.to_value(),
            "language": self.language.to_value(),
            "entry_locations": self.entry_locations.iter().map(Range::to_value).collect::<Vec<_>>(),
            "data_entry_location": self.data_entry_location.to_value(),
            "code_page": self.code_page,
            "reserved": self.reserved,
            "payload": {
                "rva": self.payload_rva,
                "location": self.payload_location.to_value(),
                "sha256": self.payload_sha256,
            },
        })
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    layout: &'a Layout,
    root: i64,
    max_entries: i64,
    examined: i64,
    metadata_bytes: usize,
    directories: Vec<Value>,
    resources: Vec<Resource>,
    occupied: Vec<Occupied>,
    names: HashMap<u32, Identity>,
}

fn json_bytes(value: &Value, _maximum: usize) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}

impl Parser<'_> {
    fn ensure_capacity(&self, projected: usize) -> Result<(), PeFailure> {
        if self.metadata_bytes + projected > METADATA_BYTES {
            return limit("PE resource metadata exceeds the 8 MiB complete-result allocation budget.");
        }
        Ok(())
    }

    fn account_bytes(&mut self, projected: usize) -> Result<(), PeFailure> {
        self.ensure_capacity(projected)?;
        self.metadata_bytes += projected;
        Ok(())
    }

    fn account(&mut self, value: &Value) -> Result<(), PeFailure> {
        let remaining = METADATA_BYTES.saturating_sub(self.metadata_bytes).saturating_sub(1);
        let size = json_bytes(value, remaining);
        self.account_bytes(size + 1)
    }

    fn relative(&self, at: i64, length: i64) -> Result<i64, PeFailure> {
        if at > self.layout.size - length || at < 0 {
            return pe_failure("Resource directory offset leaves the declared resource interval.");
        }
        require_range(self.bytes, self.root + at, length)?;
        Ok(self.root + at)
    }

    fn record_range(&mut self, offset: i64, size: i64, kind: OccupiedKind) -> Range {
        if size > 0 {
            self.occupied.push(Occupied {
                offset,
                bytes: size,
                kind,
            });
        }
        Range { offset, bytes: size }
    }

    fn read_identity(&mut self, encoded: u32) -> Result<Identity, PeFailure> {
        if encoded & 0x8000_0000 == 0 {
            return Ok(Identity::Id(encoded));
        }
        let at = encoded & 0x7fff_ffff;
        if let Some(previous) = self.names.get(&at) {
            return Ok(previous.clone());
        }
        if !at.is_multiple_of(2) {
            return pe_failure("Unaligned PE resource name.");
        }
        let start = self.relative(i64::from(at), 2)?;
        let units = i64::from(u16_at(self.bytes, start)?);
        // A JSON string can need six ASCII bytes per UTF-16 code unit.
        self.ensure_capacity((10 * units + 256) as usize)?;
        let length = units * 2;
        self.relative(i64::from(at), 2 + length)?;
        let raw = &self.bytes[(start + 2) as usize..(start + 2 + length) as usize];
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let utf16: Vec<u16> = raw.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        let identity = Identity::Name {
            name: String::from_utf16_lossy(&utf16),
            utf16le_hex: hex::encode(raw),
            location: self.record_range(start, 2 + length, OccupiedKind::Name),
        };
        self.names.insert(at, identity.clone());
        Ok(identity)
    }

    fn visit(
        &mut self,
        at: i64,
        path: &[Identity],
        entry_locations: &[Range],
        ancestors: &HashSet<i64>,
    ) -> Result<(), PeFailure> {
        if ancestors.contains(&at) {
            return pe_failure("Cyclic PE resource directory.");
        }
        if at % 4 != 0 {
            return pe_failure("Unaligned PE resource directory.");
        }
        let header = self.relative(at, 16)?;
        let named = i64::from(u16_at(self.bytes, header + 12)?);
        let ids = i64::from(u16_at(self.bytes, header + 14)?);
        let count = named + ids;
        if count > self.max_entries - self.examined {
            return limit("PE resource directory entry budget exceeded; no partial inventory was returned.");
        }
        self.examined += count;
        self.relative(at, 16 + 8 * count)?;
        let location = self.record_range(header, 16 + 8 * count, OccupiedKind::Directory);
        let directory = json!({
            "location": location.to_value(),
            "characteristics": u32_at(self.bytes, header)?,
            "timestamp": u32_at(self.bytes, header + 4)?,
            "major_version": u16_at(self.bytes, header + 8)?,
            "minor_version": u16_at(self.bytes, header + 10)?,
            "named_entries": named,
            "id_entries": ids,
        });
        self.account(&directory)?;
        self.directories.push(directory);
        let mut keys: HashSet<String> = HashSet::new();
        let mut nested = ancestors.clone();
        nested.insert(at);
        for index in 0..count {
            let entry = header + 16 + index * 8;
            let encoded = u32_at(self.bytes, entry)?;
            if (encoded & 0x8000_0000 != 0) != (index < named) {
                return pe_failure("Resource name/ID entry counts disagree with encoded identities.");
            }
            let identity = self.read_identity(encoded)?;
            let key = identity.key();
            if !keys.insert(key) {
                return pe_failure("Duplicate identity within a resource directory.");
            }
            let mut next: Vec<Identity> = path.to_vec();
            next.push(identity);
            let mut locations: Vec<Range> = entry_locations.to_vec();
            locations.push(Range { offset: entry, bytes: 8 });
            let target = u32_at(self.bytes, entry + 4)?;
            let offset = i64::from(target & 0x7fff_ffff);
            if target & 0x8000_0000 != 0 {
                if next.len() >= 3 {
                    return pe_failure("Unsupported resource tree deeper than type/name/language.");
                }
                self.visit(offset, &next, &locations, &nested)?;
            } else {
                if next.len() != 3 {
                    return pe_failure("Unsupported resource leaf outside the type/name/language profile.");
                }
                let data = self.relative(offset, 16)?;
                if offset % 4 != 0 {
                    return pe_failure("Unaligned resource data entry.");
                }
                let rva = u32_at(self.bytes, data)?;
                let size = u32_at(self.bytes, data + 4)?;
                let payload_offset = self.layout.map(self.bytes, i64::from(rva), i64::from(size))?;
                let data_entry_location = self.record_range(data, 16, OccupiedKind::DataEntry);
                let payload_location = self.record_range(payload_offset, i64::from(size), OccupiedKind::Payload);
                let resource = Resource {
                    index: self.resources.len(),
                    r#type: next[0].clone(),
                    name: next[1].clone(),
                    language: next[2].clone(),
                    entry_locations: locations,
                    data_entry_location,
                    code_page: u32_at(self.bytes, data + 8)?,
                    reserved: u32_at(self.bytes, data + 12)?,
                    payload_rva: rva,
                    payload_location,
                    payload_sha256: "0".repeat(64),
                };
                self.account(&resource.to_value())?;
                self.resources.push(resource);
            }
        }
        Ok(())
    }
}

fn reject_overlapping_ranges(ranges: &mut [Occupied]) -> Result<(), PeFailure> {
    ranges.sort_by(|left, right| left.offset.cmp(&right.offset).then(right.bytes.cmp(&left.bytes)));
    let mut previous: Option<&Occupied> = None;
    for current in ranges.iter() {
        if let Some(previous) = previous {
            if current.offset < previous.offset + previous.bytes
                && (current.offset != previous.offset || current.bytes != previous.bytes || current.kind != previous.kind)
            {
                return pe_failure("Non-identical resource byte ranges overlap.");
            }
        }
        previous = Some(current);
    }
    Ok(())
}

fn read_icon_groups(
    parser: &mut Parser<'_>,
) -> Result<Vec<Value>, PeFailure> {
    let bytes = parser.bytes;
    let mut images_by_id: HashMap<u32, Vec<usize>> = HashMap::new();
    for (position, resource) in parser.resources.iter().enumerate() {
        if resource.r#type.id() != Some(3) {
            continue;
        }
        let Some(name) = resource.name.id() else { continue };
        images_by_id.entry(name).or_default().push(position);
    }
    let groups: Vec<usize> = parser
        .resources
        .iter()
        .enumerate()
        .filter(|(_, r)| r.r#type.id() == Some(14))
        .map(|(i, _)| i)
        .collect();
    let mut output = Vec::new();
    for group_position in groups {
        let (offset, size, language_key, group_index) = {
            let group = &parser.resources[group_position];
            (
                group.payload_location.offset,
                group.payload_location.bytes,
                group.language.key(),
                group.index,
            )
        };
        if size < 6 || u16_at(bytes, offset)? != 0 || u16_at(bytes, offset + 2)? != 1 {
            return pe_failure("Malformed RT_GROUP_ICON header.");
        }
        let count = i64::from(u16_at(bytes, offset + 4)?);
        if size != 6 + count * 14 {
            return pe_failure("RT_GROUP_ICON length does not match its image count.");
        }
        let mut images: Vec<Value> = Vec::new();
        for index in 0..count {
            let at = offset + 6 + index * 14;
            let id = u32::from(u16_at(bytes, at + 12)?);
            let candidates: Vec<usize> = images_by_id.get(&id).cloned().unwrap_or_default();
            let exact = candidates
                .iter()
                .find(|c| parser.resources[**c].language.key() == language_key)
                .copied();
            parser.ensure_capacity(302 + candidates.len() * 11)?;
            let declared_bytes = u32_at(bytes, at + 8)?;
            let image = json!({
                "location": {"offset": at, "bytes": 14},
                "width": bytes[at as usize],
                "height": bytes[at as usize + 1],
                "color_count": bytes[at as usize + 2],
                "reserved": bytes[at as usize + 3],
                "planes": u16_at(bytes, at + 4)?,
                "bit_count": u16_at(bytes, at + 6)?,
                "declared_bytes": declared_bytes,
                "resource_id": id,
                "candidate_resource_indices": candidates.iter().map(|c| parser.resources[*c].index).collect::<Vec<_>>(),
                "same_language_resource_index": exact.map(|c| parser.resources[c].index),
                "size_matches": exact.map(|c| parser.resources[c].payload_location.bytes == i64::from(declared_bytes)),
            });
            parser.account(&image)?;
            images.push(image);
        }
        parser.account(&json!({"resource_index": group_index, "images": []}))?;
        output.push(json!({"resource_index": group_index, "images": images}));
    }
    Ok(output)
}

/// Decode the conventional type/name/language tree; never infer payload meaning or runtime loading.
pub fn parse_pe_resources(
    bytes: &[u8],
    artifact: (&str, &str, usize),
    max_entries: i64,
) -> Result<Value, PeFailure> {
    let layout = read_layout(bytes)?;
    let root = if layout.size == 0 {
        0
    } else {
        layout.map(bytes, layout.rva, layout.size)?
    };
    let mut parser = Parser {
        bytes,
        layout: &layout,
        root,
        max_entries,
        examined: 0,
        metadata_bytes: 0,
        directories: Vec::new(),
        resources: Vec::new(),
        occupied: Vec::new(),
        names: HashMap::new(),
    };
    if layout.size > 0 {
        parser.visit(0, &[], &[], &HashSet::new())?;
    }
    let mut occupied = std::mem::take(&mut parser.occupied);
    reject_overlapping_ranges(&mut occupied)?;
    let mut hashes: HashMap<(i64, i64), String> = HashMap::new();
    for resource in &mut parser.resources {
        let range = (resource.payload_location.offset, resource.payload_location.bytes);
        let digest = hashes
            .entry(range)
            .or_insert_with(|| {
                hex::encode(Sha256::digest(&bytes[range.0 as usize..(range.0 + range.1) as usize]))
            })
            .clone();
        resource.payload_sha256 = digest;
    }
    let icon_groups = read_icon_groups(&mut parser)?;
    let resources: Vec<Value> = parser.resources.iter().map(Resource::to_value).collect();
    let report = json!({
        "artifact": {"path": artifact.0, "sha256": artifact.1, "bytes": artifact.2},
        "format": layout.format,
        "machine": layout.machine,
        "directory": if layout.size == 0 { Value::Null } else { json!({
            "rva": layout.rva,
            "location": {"offset": root, "bytes": layout.size},
            "data_directory_location": {"offset": layout.directory_at, "bytes": 8},
        }) },
        "directories": parser.directories,
        "resources": resources,
        "icon_groups": icon_groups,
        "coverage": {
            "status": "complete",
            "examined_entries": parser.examined,
            "resources": parser.resources.len(),
        },
        "limitations": [
            "Static PE32/PE32+ type/name/language resource inventory; payloads other than RT_GROUP_ICON remain opaque.",
            "Icon candidates are resource-table relationships. Language fallback, image decoding and actual shell/window loading are not observed.",
            "Exact shared byte ranges are retained; non-identical overlapping resource structures or payloads are rejected.",
        ],
    });
    if json_bytes(&report, METADATA_BYTES) > METADATA_BYTES {
        return limit("PE resource result exceeds the 8 MiB allocation budget.");
    }
    Ok(report)
}

fn artifact_failure(operation: &str, reason: ArtifactReason, message: String) -> NativeError {
    NativeError::Artifact {
        operation: operation.to_string(),
        reason,
        detail: Some(message),
    }
}

/// Read one bounded regular file and reject replacement or in-place changes.
pub fn read_stable_artifact(
    path: &Path,
    maximum_bytes: u64,
    operation: &str,
) -> NativeResult<(Vec<u8>, String)> {
    use std::io::Read;
    let display = path.to_string_lossy().into_owned();
    let before = std::fs::symlink_metadata(path).map_err(|e| io_error(operation, &e, "lstat", &display))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(artifact_failure(
            operation,
            ArtifactReason::Path,
            format!("Expected a regular file without a symlink: {display}"),
        ));
    }
    if before.len() > maximum_bytes {
        return Err(artifact_failure(
            operation,
            ArtifactReason::Limit,
            format!("Selected artifact exceeds {maximum_bytes} bytes: {display}"),
        ));
    }
    let mut file = crate::dylib::open_nofollow(path).map_err(|e| {
        if matches!(e.raw_os_error(), Some(2) | Some(20) | Some(40)) {
            artifact_failure(
                operation,
                ArtifactReason::Integrity,
                format!("Artifact changed before open: {display}"),
            )
        } else {
            io_error(operation, &e, "open", &display)
        }
    })?;
    let initial = file.metadata().map_err(|e| io_error(operation, &e, "fstat", &display))?;
    if !initial.is_file() || initial.dev() != before.dev() || initial.ino() != before.ino() {
        return Err(artifact_failure(
            operation,
            ArtifactReason::Integrity,
            format!("Artifact changed before open: {display}"),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(operation, &e, "read", &display))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(artifact_failure(
            operation,
            ArtifactReason::Limit,
            format!("Selected artifact grew beyond its byte limit: {display}"),
        ));
    }
    let after = file.metadata().map_err(|e| io_error(operation, &e, "fstat", &display))?;
    let current = std::fs::symlink_metadata(path).map_err(|e| io_error(operation, &e, "lstat", &display))?;
    let changed = |stat: &std::fs::Metadata| {
        !stat.is_file()
            || stat.dev() != initial.dev()
            || stat.ino() != initial.ino()
            || stat.size() != initial.size()
            || stat.mtime() != initial.mtime()
            || stat.mtime_nsec() != initial.mtime_nsec()
            || stat.ctime() != initial.ctime()
            || stat.ctime_nsec() != initial.ctime_nsec()
    };
    if changed(&after) || changed(&current) || bytes.len() as u64 != initial.size() {
        return Err(artifact_failure(
            operation,
            ArtifactReason::Integrity,
            format!("Artifact changed during read: {display}"),
        ));
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok((bytes, sha256))
}

/// Node-shaped message for a filesystem failure (`ENOENT: no such file or directory, lstat '<path>'`).
pub fn io_error(operation: &str, error: &std::io::Error, syscall: &str, path: &str) -> NativeError {
    let (code, text) = match error.raw_os_error() {
        Some(2) => ("ENOENT", "no such file or directory"),
        Some(13) => ("EACCES", "permission denied"),
        Some(1) => ("EPERM", "operation not permitted"),
        Some(20) => ("ENOTDIR", "not a directory"),
        Some(21) => ("EISDIR", "illegal operation on a directory"),
        Some(40) => ("ELOOP", "too many symbolic links encountered"),
        _ => ("EIO", "i/o error"),
    };
    if code == "EACCES" || code == "EPERM" {
        return NativeError::AccessDenied {
            operation: operation.to_string(),
            path: path.to_string(),
            system_code: code.to_string(),
        };
    }
    artifact_failure(operation, ArtifactReason::Io, format!("{code}: {text}, {syscall} '{path}'"))
}

pub struct PeRequest<'a> {
    pub path: &'a str,
    pub max_file_bytes: u64,
    pub max_entries: i64,
}

/// Complete `normalized_result` plus the artifact digest for Evidence construction.
pub fn inspect_pe_resources(request: &PeRequest<'_>) -> NativeResult<(Value, String)> {
    let reported_limits = json!({
        "max_file_bytes": request.max_file_bytes,
        "max_entries": request.max_entries,
    });
    let (bytes, sha256) = match read_stable_artifact(Path::new(request.path), request.max_file_bytes, OPERATION) {
        Ok(read) => read,
        Err(NativeError::Artifact {
            reason: ArtifactReason::Limit,
            detail: Some(message),
            ..
        }) => {
            return Err(NativeError::Resource {
                operation: OPERATION.to_string(),
                resource: "memory".to_string(),
                reason: message,
                reported_limits,
            })
        }
        Err(other) => return Err(other),
    };
    match parse_pe_resources(&bytes, (request.path, &sha256, bytes.len()), request.max_entries) {
        Ok(report) => Ok((report, sha256)),
        Err(PeFailure::Format(message)) => Err(artifact_failure(OPERATION, ArtifactReason::Format, message)),
        Err(PeFailure::Limit(message)) => Err(NativeError::Resource {
            operation: OPERATION.to_string(),
            resource: "memory".to_string(),
            reason: message,
            reported_limits,
        }),
    }
}
