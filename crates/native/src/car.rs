//! Compiled Apple asset catalogs (`Assets.car`): a BOM container holding CoreUI structures.
//!
//! The container and structure layouts follow the community reverse engineering of the format
//! (BOM store, `CARHEADER`, `KEYFORMAT`, `FACETKEYS`, `RENDITIONS`, CSI renditions), notably
//! the MIT-licensed `skytoup/car-parser` and `bartoszj/acextract` projects. Only metadata is
//! decoded; image payloads are not decompressed.
//!
//! Records use the field names of Apple's `assetutil --info`, but only the subset below is
//! produced; see [`CATALOG_LIMITATION`].

use std::collections::HashMap;

use serde_json::{json, Map, Value};

pub const CATALOG_LIMITATION: &str = "Records come from tracewise's native CoreUI catalog reader, not from Apple's assetutil. They use assetutil's field names for the subset the reader decodes (header, name, identifier, rendition name, scale, idiom, appearance, pixel size, encoding, color model, color components, compression, opacity, UTI, layout and on-disk size); SHA1Digest, template, slice and other private fields are not produced.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarError(pub String);

impl std::fmt::Display for CarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type CarResult<T> = Result<T, CarError>;

fn fail<T>(message: impl Into<String>) -> CarResult<T> {
    Err(CarError(message.into()))
}

// ---------------------------------------------------------------------------
// BOM store
// ---------------------------------------------------------------------------

struct Bom<'a> {
    data: &'a [u8],
    /// (offset, length) of each block.
    blocks: Vec<(usize, usize)>,
    vars: Vec<(String, u32)>,
}

fn be32(data: &[u8], at: usize) -> CarResult<u32> {
    data.get(at..at + 4)
        .map(|raw| u32::from_be_bytes(raw.try_into().unwrap()))
        .ok_or_else(|| CarError(format!("BOM read at {at} passes the end of the file")))
}

fn be16(data: &[u8], at: usize) -> CarResult<u16> {
    data.get(at..at + 2)
        .map(|raw| u16::from_be_bytes(raw.try_into().unwrap()))
        .ok_or_else(|| CarError(format!("BOM read at {at} passes the end of the file")))
}

fn le32(data: &[u8], at: usize) -> CarResult<u32> {
    data.get(at..at + 4)
        .map(|raw| u32::from_le_bytes(raw.try_into().unwrap()))
        .ok_or_else(|| CarError(format!("read at {at} passes the end of a block of {} bytes", data.len())))
}

fn le16(data: &[u8], at: usize) -> CarResult<u16> {
    data.get(at..at + 2)
        .map(|raw| u16::from_le_bytes(raw.try_into().unwrap()))
        .ok_or_else(|| CarError(format!("read at {at} passes the end of a block of {} bytes", data.len())))
}

const MAX_BLOCKS: usize = 4_000_000;

impl<'a> Bom<'a> {
    fn parse(data: &'a [u8]) -> CarResult<Self> {
        if data.get(..8) != Some(b"BOMStore") {
            return fail("not a BOM store (missing BOMStore magic)");
        }
        let index_offset = be32(data, 16)? as usize;
        let var_offset = be32(data, 24)? as usize;
        let count = be32(data, index_offset)? as usize;
        if count > MAX_BLOCKS || index_offset.saturating_add(4 + count * 8) > data.len() {
            return fail("BOM block table passes the end of the file");
        }
        let mut blocks = Vec::with_capacity(count);
        for index in 0..count {
            let at = index_offset + 4 + index * 8;
            blocks.push((be32(data, at)? as usize, be32(data, at + 4)? as usize));
        }
        let var_count = be32(data, var_offset)? as usize;
        if var_count > 65_536 {
            return fail("BOM variable table is implausibly large");
        }
        let mut vars = Vec::new();
        let mut cursor = var_offset + 4;
        for _ in 0..var_count {
            let block = be32(data, cursor)?;
            let length = *data.get(cursor + 4).ok_or_else(|| CarError("BOM variable passes the end".into()))? as usize;
            let name = data
                .get(cursor + 5..cursor + 5 + length)
                .ok_or_else(|| CarError("BOM variable name passes the end".into()))?;
            vars.push((String::from_utf8_lossy(name).into_owned(), block));
            cursor += 5 + length;
        }
        Ok(Self { data, blocks, vars })
    }

    fn block(&self, index: u32) -> CarResult<&'a [u8]> {
        let (offset, length) = *self
            .blocks
            .get(index as usize)
            .ok_or_else(|| CarError(format!("BOM block {index} does not exist")))?;
        self.data
            .get(offset..offset.saturating_add(length))
            .ok_or_else(|| CarError(format!("BOM block {index} passes the end of the file")))
    }

    fn named_block(&self, name: &str) -> CarResult<&'a [u8]> {
        let (_, index) = self
            .vars
            .iter()
            .find(|(candidate, _)| candidate == name)
            .ok_or_else(|| CarError(format!("BOM variable {name} is missing")))?;
        self.block(*index)
    }

    fn has(&self, name: &str) -> bool {
        self.vars.iter().any(|(candidate, _)| candidate == name)
    }

    /// Key/value blocks of a named tree, in storage order.
    fn tree(&self, name: &str) -> CarResult<Vec<(&'a [u8], &'a [u8])>> {
        let header = self.named_block(name)?;
        if header.get(..4) != Some(b"tree") {
            return fail(format!("BOM variable {name} is not a tree"));
        }
        let mut node = be32(header, 8)?;
        let mut out = Vec::new();
        let mut guard = 0usize;
        // Descend through interior nodes to the first leaf, then follow the leaf chain.
        loop {
            guard += 1;
            if guard > 1_000_000 {
                return fail("BOM tree is cyclic or too deep");
            }
            let paths = self.block(node)?;
            let is_leaf = be16(paths, 0)?;
            let count = be16(paths, 2)? as usize;
            if is_leaf == 0 {
                if count == 0 {
                    return Ok(out);
                }
                node = be32(paths, 12)?;
                continue;
            }
            for i in 0..count {
                let value = be32(paths, 12 + i * 8)?;
                let key = be32(paths, 16 + i * 8)?;
                out.push((self.block(key)?, self.block(value)?));
            }
            let forward = be32(paths, 4)?;
            if forward == 0 {
                return Ok(out);
            }
            node = forward;
        }
    }
}

// ---------------------------------------------------------------------------
// CoreUI structures
// ---------------------------------------------------------------------------

fn c_string(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// `kCRTheme*Name` of a `KEYFORMAT` attribute id.
pub fn attribute_name(id: u16) -> String {
    let name = match id {
        0 => "Look",
        1 => "Element",
        2 => "Part",
        3 => "Size",
        4 => "Direction",
        5 => "Placeholder",
        6 => "Value",
        7 => "Appearance",
        8 => "Dimension1",
        9 => "Dimension2",
        10 => "State",
        11 => "Layer",
        12 => "Scale",
        13 => "Localization",
        14 => "PresentationState",
        15 => "Idiom",
        16 => "Subtype",
        17 => "Identifier",
        18 => "PreviousValue",
        19 => "PreviousState",
        20 => "SizeClassHorizontal",
        21 => "SizeClassVertical",
        22 => "MemoryClass",
        23 => "GraphicsClass",
        24 => "DisplayGamut",
        25 => "DeploymentTarget",
        26 => "GlyphWeight",
        27 => "GlyphSize",
        other => return format!("kCRThemeAttribute{other}Name"),
    };
    format!("kCRTheme{name}Name")
}

fn idiom_name(value: u16) -> &'static str {
    match value {
        0 => "universal",
        1 => "iphone",
        2 => "ipad",
        3 => "tv",
        4 => "car",
        5 => "watch",
        6 => "marketing",
        _ => "unknown",
    }
}

fn color_space_name(id: u32) -> String {
    match id {
        1 => "srgb".to_string(),
        2 => "gray gamma 22".to_string(),
        3 => "display p3".to_string(),
        4 => "extended range srgb".to_string(),
        5 => "extended linear srgb".to_string(),
        6 => "extended gray".to_string(),
        257 => "system srgb".to_string(),
        other => format!("unknown ({other})"),
    }
}

fn compression_name(id: u32) -> String {
    match id {
        0 => "uncompressed",
        1 => "rle",
        2 => "zip",
        3 => "lzvn",
        4 => "lzfse",
        5 => "jpeg-lzfse",
        6 => "blurred",
        7 => "astc",
        8 => "palette-img",
        9 => "hevc",
        10 => "deepmap-lzfse",
        11 => "deepmap2",
        other => return format!("unknown ({other})"),
    }
    .to_string()
}

fn layout_asset_type(layout: u16) -> &'static str {
    match layout {
        6 => "Gradient",
        7 => "Effect",
        9 => "Vector",
        10..=12 | 20..=25 | 30..=34 | 40 | 50 => "Image",
        1000 => "Data",
        1001 => "External Link",
        1002 => "Layer Stack",
        1003 => "Internal Link",
        1004 => "PackedImage",
        1005 => "Name List",
        1007 => "Texture",
        1008 => "Texture Image",
        1009 => "Color",
        1010 => "MultiSized Image",
        1012 => "Layer Reference",
        1013 => "Content Rendition",
        1014 => "Recognition Object",
        _ => "Unknown",
    }
}

/// Pixel format four-character code, as stored (little-endian) in the CSI header.
fn encoding_name(raw: [u8; 4]) -> Option<String> {
    if raw == [0, 0, 0, 0] {
        return None;
    }
    let mut reversed = raw;
    reversed.reverse();
    Some(String::from_utf8_lossy(&reversed).trim_end().to_string())
}

fn bits_per_component(encoding: &str) -> Option<u32> {
    match encoding {
        "ARGB" | "GA8" | "RGB5" => Some(8),
        "GA16" | "RGBW" => Some(16),
        _ => None,
    }
}

struct Csi {
    flags: u32,
    width: u32,
    height: u32,
    scale_factor: u32,
    pixel_format: [u8; 4],
    color_model: u32,
    layout: u16,
    name: String,
    uti: Option<String>,
    rendition_tag: Option<[u8; 4]>,
    color: Option<(u32, Vec<f64>)>,
    compression: Option<u32>,
    raw_data_length: Option<u32>,
    size_on_disk: usize,
}

fn parse_csi(block: &[u8]) -> CarResult<Csi> {
    if block.get(..4) != Some(b"ISTC") {
        return fail("rendition block is not a CSI (missing ISTC magic)");
    }
    let flags = le32(block, 8)?;
    let width = le32(block, 12)?;
    let height = le32(block, 16)?;
    let scale_factor = le32(block, 20)?;
    let pixel_format: [u8; 4] = block.get(24..28).ok_or_else(|| CarError("CSI header is truncated".into()))?.try_into().unwrap();
    let color_model = le32(block, 28)?;
    // modification time at 32, layout u32 at 36, name[128] at 40.
    let layout = le32(block, 36)? as u16;
    let name = c_string(block.get(40..168).ok_or_else(|| CarError("CSI name is truncated".into()))?);
    let tlv_length = le32(block, 168)? as usize;
    // bitmap count at 172, zero at 176, rendition length at 180.
    let rendition_length = le32(block, 180)? as usize;
    let tlv_start = 184usize;
    let tlv_end = tlv_start.checked_add(tlv_length).ok_or_else(|| CarError("CSI TLV length overflows".into()))?;
    let tlv = block.get(tlv_start..tlv_end).ok_or_else(|| CarError("CSI TLV block passes the end".into()))?;
    let mut uti = None;
    let mut cursor = 0usize;
    while cursor + 8 <= tlv.len() {
        let tag = le32(tlv, cursor)?;
        let length = le32(tlv, cursor + 4)? as usize;
        let body = tlv.get(cursor + 8..cursor + 8 + length).unwrap_or(&[]);
        if tag == 1005 && body.len() >= 8 {
            let string_length = le32(body, 0).unwrap_or(0) as usize;
            if let Some(raw) = body.get(8..8 + string_length) {
                uti = Some(c_string(raw));
            }
        }
        cursor += 8 + length;
    }
    let payload_start = tlv_end;
    let payload_end = payload_start.saturating_add(rendition_length).min(block.len());
    let payload = block.get(payload_start..payload_end).unwrap_or(&[]);
    let mut rendition_tag = None;
    let mut color = None;
    let mut compression = None;
    let mut raw_data_length = None;
    if payload.len() >= 4 {
        let tag: [u8; 4] = payload[..4].try_into().unwrap();
        rendition_tag = Some(tag);
        match &tag {
            b"RLOC" if payload.len() >= 16 => {
                let space = le32(payload, 8)?;
                let count = le32(payload, 12)? as usize;
                let mut components = Vec::new();
                for i in 0..count.min(16) {
                    if let Some(raw) = payload.get(16 + i * 8..24 + i * 8) {
                        components.push(f64::from_le_bytes(raw.try_into().unwrap()));
                    }
                }
                color = Some((space, components));
            }
            b"MLEC" if payload.len() >= 16 => {
                compression = Some(le32(payload, 8)?);
            }
            b"DWAR" if payload.len() >= 12 => {
                raw_data_length = Some(le32(payload, 8)?);
            }
            _ => {}
        }
    }
    Ok(Csi {
        flags,
        width,
        height,
        scale_factor,
        pixel_format,
        color_model,
        layout,
        name,
        uti,
        rendition_tag,
        color,
        compression,
        raw_data_length,
        size_on_disk: block.len(),
    })
}

/// Records of one catalog: the header record followed by one record per rendition.
pub fn read_catalog(data: &[u8]) -> Result<Vec<Value>, CarError> {
    let bom = Bom::parse(data)?;
    // --- CARHEADER
    let header = bom.named_block("CARHEADER")?;
    if header.get(..4) != Some(b"RATC") {
        return fail("CARHEADER block is not a CoreUI header (missing RATC magic)");
    }
    let coreui_version = le32(header, 4)?;
    let storage_version = le32(header, 8)?;
    let storage_timestamp = le32(header, 12)?;
    let main_version = c_string(header.get(20..148).ok_or_else(|| CarError("CARHEADER is truncated".into()))?);
    let version_string = c_string(header.get(148..404).ok_or_else(|| CarError("CARHEADER is truncated".into()))?);
    let schema_version = header.get(424..428).map(|_| le32(header, 424)).transpose()?;
    // --- KEYFORMAT
    let key_format_block = bom.named_block("KEYFORMAT")?;
    if key_format_block.get(..4) != Some(b"tmfk") {
        return fail("KEYFORMAT block is not a key format (missing tmfk magic)");
    }
    let key_count = le32(key_format_block, 8)? as usize;
    if key_count > 64 {
        return fail("KEYFORMAT declares implausibly many attributes");
    }
    let mut attribute_ids: Vec<u16> = Vec::new();
    for i in 0..key_count {
        attribute_ids.push(le16(key_format_block, 12 + i * 4)?);
    }
    // --- EXTENDED_METADATA
    let (authoring_tool, deployment_platform, deployment_platform_version) = match bom.named_block("EXTENDED_METADATA") {
        Ok(block) if block.get(..4) == Some(b"META") && block.len() >= 4 + 1024 => (
            Some(c_string(&block[4 + 768..4 + 1024])),
            Some(c_string(&block[4 + 512..4 + 768])),
            Some(c_string(&block[4 + 256..4 + 512])),
        ),
        _ => (None, None, None),
    };
    let mut header_record = Map::new();
    header_record.insert("AssetStorageVersion".into(), json!(version_string));
    if let Some(tool) = authoring_tool.filter(|t| !t.is_empty()) {
        header_record.insert("Authoring Tool".into(), json!(tool));
    }
    header_record.insert("CoreUIVersion".into(), json!(coreui_version));
    header_record.insert(
        "Key Format".into(),
        Value::Array(attribute_ids.iter().map(|id| json!(attribute_name(*id))).collect()),
    );
    header_record.insert("MainVersion".into(), json!(main_version));
    if let Some(platform) = deployment_platform.filter(|p| !p.is_empty()) {
        header_record.insert("Platform".into(), json!(platform));
    }
    if let Some(version) = deployment_platform_version.filter(|p| !p.is_empty()) {
        header_record.insert("PlatformVersion".into(), json!(version));
    }
    if let Some(schema) = schema_version {
        header_record.insert("SchemaVersion".into(), json!(schema));
    }
    header_record.insert("StorageVersion".into(), json!(storage_version));
    header_record.insert("Timestamp".into(), json!(storage_timestamp));
    let mut records = vec![Value::Object(header_record)];

    // --- facet names by identifier
    let identifier_position = attribute_ids.iter().position(|id| *id == 17);
    let mut names: HashMap<u16, String> = HashMap::new();
    if bom.has("FACETKEYS") {
        for (key, value) in bom.tree("FACETKEYS")? {
            let name = c_string(key);
            let count = le16(value, 4)? as usize;
            for i in 0..count.min(64) {
                let attribute = le16(value, 6 + i * 4)?;
                let attribute_value = le16(value, 8 + i * 4)?;
                if attribute == 17 {
                    names.entry(attribute_value).or_insert_with(|| name.clone());
                }
            }
        }
    }
    // --- appearance names
    let mut appearances: HashMap<u16, String> = HashMap::new();
    if bom.has("APPEARANCEKEYS") {
        for (key, value) in bom.tree("APPEARANCEKEYS")? {
            if let Ok(id) = le16(value, 0) {
                appearances.insert(id, c_string(key));
            }
        }
    }
    // --- renditions
    for (key, value) in bom.tree("RENDITIONS")? {
        let values: Vec<u16> = (0..attribute_ids.len()).map(|i| le16(key, i * 2)).collect::<CarResult<_>>()?;
        let csi = parse_csi(value)?;
        let by_attribute = |wanted: u16| attribute_ids.iter().position(|id| *id == wanted).map(|i| values[i]);
        let mut record = Map::new();
        record.insert("AssetType".into(), json!(layout_asset_type(csi.layout)));
        if let Some(position) = identifier_position {
            let identifier = values[position];
            if let Some(name) = names.get(&identifier) {
                record.insert("Name".into(), json!(name));
            }
            record.insert("NameIdentifier".into(), json!(identifier));
        }
        if !csi.name.is_empty() {
            record.insert("RenditionName".into(), json!(csi.name));
        }
        if let Some(scale) = by_attribute(12) {
            record.insert("Scale".into(), json!(scale));
        }
        if let Some(idiom) = by_attribute(15) {
            record.insert("Idiom".into(), json!(idiom_name(idiom)));
        }
        if let Some(appearance) = by_attribute(7).filter(|a| *a != 0) {
            if let Some(name) = appearances.get(&appearance) {
                record.insert("Appearance".into(), json!(name));
            }
        }
        match (csi.rendition_tag.as_ref(), &csi.color) {
            (Some(b"RLOC"), Some((space, components))) => {
                record.insert("Color components".into(), json!(components));
                record.insert("Colorspace".into(), json!(color_space_name(*space)));
            }
            _ => {
                let is_image = matches!(csi.layout, 10..=12 | 20..=25 | 30..=34 | 40 | 50 | 1004 | 1010 | 9);
                if is_image {
                    record.insert("PixelWidth".into(), json!(csi.width));
                    record.insert("PixelHeight".into(), json!(csi.height));
                    if let Some(encoding) = encoding_name(csi.pixel_format) {
                        if let Some(bits) = bits_per_component(&encoding) {
                            record.insert("BitsPerComponent".into(), json!(bits));
                        }
                        record.insert("Encoding".into(), json!(encoding));
                    }
                    match csi.color_model {
                        1 => {
                            record.insert("ColorModel".into(), json!("RGB"));
                        }
                        2 => {
                            record.insert("ColorModel".into(), json!("Monochrome"));
                        }
                        _ => {}
                    }
                    record.insert("Opaque".into(), json!(csi.flags & 0b1000 != 0));
                }
                if let Some(compression) = csi.compression {
                    record.insert("Compression".into(), json!(compression_name(compression)));
                }
                if let Some(length) = csi.raw_data_length {
                    record.insert("Data Length".into(), json!(length));
                }
                if let Some(uti) = &csi.uti {
                    record.insert("UTI".into(), json!(uti));
                }
            }
        }
        let _ = csi.scale_factor;
        record.insert("Layout".into(), json!(csi.layout));
        record.insert("SizeOnDisk".into(), json!(csi.size_on_disk));
        records.push(Value::Object(record));
    }
    Ok(records)
}
