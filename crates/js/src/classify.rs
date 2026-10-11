use crate::hash::ARTIFACT_CLASSIFICATION_PREFIX_BYTES;

pub fn has_zip_signature(prefix: &[u8]) -> bool {
    prefix.len() >= 4
        && prefix[0] == 0x50
        && prefix[1] == 0x4b
        && ((prefix[2] == 0x03 && prefix[3] == 0x04)
            || (prefix[2] == 0x05 && prefix[3] == 0x06)
            || (prefix[2] == 0x07 && prefix[3] == 0x08))
}

pub fn zip_package_format_for_path(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with(".zip") {
        return Some("zip");
    }
    if lower.ends_with(".ipa") {
        return Some("ipa");
    }
    if lower.ends_with(".apk") {
        return Some("apk");
    }
    if lower.ends_with(".msix") || lower.ends_with(".msixbundle") {
        return Some("msix");
    }
    if lower.ends_with(".appx") || lower.ends_with(".appxbundle") {
        return Some("appx");
    }
    None
}

pub fn has_asar_header(prefix: &[u8]) -> bool {
    if prefix.len() < 17 {
        return false;
    }
    let first = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    if first != 4 {
        return false;
    }
    let header_size = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    let payload_size = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
    if header_size < 16 || payload_size != header_size - 4 {
        return false;
    }
    let string_length = u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
    string_length >= 2 && string_length <= payload_size - 4 && prefix[16] == 0x7b
}

pub fn classify_artifact_bytes(prefix: &[u8], file_size: u64) -> String {
    if has_zip_signature(prefix) {
        return "zip".to_string();
    }
    if prefix.len() >= 8 && prefix[..8] == *b"bplist00" {
        return "plist".to_string();
    }
    if prefix.len() >= 4 {
        let magic = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
        if [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].contains(&magic) {
            return "mach-o-universal".to_string();
        }
        if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].contains(&magic) {
            return "mach-o".to_string();
        }
        if prefix[..4] == [0x7f, 0x45, 0x4c, 0x46] {
            return "elf".to_string();
        }
    }
    if prefix.len() >= 2 && prefix[0] == 0x4d && prefix[1] == 0x5a {
        if file_size >= prefix.len() as u64 && prefix.len() >= 64 {
            if prefix.len() >= 64 {
                let windows_offset = u32::from_le_bytes([
                    prefix[0x3c],
                    prefix[0x3d],
                    prefix[0x3e],
                    prefix[0x3f],
                ]) as usize;
                if windows_offset >= 64
                    && windows_offset + 4 <= prefix.len()
                    && prefix[windows_offset..windows_offset + 4] == [0x50, 0x45, 0, 0]
                {
                    return "pe".to_string();
                }
            }
        }
        return "unknown".to_string();
    }
    "file".to_string()
}

pub fn classify_artifact_path(path: &str) -> (String, String) {
    let lower = path.to_lowercase();
    if lower.ends_with(".map") {
        return ("source-map".to_string(), "source-map".to_string());
    }
    if lower.ends_with(".mjs")
        || lower.ends_with(".js")
        || lower.ends_with(".cjs")
    {
        return ("javascript".to_string(), "javascript-bundle".to_string());
    }
    if lower.contains(".framework/") || lower.ends_with(".framework") {
        return ("framework".to_string(), "file".to_string());
    }
    if lower.ends_with(".node") {
        return ("native-addon".to_string(), "file".to_string());
    }
    if lower.ends_with(".dylib") || lower.ends_with(".so") {
        return ("dynamic-library".to_string(), "file".to_string());
    }
    if lower.ends_with(".plist") {
        return ("plist".to_string(), "plist".to_string());
    }
    if lower.ends_with(".entitlements") {
        return ("entitlements".to_string(), "entitlements".to_string());
    }
    ("resource".to_string(), "file".to_string())
}

fn artifact_role_for_format(path: &str, format: &str) -> (String, String) {
    let by_path = classify_artifact_path(path);
    if format == "file" || format == by_path.1 {
        return by_path;
    }
    if format == "unknown" {
        return ("unknown".to_string(), "unknown".to_string());
    }
    if format == "zip" {
        return (
            "container".to_string(),
            zip_package_format_for_path(path)
                .unwrap_or("zip")
                .to_string(),
        );
    }
    if format == "plist" {
        return ("plist".to_string(), "plist".to_string());
    }
    if by_path.0 == "native-addon" || by_path.0 == "dynamic-library" {
        return by_path;
    }
    ("executable".to_string(), format.to_string())
}

pub fn classify_artifact_content(path: &str, prefix: &[u8], file_size: u64) -> (String, String) {
    let format = classify_artifact_bytes(prefix, file_size);
    if format == "file" && path.to_lowercase().ends_with(".asar") && has_asar_header(prefix) {
        return ("container".to_string(), "asar".to_string());
    }
    artifact_role_for_format(path, &format)
}

pub fn classify_root_format(path: &str, prefix: &[u8], is_directory: bool) -> String {
    if is_directory {
        return "directory".to_string();
    }
    let lower = path.to_lowercase();
    if has_zip_signature(prefix) {
        return zip_package_format_for_path(&lower).unwrap_or("zip").to_string();
    }
    if lower.ends_with(".asar") || has_asar_header(prefix) {
        return "asar".to_string();
    }
    classify_artifact_content(path, prefix, prefix.len() as u64).1
}

pub fn read_classification_prefix(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; ARTIFACT_CLASSIFICATION_PREFIX_BYTES];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
