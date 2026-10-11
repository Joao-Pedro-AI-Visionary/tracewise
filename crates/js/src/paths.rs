use crate::error::JsError;
use crate::identity::logical_path_nfc;

pub fn normalize_artifact_path(input: &str) -> Result<String, JsError> {
    if input.contains('\0') || input.contains('\\') || input.starts_with('/') {
        return Err(JsError::Path(format!(
            "Artifact path is absolute or unsafe: {:?}",
            input
        )));
    }
    let normalized = logical_path_nfc(input.trim_end_matches('/'));
    if normalized.is_empty() {
        return Err(JsError::Path(format!(
            "Artifact path is not normalized: {:?}",
            input
        )));
    }
    for part in normalized.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(JsError::Path(format!(
                "Artifact path is not normalized: {:?}",
                input
            )));
        }
    }
    Ok(normalized)
}
