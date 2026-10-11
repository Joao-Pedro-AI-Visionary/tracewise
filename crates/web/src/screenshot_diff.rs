use base64::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use crate::error::WebError;

const CDP_BROWSER_PROVIDER_ID: &str = "rea-cdp-browser";
const CDP_BROWSER_PROVIDER_NAME: &str = "REA Chrome DevTools Protocol observation provider";
const CDP_BROWSER_PROVIDER_VERSION: &str = "2";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompareWebScreenshotsInput {
    pub before: WebScreenshotArtifact,
    pub after: WebScreenshotArtifact,
    #[serde(default)]
    pub channel_threshold: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebScreenshotArtifact {
    pub sha256: String,
    pub bytes: u64,
    pub media_type: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewportDimensions {
    pub width: u32,
    pub height: u32,
}

fn limitations() -> Vec<String> {
    vec![
        "Pixel comparison does not perform OCR, semantic layout analysis, or perceptual color correction.".to_string(),
        "Only non-interlaced 8-bit RGB and RGBA PNG screenshots are accepted.".to_string(),
        "PNG tRNS transparency is accepted only as a six-byte RGB color key; tRNS on RGBA or with another length is rejected.".to_string(),
    ]
}

fn validate_artifact(artifact: &WebScreenshotArtifact, label: &str) -> Result<Vec<u8>, WebError> {
    if artifact.media_type != "image/png" {
        return Err(WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "media_type".to_string()],
            reason: "invalid_value".to_string(),
            message: format!(
                "{label}: media_type must be image/png, got {}",
                artifact.media_type
            ),
        });
    }
    #[allow(clippy::manual_is_multiple_of)]
    if artifact.data_base64.is_empty() || artifact.data_base64.len() % 4 != 0 {
        return Err(WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "data_base64".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("{label}: invalid canonical base64 length"),
        });
    }
    let decoded = BASE64_STANDARD
        .decode(&artifact.data_base64)
        .map_err(|e| WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "data_base64".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("{label}: base64 decode failed: {e}"),
        })?;

    if BASE64_STANDARD.encode(&decoded) != artifact.data_base64 {
        return Err(WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "data_base64".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("{label}: non-canonical base64"),
        });
    }

    if decoded.len() as u64 != artifact.bytes {
        return Err(WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "bytes".to_string()],
            reason: "invalid_value".to_string(),
            message: format!(
                "{label}: byte length mismatch: expected {}, got {}",
                artifact.bytes,
                decoded.len()
            ),
        });
    }

    let actual_sha256 = hex::encode(Sha256::digest(&decoded));
    if actual_sha256 != artifact.sha256 {
        return Err(WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec![label.to_string(), "sha256".to_string()],
            reason: "invalid_value".to_string(),
            message: format!(
                "{label}: sha256 mismatch: expected {}, got {}",
                artifact.sha256, actual_sha256
            ),
        });
    }

    Ok(decoded)
}

pub fn compare_web_screenshots(input: CompareWebScreenshotsInput) -> Result<Evidence, WebError> {
    let before_bytes = validate_artifact(&input.before, "before")?;
    let after_bytes = validate_artifact(&input.after, "after")?;

    let before_img = image::load_from_memory(&before_bytes)
        .map_err(|e| WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec!["before".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("Failed to decode before PNG: {e}"),
        })?;
    let after_img = image::load_from_memory(&after_bytes)
        .map_err(|e| WebError::Input {
            operation: "compare_web_screenshots".to_string(),
            path: vec!["after".to_string()],
            reason: "invalid_value".to_string(),
            message: format!("Failed to decode after PNG: {e}"),
        })?;

    let (before_w, before_h) = (before_img.width(), before_img.height());
    let (after_w, after_h) = (after_img.width(), after_img.height());

    let limitations_list = limitations();

    let normalized_result = if before_w != after_w || before_h != after_h {
        serde_json::json!({
            "before": {
                "width": before_w,
                "height": before_h
            },
            "after": {
                "width": after_w,
                "height": after_h
            },
            "channel_threshold": input.channel_threshold,
            "limitations": limitations_list,
            "status": "dimension_mismatch",
            "compared_pixels": 0,
            "changed_pixels": null,
            "changed_ratio": null,
            "maximum_channel_delta": null,
            "mean_absolute_channel_delta": null
        })
    } else {
        let before_rgba = before_img.to_rgba8();
        let after_rgba = after_img.to_rgba8();
        let b_raw = before_rgba.as_raw();
        let a_raw = after_rgba.as_raw();

        let pixels = (before_w as u64) * (before_h as u64);
        let mut changed_pixels = 0u64;
        let mut maximum_delta = 0u8;
        let mut total_delta = 0u64;

        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (b_px, a_px) in b_raw.chunks_exact(4).zip(a_raw.chunks_exact(4)) {
            let mut px_changed = false;
            for c in 0..4 {
                let delta = b_px[c].abs_diff(a_px[c]);
                total_delta += delta as u64;
                if delta > maximum_delta {
                    maximum_delta = delta;
                }
                if delta > input.channel_threshold {
                    px_changed = true;
                }
            }
            if px_changed {
                changed_pixels += 1;
            }
        }

        let mean_absolute_channel_delta = if pixels == 0 {
            0.0
        } else {
            (total_delta as f64) / ((pixels as f64) * 4.0)
        };

        let mean_delta_val = if mean_absolute_channel_delta == 0.0 {
            serde_json::json!(0)
        } else {
            serde_json::json!(mean_absolute_channel_delta)
        };

        if changed_pixels == 0 {
            serde_json::json!({
                "before": {
                    "width": before_w,
                    "height": before_h
                },
                "after": {
                    "width": after_w,
                    "height": after_h
                },
                "channel_threshold": input.channel_threshold,
                "limitations": limitations_list,
                "status": "identical",
                "compared_pixels": pixels,
                "changed_pixels": 0,
                "changed_ratio": 0,
                "maximum_channel_delta": maximum_delta,
                "mean_absolute_channel_delta": mean_delta_val
            })
        } else {
            let changed_ratio = (changed_pixels as f64) / (pixels as f64);
            serde_json::json!({
                "before": {
                    "width": before_w,
                    "height": before_h
                },
                "after": {
                    "width": after_w,
                    "height": after_h
                },
                "channel_threshold": input.channel_threshold,
                "limitations": limitations_list,
                "status": "different",
                "compared_pixels": pixels,
                "changed_pixels": changed_pixels,
                "changed_ratio": changed_ratio,
                "maximum_channel_delta": maximum_delta,
                "mean_absolute_channel_delta": mean_delta_val
            })
        }
    };

    let mut envelope_limitations = vec![
        "Artifact identity is unavailable for this observation.".to_string(),
    ];
    envelope_limitations.extend(limitations());

    let provider = EvidenceProvider {
        id: CDP_BROWSER_PROVIDER_ID.to_string(),
        name: CDP_BROWSER_PROVIDER_NAME.to_string(),
        version: Some(CDP_BROWSER_PROVIDER_VERSION.to_string()),
    };

    let parameters = serde_json::json!({
        "before_artifact_sha256": input.before.sha256,
        "after_artifact_sha256": input.after.sha256,
        "channel_threshold": input.channel_threshold,
    });

    let observation = EvidenceObservation {
        predicate_type: Some("rea.web-screenshot-diff".to_string()),
        operation: "compare_web_screenshots".to_string(),
        parameters,
        normalized_result,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Observed),
        authority: Some(EvidenceAuthority::ExternalService),
        environment: None,
        limitations: Some(envelope_limitations),
        locations: Some(vec![]),
        evidence_links: Some(vec![]),
    };

    create_evidence(None, provider, observation).map_err(WebError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screenshot_diff_against_oracle() {
        let bytes_a = std::fs::read("/workspace/tracewise/fixtures/web/shot_a.png").unwrap();
        let bytes_b = std::fs::read("/workspace/tracewise/fixtures/web/shot_b.png").unwrap();

        let sha_a = hex::encode(Sha256::digest(&bytes_a));
        let sha_b = hex::encode(Sha256::digest(&bytes_b));

        let art_a = WebScreenshotArtifact {
            sha256: sha_a,
            bytes: bytes_a.len() as u64,
            media_type: "image/png".to_string(),
            data_base64: BASE64_STANDARD.encode(&bytes_a),
        };
        let art_b = WebScreenshotArtifact {
            sha256: sha_b,
            bytes: bytes_b.len() as u64,
            media_type: "image/png".to_string(),
            data_base64: BASE64_STANDARD.encode(&bytes_b),
        };

        let ev = compare_web_screenshots(CompareWebScreenshotsInput {
            before: art_a,
            after: art_b,
            channel_threshold: 0,
        })
        .unwrap();

        let oracle_str = std::fs::read_to_string(
            "/workspace/tracewise/fixtures/web/oracle_compare_web_screenshots.json",
        )
        .unwrap();
        let oracle: serde_json::Value = serde_json::from_str(&oracle_str).unwrap();
        let oracle_sc = &oracle["structuredContent"];

        let ev_val = serde_json::to_value(&ev).unwrap();
        assert_eq!(ev_val["evidence_id"], oracle_sc["evidence_id"]);
        assert_eq!(ev_val["normalized_result"], oracle_sc["normalized_result"]);
        assert_eq!(ev_val, *oracle_sc);
    }
}

