//! App bundle resolution (port of REA `application/AppBundleExecutable.ts`).
//!
//! Binary `Info.plist` files are decoded natively; REA shells out to
//! `plutil` for them on macOS.

use std::fs;
use std::path::{Path, PathBuf};

use crate::bounded_read::{read_bounded, Bounded};
use crate::error::NativeError;

/// An Info.plist is a few KiB; the cap keeps a hostile bundle from filling memory.
const MAX_INFO_PLIST_BYTES: u64 = 16 * 1024 * 1024;
use crate::plistjs::{decode_xml_plist_text, parse_binary_checked, parse_xml_checked, PVal};

#[derive(Debug, Clone)]
pub struct ResolvedBundle {
    /// Canonical path of the declared program file.
    pub executable: PathBuf,
    pub info_plist: PathBuf,
}

struct Layout {
    plist: &'static [&'static str],
    programs: &'static [&'static str],
    programs_label: &'static str,
}

const LAYOUTS: [Layout; 2] = [
    Layout {
        plist: &["Contents", "Info.plist"],
        programs: &["Contents", "MacOS"],
        programs_label: "Contents/MacOS",
    },
    Layout {
        plist: &["Info.plist"],
        programs: &[],
        programs_label: "the bundle root",
    },
];

fn join(base: &Path, parts: &[&str]) -> PathBuf {
    let mut path = base.to_path_buf();
    for part in parts {
        path.push(part);
    }
    path
}

fn target_error(path: &Path, reason: String) -> NativeError {
    NativeError::Target {
        path: path.to_string_lossy().into_owned(),
        reason,
    }
}

fn is_absence(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::NotFound) || error.raw_os_error() == Some(20)
}

fn present_layout(bundle: &Path) -> Result<Option<&'static Layout>, NativeError> {
    for layout in &LAYOUTS {
        let plist = join(bundle, layout.plist);
        match fs::metadata(&plist) {
            Ok(metadata) if metadata.is_file() => return Ok(Some(layout)),
            Ok(_) => {}
            Err(error) if is_absence(&error) => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(target_error(
                    &plist,
                    format!("permission denied inspecting app Info.plist {}", plist.display()),
                ))
            }
            Err(_) => {
                return Err(target_error(
                    bundle,
                    format!("could not inspect app bundle path {}", bundle.display()),
                ))
            }
        }
    }
    Ok(None)
}

fn wrapped_bundle(bundle: &Path) -> Option<PathBuf> {
    let wrapper = bundle.join("Wrapper");
    let metadata = fs::symlink_metadata(&wrapper).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    let mut app: Option<PathBuf> = None;
    for entry in fs::read_dir(&wrapper).ok()? {
        let entry = entry.ok()?;
        let file_type = entry.file_type().ok()?;
        if !file_type.is_dir() || !entry.file_name().to_string_lossy().to_lowercase().ends_with(".app") {
            continue;
        }
        if app.is_some() {
            return None;
        }
        app = Some(entry.path());
    }
    app
}

fn is_safe_executable_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('\0') && !name.contains('/') && !name.contains('\\')
}

fn executable_name(plist_path: &Path) -> Result<String, NativeError> {
    let read_error = |error: std::io::Error| {
        target_error(
            plist_path,
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                format!("permission denied reading app Info.plist {}", plist_path.display())
            } else if is_absence(&error) {
                format!("app Info.plist is missing: {}", plist_path.display())
            } else {
                format!("could not read app Info.plist {}", plist_path.display())
            },
        )
    };
    let bytes = match fs::File::open(plist_path).and_then(|file| read_bounded(file, MAX_INFO_PLIST_BYTES)) {
        Ok(Bounded::Complete(bytes)) => bytes,
        Ok(Bounded::TooLarge) => {
            return Err(target_error(
                plist_path,
                format!("app Info.plist exceeds {MAX_INFO_PLIST_BYTES} bytes: {}", plist_path.display()),
            ))
        }
        Err(error) => return Err(read_error(error)),
    };
    let malformed = |detail: String| {
        target_error(
            plist_path,
            format!(
                "app Info.plist is malformed, unsupported, or lacks CFBundleExecutable: {} ({detail})",
                plist_path.display()
            ),
        )
    };
    let value = if bytes.len() >= 6 && &bytes[..6] == b"bplist" {
        parse_binary_checked(&bytes).map_err(|e| malformed(e.message))?
    } else {
        let text = decode_xml_plist_text(&bytes).map_err(|e| malformed(e.message))?;
        parse_xml_checked(&text).map_err(|e| malformed(e.message))?.0
    };
    match value {
        PVal::Dict(map) => match map.get("CFBundleExecutable") {
            Some(PVal::Str(name)) => Ok(name.clone()),
            _ => Err(malformed("CFBundleExecutable is missing".to_string())),
        },
        _ => Err(malformed("CFBundleExecutable is missing".to_string())),
    }
}

fn resolve_layout(bundle: &Path, layout: &Layout) -> Result<ResolvedBundle, NativeError> {
    let plist_path = join(bundle, layout.plist);
    let name = executable_name(&plist_path)?;
    if !is_safe_executable_name(&name) {
        return Err(target_error(bundle, "app has an unsafe CFBundleExecutable".to_string()));
    }
    let programs = join(bundle, layout.programs);
    let executable = programs.join(&name);
    let missing = |path: &Path, error: &std::io::Error| {
        target_error(
            path,
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                format!("permission denied resolving app program file {}", path.display())
            } else if is_absence(error) {
                format!("app program file is missing: {}", path.display())
            } else {
                format!("could not resolve app program file {}", path.display())
            },
        )
    };
    let canonical_programs = fs::canonicalize(&programs).map_err(|e| missing(&executable, &e))?;
    let canonical_executable = fs::canonicalize(&executable).map_err(|e| missing(&executable, &e))?;
    if !canonical_executable.starts_with(&canonical_programs) || canonical_executable == canonical_programs {
        return Err(target_error(
            bundle,
            format!("app program file leaves {}", layout.programs_label),
        ));
    }
    Ok(ResolvedBundle {
        executable: canonical_executable,
        info_plist: plist_path,
    })
}

/// Resolve an app bundle directory to its declared program file.
pub fn resolve_app_bundle(path: &Path) -> Result<ResolvedBundle, NativeError> {
    if let Some(layout) = present_layout(path)? {
        return resolve_layout(path, layout);
    }
    if let Some(wrapped) = wrapped_bundle(path) {
        if let Some(layout) = present_layout(&wrapped)? {
            return resolve_layout(&wrapped, layout);
        }
    }
    Err(target_error(
        path,
        format!(
            "app Info.plist is missing or no supported bundle layout was found: {}",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_info_plist_is_refused_without_reading_it_all() {
        let root = std::env::temp_dir().join(format!("tracewise-bigplist-{}.app", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Contents/MacOS")).unwrap();
        fs::write(root.join("Contents/MacOS/App"), b"x").unwrap();
        // 17 MiB of whitespace after a valid prefix: larger than MAX_INFO_PLIST_BYTES.
        let mut plist = b"<plist><dict><key>CFBundleExecutable</key><string>App</string></dict></plist>".to_vec();
        plist.resize(17 * 1024 * 1024, b' ');
        fs::write(root.join("Contents/Info.plist"), &plist).unwrap();
        let result = resolve_app_bundle(&root);
        fs::remove_dir_all(&root).unwrap();
        match result {
            Err(NativeError::Target { reason, .. }) => assert!(reason.contains("exceeds"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_normal_info_plist_still_resolves() {
        let root = std::env::temp_dir().join(format!("tracewise-okplist-{}.app", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("Contents/MacOS")).unwrap();
        fs::write(root.join("Contents/MacOS/App"), b"x").unwrap();
        fs::write(
            root.join("Contents/Info.plist"),
            b"<plist><dict><key>CFBundleExecutable</key><string>App</string></dict></plist>",
        )
        .unwrap();
        let resolved = resolve_app_bundle(&root);
        fs::remove_dir_all(&root).unwrap();
        assert!(resolved.unwrap().executable.ends_with("Contents/MacOS/App"));
    }
}
