//! Golden parity of the native Mach-O decoders with REA.
//!
//! `fixtures/native_static/macho_golden` holds Mach-O files rebuilt from Apple `otool -l`
//! captures (REA's own fixtures), the capture text, and what the ORIGINAL REA computes from
//! the captured tool output (`replay_rea.mjs`). The native decoders read only the file bytes.
//!
//! Intentionally different (documented, not silently ignored):
//! - `endian`: REA reads `file -b`, which prints no endianness on macOS (null); the native
//!   decoder knows the byte order.
//! - `provenance`: REA lists the Apple tool runs, tracewise one native decoder run.
//! - `limitations` and the coverage `limitations`: they name the producing tools.
//! - the `time stamp` text of dylib commands: `otool` prints it in the host time zone, the
//!   native printer in UTC.

use std::path::PathBuf;

use serde_json::Value;
use tracewise_native::macho_image::Image;
use tracewise_native::macho_tools::inspect_macho;
use tracewise_native::otool::print_header_and_commands;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native_static/macho_golden")
}

fn normalize_text(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| {
            let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.starts_with("time stamp ") {
                // Keep the numeric time stamp, drop the host-time-zone date text.
                collapsed.split(' ').take(3).collect::<Vec<_>>().join(" ")
            } else {
                collapsed
            }
        })
        .filter(|line| !line.is_empty())
        .collect()
}

fn check_text(name: &str) {
    let dir = golden_dir();
    let data = std::fs::read(dir.join(format!("{name}.macho"))).unwrap();
    let image = Image::parse(&data).unwrap();
    let printed = print_header_and_commands(&image, "$ARTIFACT").unwrap();
    let capture = std::fs::read_to_string(dir.join(format!("{name}.otool.txt"))).unwrap();
    let mine = normalize_text(&printed);
    let mut theirs = normalize_text(&capture);
    // The captures start with a path line (and, for the two-run capture, repeat it).
    theirs.retain(|line| !(line.ends_with(':') && (line.starts_with('/') || line.starts_with('$'))));
    let mine: Vec<String> = mine
        .into_iter()
        .filter(|line| !(line.ends_with(':') && (line.starts_with('/') || line.starts_with('$'))))
        .collect();
    // The capture of `dyld_inventory` has no `Mach header` block; compare commands only then.
    let start = mine.iter().position(|l| l == "Load command 0").unwrap();
    let theirs_start = theirs.iter().position(|l| l == "Load command 0").unwrap();
    assert_eq!(mine[start..], theirs[theirs_start..], "{name}: printed load commands differ from the Apple capture");
    if let Some(header) = theirs.iter().position(|l| l == "Mach header") {
        assert_eq!(mine[..start], theirs[header..theirs_start], "{name}: Mach header differs");
    }
}

fn check_inspection(name: &str) {
    let dir = golden_dir();
    let expected: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(format!("{name}.expected.json"))).unwrap()).unwrap();
    assert_eq!(expected["ok"], true);
    let expected = &expected["result"];
    let observation = inspect_macho(&dir.join(format!("{name}.macho")), Some("arm64"), "$ARTIFACT").unwrap();
    let got = &observation.result;
    for key in [
        "format",
        "word_size",
        "file_type",
        "flags",
        "uuid",
    ] {
        assert_eq!(got[key], expected[key], "{name}: {key}");
    }
    for key in [
        "entrypoints",
        "architectures",
        "build_metadata",
        "load_commands",
        "dependencies",
        "imports",
        "exports",
        "segments",
    ] {
        let mut mine = got[key].clone();
        let mut theirs = expected[key].clone();
        // Coverage limitations name the Apple tools.
        mine["limitations"] = Value::Null;
        theirs["limitations"] = Value::Null;
        if key == "load_commands" {
            // `time stamp` carries host-time-zone text in the capture.
            for side in [&mut mine, &mut theirs] {
                for item in side["items"].as_array_mut().unwrap() {
                    if let Some(stamp) = item["fields"].get_mut("time stamp") {
                        let text = stamp.as_str().unwrap().split(' ').next().unwrap().to_string();
                        *stamp = Value::String(text);
                    }
                }
            }
        }
        assert_eq!(mine, theirs, "{name}: {key} differs from REA on the Apple capture");
    }
}

#[test]
fn printed_load_commands_match_the_apple_captures() {
    check_text("header_capture");
    check_text("dyld_inventory");
}

#[test]
fn inspect_macho_matches_rea_on_header_capture() {
    check_inspection("header_capture");
}

#[test]
fn inspect_macho_matches_rea_on_dyld_inventory() {
    check_inspection("dyld_inventory");
}
