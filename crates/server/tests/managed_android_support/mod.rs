//! Helpers shared by the managed_android integration tests.

/// A test that needs an external oracle or tool that is not installed.
///
/// With `TRACEWISE_REQUIRE_ORACLE=1` (set by `/workspace/tools/env.sh`) a missing
/// prerequisite is a failure, so a green run always means the comparison ran.
/// Without it the caller prints why and returns, which is allowed for
/// contributors who do not have the REA checkout and the pinned tools.
#[allow(dead_code)]
pub fn require_or_skip(reason: &str) {
    if std::env::var("TRACEWISE_REQUIRE_ORACLE").as_deref() == Ok("1") {
        panic!("TRACEWISE_REQUIRE_ORACLE=1 but a prerequisite is missing: {reason}");
    }
    eprintln!("skipping: {reason}");
}

/// Reads a JSON fixture as text. Large recorded fixtures are stored gzipped
/// next to where the generators write them (`name.json.gz`), so a missing
/// `name.json` falls back to that file.
#[allow(dead_code)]
pub fn read_fixture_text(path: &std::path::Path) -> String {
    use std::io::Read;
    if path.exists() {
        return std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    let mut gz = path.as_os_str().to_owned();
    gz.push(".gz");
    let file = std::fs::File::open(&gz).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("{}.gz: {e}", path.display()));
    text
}

/// The APK variants the Android and Apktool scenarios refer to, derived from the
/// pinned ApiDemos APK exactly as `fixtures/android/gen/gen_android_scenarios.py`
/// derives them: a 200000-byte truncation, a text file named `.apk`, and the
/// same bytes named `.zip`. Written next to the APK when missing.
#[allow(dead_code)]
pub fn ensure_derived_android_fixtures(apk: &str) {
    let dir = std::path::Path::new(apk).parent().expect("apk directory");
    let bytes = std::fs::read(apk).expect("pinned ApiDemos APK");
    let derived: [(&str, Vec<u8>); 3] = [
        ("truncated.apk", bytes[..200_000.min(bytes.len())].to_vec()),
        ("not-a-zip.apk", b"this is not an apk\n".repeat(10)),
        ("ApiDemos-debug.zip", bytes.clone()),
    ];
    for (name, content) in derived {
        let path = dir.join(name);
        if std::fs::read(&path).ok().as_deref() != Some(content.as_slice()) {
            std::fs::write(&path, content).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        }
    }
}
