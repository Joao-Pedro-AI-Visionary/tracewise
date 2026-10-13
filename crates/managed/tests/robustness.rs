//! The inspectors parse hostile input: whatever the bytes, they must return a
//! result or a structured failure and never panic, overflow or hang.
//!
//! Inputs: arbitrary bytes, truncations and byte-level mutations of every PE
//! fixture in `fixtures/managed/` (synthetic REA images and three real NuGet
//! assemblies), and mutations concentrated on the headers where the offsets
//! live. A panic fails the property (proptest also shrinks it). Overflow checks
//! are on in the test profile, so arithmetic wrap-around is caught too.

use std::path::PathBuf;

use proptest::prelude::*;
use tracewise_managed::{
    inspect_managed_artifact_bytes, inspect_managed_members_bytes, inspect_managed_native_boundaries_bytes, ManagedTarget,
};

fn fixtures() -> &'static Vec<(String, Vec<u8>)> {
    static CACHE: std::sync::OnceLock<Vec<(String, Vec<u8>)>> = std::sync::OnceLock::new();
    CACHE.get_or_init(load_fixtures)
}

fn load_fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/managed");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("fixtures/managed")
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "dll"))
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap()))
        .collect();
    out.sort();
    assert_eq!(out.len(), 66, "managed fixtures");
    out
}

fn inspect_all(bytes: &[u8]) {
    let target = ManagedTarget { path: "/fuzz/input.dll".to_string(), sha256: "0".repeat(64) };
    // Results and failures are both fine; a panic is not.
    let _ = inspect_managed_artifact_bytes(bytes, &target);
    let _ = inspect_managed_members_bytes(bytes, &target);
    let _ = inspect_managed_native_boundaries_bytes(bytes, &target);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        inspect_all(&bytes);
    }

    #[test]
    fn arbitrary_bytes_behind_an_mz_header_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..2048), e_lfanew in 0u32..4096) {
        let mut bytes = vec![0u8; 64];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[60..64].copy_from_slice(&e_lfanew.to_le_bytes());
        bytes.extend_from_slice(&tail);
        inspect_all(&bytes);
    }

    #[test]
    fn mutated_fixtures_never_panic(
        index in 0usize..66,
        edits in proptest::collection::vec((any::<proptest::sample::Index>(), any::<u8>()), 1..24),
        truncate in proptest::option::of(any::<proptest::sample::Index>()),
    ) {
        let fixtures = fixtures();
        let mut bytes = fixtures[index].1.clone();
        for (at, value) in edits {
            let position = at.index(bytes.len());
            bytes[position] = value;
        }
        if let Some(cut) = truncate {
            bytes.truncate(cut.index(bytes.len() + 1));
        }
        inspect_all(&bytes);
    }

    #[test]
    fn mutations_inside_the_headers_never_panic(
        index in 0usize..66,
        edits in proptest::collection::vec((0usize..1024, any::<u8>()), 1..16),
    ) {
        // The first KiB holds the DOS/PE/CLI headers and the metadata root of the small
        // images, which is where sizes and offsets are decoded.
        let fixtures = fixtures();
        let mut bytes = fixtures[index].1.clone();
        for (at, value) in edits {
            let position = at % bytes.len();
            bytes[position] = value;
        }
        inspect_all(&bytes);
    }
}

#[test]
fn every_prefix_of_a_small_fixture_is_handled() {
    let fixtures = fixtures();
    let (_, bytes) = fixtures.iter().find(|(name, _)| name == "il_rich.dll").expect("il_rich.dll");
    for length in 0..bytes.len().min(1536) {
        inspect_all(&bytes[..length]);
    }
}
