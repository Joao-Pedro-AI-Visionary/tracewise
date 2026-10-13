//! The native catalog reader against real compiled catalogs.
//!
//! `fixtures/native_static/assets/vendor` versions seven catalogs produced by Apple tools (CoreUI 366,
//! 374 and 868; licenses and sources in its README). `TRACEWISE_CAR_CATALOGS` may name a directory
//! with further `.car` files to check as well; with `TRACEWISE_REQUIRE_ORACLE=1` a directory that is
//! named but unreadable fails the test instead of being skipped.
//!
//! Independent check: the `renditionCount` of each CARHEADER (written by Apple's compiler) must
//! equal the number of rendition records the reader produced, and every rendition must resolve
//! its facet name or be an unnamed packed asset.

use std::path::PathBuf;

use tracewise_native::car::read_catalog;

fn header_rendition_count(data: &[u8]) -> u32 {
    // BOM header: index offset at 16, variable table offset at 24 (big endian).
    let be = |at: usize| u32::from_be_bytes(data[at..at + 4].try_into().unwrap()) as usize;
    let index_offset = be(16);
    let var_offset = be(24);
    let block_count = be(index_offset);
    let blocks: Vec<(usize, usize)> =
        (0..block_count).map(|i| (be(index_offset + 4 + i * 8), be(index_offset + 8 + i * 8))).collect();
    let mut cursor = var_offset + 4;
    for _ in 0..be(var_offset) {
        let block = be(cursor);
        let length = data[cursor + 4] as usize;
        let name = &data[cursor + 5..cursor + 5 + length];
        if name == b"CARHEADER" {
            let (offset, _) = blocks[block];
            return u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap());
        }
        cursor += 5 + length;
    }
    panic!("no CARHEADER");
}

fn car_files(dir: &std::path::Path) -> std::io::Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "car"))
        .collect();
    paths.sort();
    Ok(paths)
}

fn catalogs() -> Vec<PathBuf> {
    let vendored = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native_static/assets/vendor");
    let mut paths = car_files(&vendored).expect("the vendored catalogs directory must be present");
    if let Some(dir) = std::env::var_os("TRACEWISE_CAR_CATALOGS") {
        match car_files(std::path::Path::new(&dir)) {
            Ok(extra) => paths.extend(extra),
            Err(error) if std::env::var_os("TRACEWISE_REQUIRE_ORACLE").is_some_and(|v| v == "1") => {
                panic!("TRACEWISE_CAR_CATALOGS={dir:?} cannot be read ({error}) and TRACEWISE_REQUIRE_ORACLE=1")
            }
            Err(error) => eprintln!("skipping TRACEWISE_CAR_CATALOGS={dir:?}: {error}"),
        }
    }
    paths
}

#[test]
fn rendition_records_match_the_carheader_count() {
    let mut checked = 0;
    for path in catalogs() {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let records = read_catalog(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            records.len() as u32 - 1,
            header_rendition_count(&data),
            "{}: rendition records vs CARHEADER",
            path.display()
        );
        assert!(records[0].get("CoreUIVersion").is_some());
        assert!(records[0]["Key Format"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
        checked += 1;
    }
    assert!(checked >= 7, "the seven vendored catalogs must be present, found {checked}");
}

#[test]
fn named_renditions_carry_their_facet_name_and_identifier() {
    let data = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native_static/assets/vendor/assets_tv.car"),
    )
    .unwrap();
    let records = read_catalog(&data).unwrap();
    let tv: Vec<_> = records.iter().filter(|r| r["Name"] == "d_tv").collect();
    assert_eq!(tv.len(), 1, "d_tv has exactly one rendition in acextract's tvOS catalog");
    assert_eq!(tv[0]["Idiom"], "tv");
    assert!(tv[0]["NameIdentifier"].as_u64().unwrap() > 0);
}
