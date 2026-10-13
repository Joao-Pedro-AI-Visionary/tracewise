//! A directory node hashes the names AND the ids of its children, child directories included.
//!
//! REA assigns a directory's id deepest first, so a parent sees the ids of its child directories.
//! Reading those ids before they were assigned made every nested directory with the same child
//! names the same node, whatever its contents.

use std::collections::BTreeMap;

fn directory_ids(root: &std::path::Path) -> BTreeMap<String, String> {
    let evidences = tracewise_js::inspect_artifact(&root.to_string_lossy(), "fail").expect("inspect_artifact");
    let inspection = serde_json::to_value(evidences.last().expect("evidence")).unwrap();
    let inventory = &inspection["normalized_result"]["substeps"][0]["evidence"]["normalized_result"];
    inventory["occurrences"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["entry_kind"] == "directory")
        .map(|o| (o["logical_path"].as_str().unwrap().to_string(), o["artifact_id"].as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn nested_directories_with_the_same_names_but_other_contents_are_other_nodes() {
    let dir = tempfile::tempdir().unwrap();
    for (parent, content) in [("a", "one"), ("b", "two"), ("c", "one")] {
        let nested = dir.path().join(parent).join("x");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("f"), content).unwrap();
    }
    let ids = directory_ids(dir.path());
    assert_eq!(ids["a/x"], ids["c/x"], "same names, same content");
    assert_ne!(ids["a/x"], ids["b/x"], "same names, other content");
    assert_eq!(ids["a"], ids["c"], "same names, same child ids");
    assert_ne!(ids["a"], ids["b"], "a parent follows the ids of its child directories");
}
