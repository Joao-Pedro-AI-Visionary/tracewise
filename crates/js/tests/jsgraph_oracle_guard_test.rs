//! `support::stream_oracle` feeds every layer-parity test, so it must refuse an oracle run that
//! covers only part of the corpus: a truncated stream (exit status 0, fewer lines than files) and
//! an unreadable line both fail the test instead of shrinking the comparison. These tests drive
//! the helper with small stand-in oracle scripts and do not need the REA checkout.

mod support;

use std::path::PathBuf;
use support::{stream_oracle, ORACLE_CHUNK};

/// More files than one chunk, so the chunking path is exercised too.
fn files(count: usize) -> Vec<PathBuf> {
    (0..count).map(|index| PathBuf::from(format!("/virtual/file-{index}.js"))).collect()
}

#[test]
fn complete_answers_are_all_delivered_across_chunks() {
    let corpus = files(ORACLE_CHUNK * 2 + 7);
    let mut seen = Vec::new();
    let answered = stream_oracle("fake_complete.mjs", &corpus, |line| seen.push(line["path"].as_str().unwrap().to_string()));
    assert_eq!(answered, corpus.len());
    let expected: Vec<String> = corpus.iter().map(|p| p.display().to_string()).collect();
    assert_eq!(seen, expected, "lines must arrive in corpus order");
}

#[test]
#[should_panic(expected = "the oracle dropped output")]
fn a_truncated_oracle_fails_instead_of_comparing_a_prefix() {
    stream_oracle("fake_truncated.mjs", &files(10), |_| {});
}

#[test]
#[should_panic(expected = "unreadable oracle line 2")]
fn an_unreadable_oracle_line_fails_instead_of_being_dropped() {
    stream_oracle("fake_unreadable.mjs", &files(10), |_| {});
}
