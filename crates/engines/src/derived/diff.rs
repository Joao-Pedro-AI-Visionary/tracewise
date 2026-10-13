//! Line diff with the exact search order of the `diff` package (jsdiff 9, `diffLines`).
//!
//! The comparison reports added/removed line counts and the number of changed components
//! ("hunks"). Those depend on which minimal edit script the search finds first, so the
//! Myers-style walk, its tie-breaking and the component merging are ported one to one rather
//! than replaced by another diff implementation.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One run of the edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub count: usize,
    pub added: bool,
    pub removed: bool,
}

#[derive(Clone, Copy)]
struct Component {
    count: usize,
    added: bool,
    removed: bool,
    previous: Option<usize>,
}

#[derive(Clone, Copy)]
struct Path {
    old_pos: i64,
    last: Option<usize>,
}

/// `Diff.tokenize` of the line diff: lines keep their terminator, empty tokens are dropped.
pub fn tokenize_lines(value: &str) -> Vec<String> {
    // value.split(/(\n|\r\n)/): separators are captured, so the parts alternate
    // content, separator, content, ...
    let mut parts: Vec<String> = Vec::new();
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            parts.push(value[start..index].to_string());
            parts.push("\n".to_string());
            index += 1;
            start = index;
        } else if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            parts.push(value[start..index].to_string());
            parts.push("\r\n".to_string());
            index += 2;
            start = index;
        } else {
            index += 1;
        }
    }
    parts.push(value[start..].to_string());
    // Ignore the final empty token that occurs if the string ends with a new line.
    if parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    let mut lines: Vec<String> = Vec::new();
    for (i, part) in parts.into_iter().enumerate() {
        if i % 2 == 1 {
            if let Some(last) = lines.last_mut() {
                last.push_str(&part);
            }
        } else {
            lines.push(part);
        }
    }
    lines.retain(|line| !line.is_empty());
    lines
}

struct Search<'a> {
    old: &'a [String],
    new: &'a [String],
    components: Vec<Component>,
}

impl Search<'_> {
    fn extract_common(&mut self, path: &mut Path, diagonal: i64) -> i64 {
        let new_len = self.new.len() as i64;
        let old_len = self.old.len() as i64;
        let mut old_pos = path.old_pos;
        let mut new_pos = old_pos - diagonal;
        let mut common = 0;
        while new_pos + 1 < new_len
            && old_pos + 1 < old_len
            && self.old[(old_pos + 1) as usize] == self.new[(new_pos + 1) as usize]
        {
            new_pos += 1;
            old_pos += 1;
            common += 1;
        }
        if common > 0 {
            self.components.push(Component {
                count: common,
                added: false,
                removed: false,
                previous: path.last,
            });
            path.last = Some(self.components.len() - 1);
        }
        path.old_pos = old_pos;
        new_pos
    }

    fn add_to_path(&mut self, path: &Path, added: bool, removed: bool, old_pos_inc: i64) -> Path {
        let component = match path.last.map(|index| self.components[index]) {
            Some(last) if last.added == added && last.removed == removed => Component {
                count: last.count + 1,
                added,
                removed,
                previous: last.previous,
            },
            last => Component {
                count: 1,
                added,
                removed,
                previous: if last.is_some() { path.last } else { None },
            },
        };
        self.components.push(component);
        Path {
            old_pos: path.old_pos + old_pos_inc,
            last: Some(self.components.len() - 1),
        }
    }

    fn build(&self, last: Option<usize>) -> Vec<Change> {
        let mut changes = Vec::new();
        let mut cursor = last;
        while let Some(index) = cursor {
            let component = self.components[index];
            changes.push(Change {
                count: component.count,
                added: component.added,
                removed: component.removed,
            });
            cursor = component.previous;
        }
        changes.reverse();
        changes
    }
}

/// `diffLines(old, new, { timeout, maxEditLength })`; `None` when the search is abandoned.
pub fn diff_lines(old_text: &str, new_text: &str, timeout: Duration, max_edit_length: usize) -> Option<Vec<Change>> {
    let old = tokenize_lines(old_text);
    let new = tokenize_lines(new_text);
    let new_len = new.len() as i64;
    let old_len = old.len() as i64;
    let mut edit_length: i64 = 1;
    let max_edit = (new_len + old_len).min(max_edit_length as i64);
    let deadline = Instant::now() + timeout;
    let mut search = Search {
        old: &old,
        new: &new,
        components: Vec::new(),
    };
    let mut best: HashMap<i64, Path> = HashMap::new();
    let mut first = Path { old_pos: -1, last: None };
    let new_pos = search.extract_common(&mut first, 0);
    if first.old_pos + 1 >= old_len && new_pos + 1 >= new_len {
        return Some(search.build(first.last));
    }
    best.insert(0, first);
    let mut min_diagonal = i64::MIN;
    let mut max_diagonal = i64::MAX;
    while edit_length <= max_edit && Instant::now() <= deadline {
        let lower = min_diagonal.max(-edit_length);
        let upper = max_diagonal.min(edit_length);
        let mut diagonal = lower;
        while diagonal <= upper {
            let remove_path = best.get(&(diagonal - 1)).copied();
            let add_path = best.get(&(diagonal + 1)).copied();
            if remove_path.is_some() {
                best.remove(&(diagonal - 1));
            }
            let can_add = add_path.is_some_and(|add| {
                let add_new_pos = add.old_pos - diagonal;
                0 <= add_new_pos && add_new_pos < new_len
            });
            let can_remove = remove_path.is_some_and(|remove| remove.old_pos + 1 < old_len);
            if !can_add && !can_remove {
                best.remove(&diagonal);
                diagonal += 2;
                continue;
            }
            let mut base = if !can_remove
                || (can_add && remove_path.map(|r| r.old_pos) < add_path.map(|a| a.old_pos))
            {
                search.add_to_path(&add_path.expect("add path exists"), true, false, 0)
            } else {
                search.add_to_path(&remove_path.expect("remove path exists"), false, true, 1)
            };
            let new_pos = search.extract_common(&mut base, diagonal);
            if base.old_pos + 1 >= old_len && new_pos + 1 >= new_len {
                return Some(search.build(base.last));
            }
            best.insert(diagonal, base);
            if base.old_pos + 1 >= old_len {
                max_diagonal = max_diagonal.min(diagonal - 1);
            }
            if new_pos + 1 >= new_len {
                min_diagonal = min_diagonal.max(diagonal + 1);
            }
            diagonal += 2;
        }
        edit_length += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(old: &str, new: &str) -> Vec<(usize, bool, bool)> {
        diff_lines(old, new, Duration::from_millis(100), 10_000)
            .unwrap()
            .into_iter()
            .map(|c| (c.count, c.added, c.removed))
            .collect()
    }

    #[test]
    fn tokenizer_keeps_terminators_and_drops_empty_tokens() {
        assert_eq!(tokenize_lines("a\nb"), vec!["a\n", "b"]);
        assert_eq!(tokenize_lines("a\r\nb\n"), vec!["a\r\n", "b\n"]);
        assert_eq!(tokenize_lines("a\n\nb"), vec!["a\n", "\n", "b"]);
        assert!(tokenize_lines("").is_empty());
    }

    #[test]
    fn identical_text_is_one_common_component() {
        assert_eq!(run("a\nb\n", "a\nb\n"), vec![(2, false, false)]);
    }

    /// Every recorded case (`fixtures/engines/gen_diff_cases.mjs`, produced by the real
    /// `diff` package) must give the identical component list, not just identical counts.
    #[test]
    fn component_lists_match_jsdiff_on_recorded_cases() {
        use std::io::Read;
        let packed = include_bytes!("../../../../fixtures/engines/oracle_diff_lines.json.gz");
        let mut raw = String::new();
        flate2::read::GzDecoder::new(&packed[..]).read_to_string(&mut raw).expect("the recorded cases decompress");
        let cases: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("recorded cases are JSON");
        assert!(cases.len() >= 700, "recorded cases: {}", cases.len());
        for (index, case) in cases.iter().enumerate() {
            let old = case["old"].as_str().unwrap();
            let new = case["new"].as_str().unwrap();
            let want: Vec<(usize, bool, bool)> = case["changes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| (c[0].as_u64().unwrap() as usize, c[1].as_bool().unwrap(), c[2].as_bool().unwrap()))
                .collect();
            let got: Vec<(usize, bool, bool)> = diff_lines(old, new, Duration::from_secs(5), 100_000)
                .unwrap_or_else(|| panic!("case {index} was abandoned"))
                .into_iter()
                .map(|c| (c.count, c.added, c.removed))
                .collect();
            assert_eq!(got, want, "case {index}: {old:?} -> {new:?}");
        }
    }

    #[test]
    fn replacement_is_a_removal_then_an_addition() {
        assert_eq!(
            run("a\nb\nc\n", "a\nx\nc\n"),
            vec![(1, false, false), (1, false, true), (1, true, false), (1, false, false)]
        );
    }
}
