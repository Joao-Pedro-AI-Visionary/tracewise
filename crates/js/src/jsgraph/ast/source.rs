//! Source text with Babel-style UTF-16 offsets and line/column positions.

use serde::{Deserialize, Serialize};

/// One parser coordinate (`line` is 1-based, `column` counts UTF-16 code units from 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourcePoint {
    pub line: u32,
    pub column: u32,
}

/// One exact source range (REA `JavaScriptSourceRange`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRange {
    pub start: SourcePoint,
    pub end: SourcePoint,
}

#[derive(Debug)]
pub struct Source {
    text: String,
    ascii: bool,
    /// `byte_of_unit[i]` is the byte offset of UTF-16 unit `i` (non-ASCII sources only).
    byte_of_unit: Vec<u32>,
    /// `unit_of_byte[b]` is the UTF-16 offset of byte `b` (non-ASCII sources only).
    unit_of_byte: Vec<u32>,
    /// UTF-16 offsets at which each line starts.
    line_starts: Vec<u32>,
    len16: u32,
}

impl Source {
    pub fn new(text: &str) -> Source {
        let ascii = text.is_ascii();
        let mut byte_of_unit = Vec::new();
        let mut unit_of_byte = Vec::new();
        let mut line_starts = vec![0u32];
        let mut unit = 0u32;
        let mut previous_cr = false;
        if !ascii {
            byte_of_unit.reserve(text.len() + 1);
            unit_of_byte.reserve(text.len() + 1);
        }
        for (byte, ch) in text.char_indices() {
            if !ascii {
                for _ in 0..ch.len_utf8() {
                    unit_of_byte.push(unit);
                }
                for _ in 0..ch.len_utf16() {
                    byte_of_unit.push(byte as u32);
                }
            }
            let width = ch.len_utf16() as u32;
            match ch {
                '\n' => {
                    if !previous_cr {
                        line_starts.push(unit + width);
                    } else {
                        // `\r\n`: the line already started after `\r`; move it past `\n`.
                        if let Some(last) = line_starts.last_mut() {
                            *last = unit + width;
                        }
                    }
                    previous_cr = false;
                }
                '\r' => {
                    line_starts.push(unit + width);
                    previous_cr = true;
                }
                '\u{2028}' | '\u{2029}' => {
                    line_starts.push(unit + width);
                    previous_cr = false;
                }
                _ => previous_cr = false,
            }
            unit += width;
        }
        if !ascii {
            byte_of_unit.push(text.len() as u32);
            unit_of_byte.push(unit);
        }
        Source {
            text: text.to_string(),
            ascii,
            byte_of_unit,
            unit_of_byte,
            line_starts,
            len16: unit,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// Length in UTF-16 code units (`source.length`).
    pub fn len16(&self) -> u32 {
        self.len16
    }

    pub fn is_ascii(&self) -> bool {
        self.ascii
    }

    /// UTF-16 offset of a UTF-8 byte offset.
    pub fn unit_of_byte(&self, byte: u32) -> u32 {
        if self.ascii {
            byte
        } else {
            self.unit_of_byte[(byte as usize).min(self.unit_of_byte.len() - 1)]
        }
    }

    /// UTF-8 byte offset of a UTF-16 offset (snapped to a char boundary).
    pub fn byte_of_unit(&self, unit: u32) -> usize {
        if self.ascii {
            (unit as usize).min(self.text.len())
        } else {
            self.byte_of_unit[(unit as usize).min(self.byte_of_unit.len() - 1)] as usize
        }
    }

    /// `source.slice(start, end)` with UTF-16 offsets.
    pub fn slice(&self, start: u32, end: u32) -> &str {
        let from = self.byte_of_unit(start);
        let to = self.byte_of_unit(end).max(from);
        &self.text[from..to]
    }

    pub fn point(&self, offset: u32) -> SourcePoint {
        let index = match self.line_starts.binary_search(&offset) {
            Ok(index) => index,
            Err(index) => index - 1,
        };
        SourcePoint {
            line: index as u32 + 1,
            column: offset - self.line_starts[index],
        }
    }

    pub fn range(&self, start: u32, end: u32) -> SourceRange {
        SourceRange {
            start: self.point(start),
            end: self.point(end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_offsets_and_lines() {
        let source = Source::new("a\r\nb\u{1F600}c\n\u{2028}d");
        // a(0) \r(1) \n(2) b(3) emoji(4,5) c(6) \n(7)  (8) d(9)
        assert_eq!(source.len16(), 10);
        assert_eq!(source.point(0), SourcePoint { line: 1, column: 0 });
        assert_eq!(source.point(3), SourcePoint { line: 2, column: 0 });
        assert_eq!(source.point(6), SourcePoint { line: 2, column: 3 });
        assert_eq!(source.point(8), SourcePoint { line: 3, column: 0 });
        assert_eq!(source.point(9), SourcePoint { line: 4, column: 0 });
        assert_eq!(source.slice(3, 7), "b\u{1F600}c");
        assert_eq!(source.unit_of_byte(source.byte_of_unit(6) as u32), 6);
    }
}
