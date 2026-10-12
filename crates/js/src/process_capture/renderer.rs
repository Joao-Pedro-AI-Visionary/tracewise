//! Port of REA `process/capture/TerminalRenderer.ts`.
//!
//! REA renders PTY output with `@xterm/headless` and serializes state with
//! `@xterm/addon-serialize`. This port renders with the `vt100` crate and
//! re-implements the addon's `StringSerializeHandler` over vt100 cells, so
//! `lines` and `serialized_state` follow the same algorithm. Known gaps
//! (documented as capture limitations by the caller):
//! - vt100 tracks bold/italic/underline/inverse only; dim, blink, overline,
//!   invisible and strikethrough SGR flags are not represented.
//! - vt100 does not expose the inactive normal buffer while the alternate
//!   screen is active, so alternate-screen state serializes without the
//!   normal-buffer prefix.
//! - Only cursor-key, keypad, bracketed-paste and mouse-tracking modes are
//!   serialized (vt100 does not expose insert/origin/wraparound/focus modes).

use serde_json::{json, Value};
use vt100::{Color, MouseProtocolMode, Parser};

/// Budget accounting for one terminal representation.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TerminalRetention {
    pub budget_bytes: u64,
    pub observed_bytes: u64,
    pub retained_bytes: u64,
    pub observed_frames: u64,
    pub retained_frames: u64,
}

impl TerminalRetention {
    pub fn to_value(self) -> Value {
        json!({
            "budget_bytes": self.budget_bytes,
            "observed_bytes": self.observed_bytes,
            "retained_bytes": self.retained_bytes,
            "observed_frames": self.observed_frames,
            "retained_frames": self.retained_frames,
        })
    }

    pub fn omitted(&self) -> bool {
        self.observed_frames > self.retained_frames
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Attr {
    fg: Color,
    bg: Color,
    bold: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
}

const DEFAULT_ATTR: Attr = Attr {
    fg: Color::Default,
    bg: Color::Default,
    bold: false,
    italic: false,
    underline: false,
    inverse: false,
};

#[derive(Debug, Clone)]
struct CellInfo {
    chars: String,
    width: usize,
    attr: Attr,
}

impl CellInfo {
    fn null() -> Self {
        Self { chars: String::new(), width: 1, attr: DEFAULT_ATTR }
    }
}

impl Attr {
    fn is_default(&self) -> bool {
        *self == DEFAULT_ATTR
    }
}

fn equal_bg(a: &Attr, b: &Attr) -> bool {
    a.bg == b.bg
}

fn push_color(seq: &mut Vec<u32>, color: Color, foreground: bool) {
    let (rgb, ext, base, bright, default) = if foreground { (38, 38, 30, 90, 39) } else { (48, 48, 40, 100, 49) };
    match color {
        Color::Rgb(r, g, b) => seq.extend([rgb, 2, r as u32, g as u32, b as u32]),
        Color::Idx(index) if index >= 16 => seq.extend([ext, 5, index as u32]),
        Color::Idx(index) => seq.push(if index & 8 != 0 { bright + (index as u32 & 7) } else { base + (index as u32 & 7) }),
        Color::Default => seq.push(default),
    }
}

fn diff_style(cell: &Attr, old: &Attr) -> Vec<u32> {
    let mut seq = Vec::new();
    let fg_changed = cell.fg != old.fg;
    let bg_changed = cell.bg != old.bg;
    let flags_changed = cell.inverse != old.inverse || cell.bold != old.bold || cell.underline != old.underline || cell.italic != old.italic;
    if fg_changed || bg_changed || flags_changed {
        if cell.is_default() {
            if !old.is_default() {
                seq.push(0);
            }
        } else {
            if fg_changed {
                push_color(&mut seq, cell.fg, true);
            }
            if bg_changed {
                push_color(&mut seq, cell.bg, false);
            }
            if flags_changed {
                if cell.inverse != old.inverse {
                    seq.push(if cell.inverse { 7 } else { 27 });
                }
                if cell.bold != old.bold {
                    seq.push(if cell.bold { 1 } else { 22 });
                }
                if cell.underline != old.underline {
                    seq.push(if cell.underline { 4 } else { 24 });
                }
                if cell.italic != old.italic {
                    seq.push(if cell.italic { 3 } else { 23 });
                }
            }
        }
    }
    seq
}

fn sgr(seq: &[u32]) -> String {
    format!("\u{1b}[{}m", seq.iter().map(u32::to_string).collect::<Vec<_>>().join(";"))
}

/// Port of xterm `StringSerializeHandler` over a materialized buffer.
struct Serializer<'a> {
    lines: &'a [Vec<CellInfo>],
    /// xterm `isWrapped`: line `i` continues line `i - 1`.
    wrapped: &'a [bool],
    term_rows: usize,
    cols: usize,
    all_rows: Vec<String>,
    all_separators: Vec<String>,
    current_row: String,
    null_cell_count: usize,
    cursor_style: Attr,
    cursor_style_row: usize,
    cursor_style_col: usize,
    background: Attr,
    first_row: usize,
    last_cursor_row: usize,
    last_cursor_col: usize,
    last_content_cursor_row: usize,
    last_content_cursor_col: usize,
}

impl<'a> Serializer<'a> {
    fn cell(&self, row: usize, col: usize) -> CellInfo {
        self.lines.get(row).and_then(|line| line.get(col)).cloned().unwrap_or_else(CellInfo::null)
    }

    fn run(mut self, cursor_row: usize, cursor_col: usize, pen: Attr) -> String {
        let end = self.lines.len().saturating_sub(1);
        for row in 0..self.lines.len() {
            for col in 0..self.cols {
                let cell = self.cell(row, col);
                self.next_cell(&cell, row, col);
            }
            self.row_end(row, row == end);
        }
        self.serialize_string(cursor_row, cursor_col, pen)
    }

    fn row_end(&mut self, row: usize, is_last: bool) {
        if self.null_cell_count > 0 && !equal_bg(&self.cursor_style, &self.background) {
            self.current_row.push_str(&format!("\u{1b}[{}X", self.null_cell_count));
        }
        let mut separator = String::new();
        if !is_last {
            if row - self.first_row >= self.term_rows {
                self.background = self.cell(self.cursor_style_row, self.cursor_style_col).attr;
            }
            if !self.wrapped.get(row + 1).copied().unwrap_or(false) {
                separator = "\r\n".into();
                self.last_cursor_row = row + 1;
                self.last_cursor_col = 0;
            } else {
                let this_last = self.cell(row, self.cols.saturating_sub(1));
                let this_last_second = self.cell(row, self.cols.saturating_sub(2));
                let next_first = self.cell(row + 1, 0);
                let double_width = next_first.width > 1;
                let mut valid = false;
                let admissible = if !next_first.chars.is_empty() && double_width {
                    self.null_cell_count <= 1
                } else {
                    self.null_cell_count == 0
                };
                if admissible {
                    if (!this_last.chars.is_empty() || this_last.width == 0) && equal_bg(&this_last.attr, &next_first.attr) {
                        valid = true;
                    }
                    if double_width
                        && (!this_last_second.chars.is_empty() || this_last_second.width == 0)
                        && equal_bg(&this_last.attr, &next_first.attr)
                        && equal_bg(&this_last_second.attr, &next_first.attr)
                    {
                        valid = true;
                    }
                }
                if !valid {
                    separator = "-".repeat(self.null_cell_count + 1);
                    separator.push_str("\u{1b}[1D\u{1b}[1X");
                    if self.null_cell_count > 0 {
                        let n = self.null_cell_count;
                        separator.push_str("\u{1b}[A");
                        separator.push_str(&format!("\u{1b}[{}C", self.cols - n));
                        separator.push_str(&format!("\u{1b}[{n}X"));
                        separator.push_str(&format!("\u{1b}[{}D", self.cols - n));
                        separator.push_str("\u{1b}[B");
                    }
                    self.last_content_cursor_row = row + 1;
                    self.last_content_cursor_col = 0;
                    self.last_cursor_row = row + 1;
                    self.last_cursor_col = 0;
                }
            }
        }
        self.all_rows.push(std::mem::take(&mut self.current_row));
        self.all_separators.push(separator);
        self.null_cell_count = 0;
    }

    fn next_cell(&mut self, cell: &CellInfo, row: usize, col: usize) {
        if cell.width == 0 {
            return;
        }
        let empty = cell.chars.is_empty();
        let seq = diff_style(&cell.attr, &self.cursor_style);
        let style_changed = if empty { !equal_bg(&self.cursor_style, &cell.attr) } else { !seq.is_empty() };
        if style_changed {
            if self.null_cell_count > 0 {
                if !equal_bg(&self.cursor_style, &self.background) {
                    self.current_row.push_str(&format!("\u{1b}[{}X", self.null_cell_count));
                }
                self.current_row.push_str(&format!("\u{1b}[{}C", self.null_cell_count));
                self.null_cell_count = 0;
            }
            self.last_content_cursor_row = row;
            self.last_cursor_row = row;
            self.last_content_cursor_col = col;
            self.last_cursor_col = col;
            self.current_row.push_str(&sgr(&seq));
            self.cursor_style = cell.attr;
            self.cursor_style_row = row;
            self.cursor_style_col = col;
        }
        if empty {
            self.null_cell_count += cell.width;
        } else {
            if self.null_cell_count > 0 {
                if equal_bg(&self.cursor_style, &self.background) {
                    self.current_row.push_str(&format!("\u{1b}[{}C", self.null_cell_count));
                } else {
                    self.current_row.push_str(&format!("\u{1b}[{}X", self.null_cell_count));
                    self.current_row.push_str(&format!("\u{1b}[{}C", self.null_cell_count));
                }
                self.null_cell_count = 0;
            }
            self.current_row.push_str(&cell.chars);
            self.last_content_cursor_row = row;
            self.last_cursor_row = row;
            self.last_content_cursor_col = col + cell.width;
            self.last_cursor_col = col + cell.width;
        }
    }

    fn serialize_string(mut self, cursor_row: usize, cursor_col: usize, pen: Attr) -> String {
        let mut row_end = self.all_rows.len();
        if self.lines.len() - self.first_row <= self.term_rows {
            row_end = self.last_content_cursor_row + 1 - self.first_row;
            self.last_cursor_col = self.last_content_cursor_col;
            self.last_cursor_row = self.last_content_cursor_row;
        }
        let mut content = String::new();
        for i in 0..row_end.min(self.all_rows.len()) {
            content.push_str(&self.all_rows[i]);
            if i + 1 < row_end {
                content.push_str(&self.all_separators[i]);
            }
        }
        let (real_row, real_col) = (cursor_row as i64, cursor_col as i64);
        if real_row != self.last_cursor_row as i64 || real_col != self.last_cursor_col as i64 {
            let down = real_row - self.last_cursor_row as i64;
            if down > 0 {
                content.push_str(&format!("\u{1b}[{down}B"));
            } else if down < 0 {
                content.push_str(&format!("\u{1b}[{}A", -down));
            }
            let right = real_col - self.last_cursor_col as i64;
            if right > 0 {
                content.push_str(&format!("\u{1b}[{right}C"));
            } else if right < 0 {
                content.push_str(&format!("\u{1b}[{}D", -right));
            }
        }
        let seq = diff_style(&pen, &self.cursor_style);
        if !seq.is_empty() {
            content.push_str(&sgr(&seq));
        }
        content
    }
}

/// Owns one headless terminal and serializes writes into deterministic frames.
pub struct TerminalRenderer {
    parser: Parser,
    max_bytes: u64,
    frames: Vec<Value>,
    captured_bytes: u64,
    observed_bytes: u64,
    observed_frames: u64,
}

impl TerminalRenderer {
    pub fn new(columns: u16, rows: u16, scrollback: u64, max_bytes: u64) -> Self {
        Self {
            parser: Parser::new(rows, columns, usize::try_from(scrollback).unwrap_or(usize::MAX)),
            max_bytes,
            frames: Vec::new(),
            captured_bytes: 0,
            observed_bytes: 0,
            observed_frames: 0,
        }
    }

    /// Parse one PTY chunk and capture state. Returns the retained sequence.
    pub fn write(&mut self, data: &str, at_ms: u64, normalize: &dyn Fn(&str) -> String) -> Option<usize> {
        self.parser.process(data.as_bytes());
        self.capture(at_ms, normalize)
    }

    /// Resize after every preceding write and capture state.
    pub fn resize(&mut self, columns: u16, rows: u16, at_ms: u64, normalize: &dyn Fn(&str) -> String) -> Option<usize> {
        self.parser.set_size(rows, columns);
        self.capture(at_ms, normalize)
    }

    pub fn frames(&self) -> &[Value] {
        &self.frames
    }

    pub fn retention(&self) -> TerminalRetention {
        TerminalRetention {
            budget_bytes: self.max_bytes,
            observed_bytes: self.observed_bytes,
            retained_bytes: self.captured_bytes,
            observed_frames: self.observed_frames,
            retained_frames: self.frames.len() as u64,
        }
    }

    fn read_cell(screen: &vt100::Screen, row: u16, col: u16) -> CellInfo {
        match screen.cell(row, col) {
            None => CellInfo::null(),
            Some(cell) => CellInfo {
                chars: if cell.is_wide_continuation() { String::new() } else { cell.contents() },
                width: if cell.is_wide_continuation() {
                    0
                } else if cell.is_wide() {
                    2
                } else {
                    1
                },
                attr: Attr {
                    fg: cell.fgcolor(),
                    bg: cell.bgcolor(),
                    bold: cell.bold(),
                    italic: cell.italic(),
                    underline: cell.underline(),
                    inverse: cell.inverse(),
                },
            },
        }
    }

    /// Materialize every buffer line (scrollback first) and xterm `isWrapped` flags.
    fn buffer(&mut self) -> (Vec<Vec<CellInfo>>, Vec<bool>, usize) {
        let (rows, cols) = self.parser.screen().size();
        self.parser.set_scrollback(usize::MAX);
        let scrollback_len = self.parser.screen().scrollback();
        let total = scrollback_len + rows as usize;
        let mut lines = Vec::with_capacity(total);
        let mut row_wraps = Vec::with_capacity(total);
        for index in 0..total {
            let row = if index < scrollback_len {
                self.parser.set_scrollback(scrollback_len - index);
                0
            } else {
                self.parser.set_scrollback(0);
                (index - scrollback_len) as u16
            };
            let screen = self.parser.screen();
            lines.push((0..cols).map(|col| Self::read_cell(screen, row, col)).collect::<Vec<_>>());
            row_wraps.push(screen.row_wrapped(row));
        }
        self.parser.set_scrollback(0);
        let mut wrapped = vec![false; total];
        if total > 1 {
            wrapped[1..total].copy_from_slice(&row_wraps[..total - 1]);
        }
        (lines, wrapped, scrollback_len)
    }

    fn serialize(&mut self) -> String {
        let (rows, cols) = self.parser.screen().size();
        let alternate = self.parser.screen().alternate_screen();
        let (lines, wrapped, base_y) = self.buffer();
        let screen = self.parser.screen();
        let (cursor_y, cursor_x) = screen.cursor_position();
        let pen = Attr {
            fg: screen.fgcolor(),
            bg: screen.bgcolor(),
            bold: screen.bold(),
            italic: screen.italic(),
            underline: screen.underline(),
            inverse: screen.inverse(),
        };
        let serializer = Serializer {
            lines: &lines,
            wrapped: &wrapped,
            term_rows: rows as usize,
            cols: cols as usize,
            all_rows: Vec::new(),
            all_separators: Vec::new(),
            current_row: String::new(),
            null_cell_count: 0,
            cursor_style: DEFAULT_ATTR,
            cursor_style_row: 0,
            cursor_style_col: 0,
            background: DEFAULT_ATTR,
            first_row: 0,
            last_cursor_row: 0,
            last_cursor_col: 0,
            last_content_cursor_row: 0,
            last_content_cursor_col: 0,
        };
        let body = serializer.run(base_y + cursor_y as usize, cursor_x as usize, pen);
        let mut content = if alternate { format!("\u{1b}[?1049h\u{1b}[H{body}") } else { body };
        if screen.application_cursor() {
            content.push_str("\u{1b}[?1h");
        }
        if screen.application_keypad() {
            content.push_str("\u{1b}[?66h");
        }
        if screen.bracketed_paste() {
            content.push_str("\u{1b}[?2004h");
        }
        match screen.mouse_protocol_mode() {
            MouseProtocolMode::None => {}
            MouseProtocolMode::Press => content.push_str("\u{1b}[?9h"),
            MouseProtocolMode::PressRelease => content.push_str("\u{1b}[?1000h"),
            MouseProtocolMode::ButtonMotion => content.push_str("\u{1b}[?1002h"),
            MouseProtocolMode::AnyMotion => content.push_str("\u{1b}[?1003h"),
        }
        content
    }

    fn visible_lines(&self) -> Vec<String> {
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        (0..rows)
            .map(|row| {
                let mut text = String::new();
                for col in 0..cols {
                    let cell = Self::read_cell(screen, row, col);
                    if cell.width == 0 {
                        continue;
                    }
                    if cell.chars.is_empty() {
                        text.push(' ');
                    } else {
                        text.push_str(&cell.chars);
                    }
                }
                let width = text.chars().count();
                if width < cols as usize {
                    text.push_str(&" ".repeat(cols as usize - width));
                }
                text
            })
            .collect()
    }

    fn capture(&mut self, at_ms: u64, normalize: &dyn Fn(&str) -> String) -> Option<usize> {
        let lines: Vec<String> = self
            .visible_lines()
            .into_iter()
            .map(|line| normalize(&line).trim_end_matches(' ').to_string())
            .collect();
        let serialized_state = normalize(&self.serialize());
        let bytes = serialized_state.len() as u64 + lines.iter().map(|l| l.len() as u64).sum::<u64>();
        self.observed_bytes += bytes;
        self.observed_frames += 1;
        if self.captured_bytes + bytes > self.max_bytes {
            return None;
        }
        self.captured_bytes += bytes;
        let screen = self.parser.screen();
        let (rows, cols) = screen.size();
        let (cursor_y, cursor_x) = screen.cursor_position();
        let sequence = self.frames.len();
        self.frames.push(json!({
            "sequence": sequence,
            "at_ms": at_ms,
            "columns": cols,
            "rows": rows,
            "cursor_x": cursor_x,
            "cursor_y": cursor_y,
            "active_buffer": if screen.alternate_screen() { "alternate" } else { "normal" },
            "lines": lines,
            "serialized_state": serialized_state,
        }));
        Some(sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(columns: u16, rows: u16, chunks: &[&str]) -> Value {
        let mut renderer = TerminalRenderer::new(columns, rows, 10, 1_000_000);
        for chunk in chunks {
            renderer.write(chunk, 0, &|s: &str| s.to_string());
        }
        renderer.frames().last().cloned().unwrap()
    }

    #[test]
    fn serializes_like_xterm_for_rea_oracle_frames() {
        // Ground truth from the REA oracle (xterm headless + addon-serialize).
        let frame = render(80, 24, &["hello"]);
        assert_eq!(frame["serialized_state"], "hello");
        assert_eq!(frame["cursor_x"], 5);
        let frame = render(40, 5, &["secret\r\n"]);
        assert_eq!(frame["serialized_state"], "secret\u{1b}[1B\u{1b}[6D");
        let frame = render(40, 5, &["secret\r\n", "\u{1b}[1;31mgot\u{1b}[0m secret\r\nhi\r\n"]);
        assert_eq!(frame["serialized_state"], "secret\r\n\u{1b}[31;1mgot\u{1b}[0m secret\r\nhi\u{1b}[1B\u{1b}[2D");
        assert_eq!(frame["lines"], json!(["secret", "got secret", "hi", "", ""]));
    }
}
