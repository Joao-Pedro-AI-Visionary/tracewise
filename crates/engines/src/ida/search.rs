//! Text matching for `search_procedures` / `search_strings` (the filter half of
//! `IdaOperationRunner.search`).
//!
//! REA compiles regex mode with `new RegExp(pattern, "u" | "iu")`. The `fancy-regex`
//! engine accepts the same constructs (lookaround, backreferences, named groups); the
//! translation below only adjusts the classes whose JavaScript meaning differs from
//! Rust's: `\d`, `\w`, `\b` are ASCII, `\s` is the ECMAScript whitespace set, and `.`
//! excludes every line terminator. Inside a character class only `\d`, `\w`, `\s` are
//! rewritten; `[]` and `[^]` keep their JavaScript meaning.

use fancy_regex::Regex;

/// ECMAScript `WhiteSpace` and `LineTerminator`.
const JS_WHITESPACE: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";
const WORD: &str = "A-Za-z0-9_";

/// Translate an ECMAScript pattern (with the `u` flag) to the syntax of `fancy-regex`.
pub fn translate(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        index += 1;
        if c == '\\' {
            let Some(&escaped) = chars.get(index) else {
                out.push('\\');
                break;
            };
            index += 1;
            match (escaped, in_class) {
                ('d', false) => out.push_str("[0-9]"),
                ('d', true) => out.push_str("0-9"),
                ('D', false) => out.push_str("[^0-9]"),
                ('w', false) => out.push_str(&format!("[{WORD}]")),
                ('w', true) => out.push_str(WORD),
                ('W', false) => out.push_str(&format!("[^{WORD}]")),
                ('s', false) => out.push_str(&format!("[{JS_WHITESPACE}]")),
                ('s', true) => out.push_str(JS_WHITESPACE),
                ('S', false) => out.push_str(&format!("[^{JS_WHITESPACE}]")),
                ('b', false) => out.push_str(&format!(
                    "(?:(?<=[{WORD}])(?![{WORD}])|(?<![{WORD}])(?=[{WORD}]))"
                )),
                ('B', false) => out.push_str(&format!(
                    "(?:(?<=[{WORD}])(?=[{WORD}])|(?<![{WORD}])(?![{WORD}]))"
                )),
                // \uXXXX and \u{X...} are code points in unicode mode.
                ('u', _) => {
                    if chars.get(index) == Some(&'{') {
                        out.push_str("\\x");
                    } else {
                        let digits: String = chars[index..].iter().take(4).collect();
                        if digits.len() == 4 && digits.chars().all(|d| d.is_ascii_hexdigit()) {
                            out.push_str(&format!("\\x{{{digits}}}"));
                            index += 4;
                        } else {
                            out.push_str("\\u");
                        }
                    }
                }
                (other, _) => {
                    out.push('\\');
                    out.push(other);
                }
            }
            continue;
        }
        if in_class {
            if c == ']' {
                in_class = false;
            }
            out.push(c);
            continue;
        }
        match c {
            '[' => {
                // `[]` never matches and `[^]` matches any code point.
                if chars.get(index) == Some(&']') {
                    index += 1;
                    out.push_str("(?!)");
                } else if chars.get(index) == Some(&'^') && chars.get(index + 1) == Some(&']') {
                    index += 2;
                    out.push_str("(?s:.)");
                } else {
                    in_class = true;
                    out.push('[');
                    if chars.get(index) == Some(&'^') {
                        out.push('^');
                        index += 1;
                    }
                    // A leading `]` is a member in Rust classes but closes the class in
                    // ECMAScript; the cases above already handled the empty classes.
                }
            }
            '.' => out.push_str(r"[^\n\r\x{2028}\x{2029}]"),
            other => out.push(other),
        }
    }
    out
}

/// Compile a pattern the way `new RegExp(pattern, case_sensitive ? "u" : "iu")` would.
pub fn compile(pattern: &str, case_sensitive: bool) -> Option<Regex> {
    let translated = translate(pattern);
    let source = if case_sensitive {
        translated
    } else {
        format!("(?i){translated}")
    };
    Regex::new(&source).ok()
}

/// `RegExp.prototype.test` (an unanchored search).
pub fn is_match(regex: &Regex, value: &str) -> bool {
    regex.is_match(value).unwrap_or(false)
}

/// Case handling of literal mode: `String.prototype.includes` after optional lowercasing.
pub fn literal_matches(value: &str, pattern: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        value.contains(pattern)
    } else {
        value.to_lowercase().contains(&pattern.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(pattern: &str, value: &str, case_sensitive: bool) -> bool {
        is_match(
            &compile(pattern, case_sensitive).expect("pattern compiles"),
            value,
        )
    }

    #[test]
    fn dot_excludes_line_terminators_like_javascript() {
        assert!(hit("a.b", "a-b", true));
        assert!(!hit("a.b", "a\nb", true));
        assert!(!hit("a.b", "a\rb", true));
        assert!(!hit("a.b", "a\u{2028}b", true));
    }

    #[test]
    fn digit_word_and_boundary_classes_are_ascii() {
        assert!(hit(r"^\d+$", "0123", true));
        assert!(!hit(r"^\d+$", "\u{0663}\u{0664}", true));
        assert!(!hit(r"^\w+$", "caf\u{e9}", true));
        assert!(hit(r"\bGLIBC", "x GLIBC_2.2.5", true));
        assert!(!hit(r"\bLIBC", "GLIBC", true));
        assert!(hit(r"[\d_]+x", "12_x", true));
    }

    #[test]
    fn whitespace_class_is_the_ecmascript_set() {
        assert!(hit(r"a\sb", "a\u{a0}b", true));
        assert!(hit(r"a\sb", "a\u{feff}b", true));
        assert!(!hit(r"a\sb", "a\u{200b}b", true));
    }

    #[test]
    fn javascript_only_constructs_still_compile() {
        assert!(hit("^(?!foo)bar", "bar", true));
        assert!(!hit("^(?!foo)foo", "foo", true));
        assert!(hit(r"(a)\1", "aa", true));
        assert!(hit(r"(?<word>ab)\k<word>", "abab", true));
        assert!(hit(r"ABC", "ABC", true));
        assert!(hit(r"\u{41}BC", "ABC", true));
    }

    #[test]
    fn empty_classes_follow_ecmascript() {
        assert!(!hit("a[]b", "ab", true));
        assert!(hit("a[^]b", "a\nb", true));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(compile("(", true).is_none());
        assert!(compile("[", true).is_none());
    }

    #[test]
    fn case_insensitivity_and_literals() {
        assert!(hit("ENGINE_LEAF", "engine_leaf", false));
        assert!(!hit("ENGINE_LEAF", "engine_leaf", true));
        assert!(literal_matches("Engine", "ENG", false));
        assert!(!literal_matches("a.b", "a+b", false));
    }
}
