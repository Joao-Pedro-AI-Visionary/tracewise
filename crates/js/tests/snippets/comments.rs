//! Source-map directives: comment forms, separators, UTF-16 columns, quoted look-alikes.

use super::named;

pub fn snippets() -> Vec<(String, String)> {
    let mut out = named("comment_fixed_", FIXED);
    let directive = "//# sourceMappingURL=app.js.map";
    let separators = [
        "\n", "\r\n", "\r", "\u{2028}", "\u{2029}", " ", "\u{b}", "\u{c}", "\r\n\r\u{2028}\n\u{2029}",
    ];
    for (index, separator) in separators.iter().enumerate() {
        out.push((format!("comment_sep_{index:03}.js"), format!("const marker = \"\u{1F600}\";{separator}  {directive}")));
    }
    out.push((
        "comment_block_terminators.js".into(),
        "const value = 1;\r/*#\u{2028} sourceMappingURL=\r\n app.js.map */".into(),
    ));
    out.push((
        "comment_repeat.js".into(),
        format!("const marker = \"\u{1F600}\";\r  {directive}\u{2028}{directive}"),
    ));
    out.push(("comment_unicode_ws.js".into(), "\u{11e}/*@\u{a0}sourceMappingURL\u{2003}=\u{feff}app.js.map* ignored */".into()));
    out.push((
        "comment_two_byte_inline.js".into(),
        format!(
            "const label = \"\u{11f}\";\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,{}",
            "A".repeat(2_000_000)
        ),
    ));
    for (index, (prefix, suffix)) in [("//#", "sourceMappingURL=x"), ("//# sourceMappingURL", "=x"), ("//# sourceMappingURL=", "x")].iter().enumerate() {
        out.push((
            format!("comment_spaces_{index:03}.js"),
            format!("\u{11f}{prefix}{}{suffix}", " ".repeat(500_000)),
        ));
    }
    out
}

const FIXED: &[&str] = &[
    "//# sourceMappingURL=app.js.map",
    "//@ sourceMappingURL=app.js.map",
    "/*# sourceMappingURL=app.js.map */",
    "code();\n/*# sourceMappingURL=vendor.abc.map */",
    "//# sourceMappingURL=first.map\n/*# sourceMappingURL=second.map */",
    "//#",
    "//# \t",
    "//# sourceMappingURL",
    "//# sourceMappingURL \t",
    "//# sourceMappingURL=",
    "//# sourceMappingURL= \t",
    "/*# sourceMappingURL= */",
    "//# sourceMappingURLx=app.js.map",
    "//# sourceMappingURL app.js.map",
    "//# sourceMappingURL=*",
    "/*# sourceMappingURL=a*b */",
    "/*# sourceMappingURL=a.map*/",
    "//## sourceMappingURL=x.map\n//@@ sourceMappingURL=y.map\n// # sourceMappingURL=z.map\n//#sourceMappingURL=w.map\n//#\tsourceMappingURL=\ttab.map",
    "//#sourceMappingURL=glued.map",
    "//# sourceMappingURL=with space.map",
    "//# sourceMappingURL=a.map extra words",
    "/*@ sourceMappingURL=typed.map */",
    "const value = 1;\n//# sourceMappingURL=data:application/json;base64,e30=",
    "#!/usr/bin/env node\n//# sourceMappingURL=shebang.map",
    "const documentation = \"//# sourceMappingURL=ghost.map \";",
    "const documentation = \"/*# sourceMappingURL=ghost.map */\";",
    "const documentation = `//# sourceMappingURL=ghost.map `;",
    "const pattern = /[//# sourceMappingURL=ghost.map ]/;",
    "const view = <div>//# sourceMappingURL=ghost.map </div>;",
    "/* Documentation example: //# sourceMappingURL=ghost.map */",
    "const a = \"//# sourceMappingURL=ghost.map \";\nconst template = `/*# sourceMappingURL=template.map */`;\n//# sourceMappingURL=real.map",
    "const value: number = 1;\n//# sourceMappingURL=typed.map",
    "const view = <div />;\n//# sourceMappingURL=typed.map",
    "const value = 1; /*@ sourceMappingURL=typed.map */",
    "const text = `${(() => { /*# sourceMappingURL=typed.map */ return 1; })()}`;",
    "const value = ;\n//# sourceMappingURL=unparsed.map",
    "\u{feff}//# sourceMappingURL=bom.map",
    "x();//# sourceMappingURL=\u{e9}\u{1F600}.map\ny();",
    "/*# sourceMappingURL=a\r\nb.map */",
    "/*#\u{2029}sourceMappingURL=a.map */",
    "//# sourceMappingURL=a.map\u{2028}b.map",
];
