//! Static path recovery: `path.join`/`path.resolve`, `URL`/`fileURLToPath`, consumed through
//! generic `preload` properties, BrowserWindow web preferences and `utilityProcess.fork`.

pub fn snippets() -> Vec<(String, String)> {
    let mut expressions: Vec<String> = Vec::new();
    // REA: javascriptStaticPathResolution
    let absolute_parts: [&[&str]; 7] = [
        &["/app", "/shared/preload.js"],
        &["ignored", "/app", "preload.js"],
        &["/app", "first", "/shared", "nested", "../preload.js"],
        &["/app", "preload///"],
        &["/app", "../../.."],
        &["///"],
        &["", "/app", "", "preload.js", ""],
    ];
    for parts in absolute_parts {
        let rendered = parts.iter().map(|part| serde_json::to_string(part).unwrap()).collect::<Vec<_>>().join(", ");
        expressions.push(format!("path.posix.resolve({rendered})"));
        expressions.push(format!("path.join({rendered})"));
        expressions.push(format!("path.posix.join({rendered})"));
    }
    expressions.extend(
        [
            r#"path.resolve(__dirname, "preload.cjs")"#,
            r#"path.posix.resolve("ignored", __dirname, "preload.js")"#,
            r#"path.resolve("/ignored", __dirname, "preload.js")"#,
            r#"path.posix.resolve("ignored", dirname(fileURLToPath(import.meta.url)), "preload.js")"#,
            r#"path.resolve("ignored", path.dirname(__filename), "preload.js")"#,
            r#"path.resolve(__dirname, "../preload.js")"#,
            r#"path.resolve(__dirname, "sub", __dirname, "preload.js")"#,
            r#"path.resolve(__dirname, "/shared", "preload.js")"#,
            "path.resolve(__dirname)",
            r#"path.posix.resolve(`/app`, `/shared`, "preload.js")"#,
            r#"path.posix.resolve("" + "/app", "preload.js")"#,
            r#"path.join("/app", "/shared/preload.js")"#,
            r#"path.posix.join("/app", "preload/")"#,
            r#"path.join("sub", "../preload.js")"#,
            r#"path.join(__dirname, "preload.js")"#,
            r#"path.join("ignored", __dirname, "preload.js")"#,
            r#"path.join(dirname(fileURLToPath(import.meta.url)), "preload.js")"#,
            r#"join("sub", "preload.js")"#,
            "path.resolve()",
            "path.posix.resolve()",
            r#"path.resolve("sub", "../preload.js")"#,
            r#"path.resolve("", "")"#,
            r#"path.resolve(runtimeBase, "/app/preload.js")"#,
            r#"path.resolve("/app", runtimeFile)"#,
            r#"path.resolve(runtimeBase, __dirname, "preload.js")"#,
            "path.resolve(__dirname, runtimeFile)",
            r#"path.resolve(...parts, "/app/preload.js")"#,
            r#"path.resolve("/app", ...parts)"#,
            r#"path.resolve(42, "/app/preload.js")"#,
            r#"path.resolve("/app", null)"#,
            "path.resolve(`/app/${runtimeFile}`)",
            r#"path.win32.resolve("/app", "/shared/preload.js")"#,
            r#"path.win32.resolve(__dirname, "preload.js")"#,
            r#"win32.resolve("/app", "preload.js")"#,
            r#"resolve("/app", "preload.js")"#,
            "path.join()",
            "path.join(__dirname)",
            r#"path.join("/app", runtimeFile)"#,
            "path.join(...parts)",
            // misc shapes
            r#"__dirname + "/preload.js""#,
            r#"__dirname + path.sep + "preload.js""#,
            r#""./" + name"#,
            r#"`./a` + "b""#,
            r#"path.join(__dirname, "..", "..", "x.js")"#,
            r#"path.join("a//b", "./c", "../d/")"#,
            r#"path.join("é", "..", "ü/ß", "..")"#,
            r#"path.join("\u{1F600}", "..", "..", "x")"#,
            r#"path.resolve(__dirname, "\u{e9}", "..", "\u{e9}", "p.js")"#,
            r#"path.resolve("/\u{1F600}/a", "..", "..", "..")"#,
            r#"app.path.join(__dirname, "p")"#,
            r#"fileURLToPath(import.meta.url)"#,
            r#"fileURLToPath(new URL("./p.js", import.meta.url))"#,
            r#"fileURLToPath("file:///abs/p.js")"#,
            r#"fileURLToPath(`file:///t.js`)"#,
            r#"url.fileURLToPath(new URL("./p.js", import.meta.url))"#,
            r#"fileURLToPath(new URL("./p.js", import.meta.url).href)"#,
            r#"new URL("./p.js", import.meta.url)"#,
            r#"new URL("./p.js", import.meta.url).pathname"#,
            r#"url.URL("./p.js", import.meta.url)"#,
            r#"path.dirname(__filename)"#,
            r#"path.dirname(fileURLToPath(import.meta.url))"#,
            r#"dirname(import.meta.url)"#,
            r#"path.join(path.dirname(fileURLToPath(import.meta.url)), "p.js")"#,
            r#"path.resolve(fileURLToPath(new URL(".", import.meta.url)), "p.js")"#,
            r#"path.join(fileURLToPath(new URL("./a", import.meta.url)), "b")"#,
            r#"fileURLToPath(new URL(import.meta.url))"#,
            r#"new URL(import.meta.url)"#,
            r#"path.resolve(new URL("./z.js", import.meta.url).pathname)"#,
        ]
        .map(str::to_string),
    );
    // REA: JavaScriptFileUrlPaths
    for reference in [
        "./preload%20name.cjs",
        "./pr%C3%A9load.cjs",
        "./preload%3F%23.cjs",
        "./preload.cjs?cache=1#v2",
        "../preload.cjs?cache=1",
        "./sub/../preload.cjs",
        "./preload.cjs",
        "preload.cjs",
        "../../../deep/up/p.cjs",
        "/abs/p.cjs",
        "/abs/../p.cjs",
        "./a/./b//c.cjs",
        "./sp ace.cjs",
        "./\u{e9}\u{1F600}.cjs",
        "./%E0%A4%A.cjs",
        "./%FF.cjs",
        "./%00.cjs",
        "./100%.cjs",
        "./a%2Fb.cjs",
        "./a%5Cb.cjs",
        "./%2e/p.cjs",
        "./%2E%2e/p.cjs",
        "./a/%2e%2e/p.cjs",
        "invalid%.cjs",
        "./invalid%.cjs",
        "https://example.test/preload.cjs",
        "//example.test/preload.cjs",
        "#fragment",
        "?cache=1",
        "",
        ".",
        "./",
        "..",
        "../",
        " ./p.cjs",
        "./p.cjs ",
        "./p\\q.cjs",
        "./p\tq.cjs",
        "C:/x/p.cjs",
        "c:p.cjs",
        "a:b/c.cjs",
        "\u{17f}:x",
        "./p.cjs#",
        "./p.cjs?",
        "./?a=%zz#b",
        "./a?/../b",
        "x/../../y",
        "./a\u{feff}",
        "\u{feff}./a",
        "\u{85}./a",
        "./a\u{85}",
        "./\u{2028}p.cjs",
        "./%25.cjs",
        "./%2F.cjs",
        "./%2f",
        "./a%252fb.cjs",
        "./~user/p.cjs",
        "./a;b=c/p.cjs",
        "./a|b.cjs",
        "|/p.cjs",
        "./a:b.cjs",
        "./[x]/{y}.cjs",
        "./a b%20c.cjs",
        "/",
        "//",
        "///x",
        "./\u{200b}p.cjs",
    ] {
        let reference = serde_json::to_string(reference).unwrap();
        expressions.push(format!("fileURLToPath(new URL({reference}, import.meta.url))"));
        expressions.push(format!("url.fileURLToPath(new URL({reference}, __filename))"));
    }
    for expression in [
        r#"fileURLToPath(new URL("./preload.cjs", runtimeBase))"#,
        "fileURLToPath(new URL(runtimePath, import.meta.url))",
        r#"convertFileURLToPath(new URL("./preload.cjs", import.meta.url))"#,
        r#"fileURLToPath(new URL("./p.cjs", import.meta.url), { windows: true })"#,
        r#"fileURLToPath(new URL("./p.cjs", pathToFileURL(__filename)))"#,
        r#"path.join(__dirname, "preload%20?#.cjs")"#,
        "fileURLToPath(new URL(`./tpl.cjs`, import.meta.url))",
        "fileURLToPath(new URL((\"./p\" + \".cjs\"), import.meta.url))",
        "fileURLToPath(new URL(\"./p.cjs\", import.meta.url, extra))",
        "fileURLToPath(new URL(\"./p.cjs\", (import.meta.url)))",
        "fileURLToPath(new URL(\"./p.cjs\", import.meta[\"url\"]))",
        "fileURLToPath(new URL(\"./p.cjs\", import.meta.URL))",
        "fileURLToPath(new URL(\"./p.cjs\", import.meta['url']))",
    ] {
        expressions.push(expression.to_string());
    }

    let mut out: Vec<(String, String)> = Vec::new();
    for (index, expression) in expressions.iter().enumerate() {
        let property = format!("preload: {expression}");
        let source = format!(
            "const options = {{ {property} }};\nnew BrowserWindow({{ webPreferences: {{ {property} }} }});\nutilityProcess.fork({expression});\n"
        );
        out.push((format!("path_{index:03}.js"), source));
    }
    out
}
