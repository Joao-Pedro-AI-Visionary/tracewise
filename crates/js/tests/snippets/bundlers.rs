//! Webpack/Rspack chunk registrations, esbuild wrappers, module attribution, export names.

use super::named;

pub fn snippets() -> Vec<(String, String)> {
    let mut out = named("bundler_fixed_", FIXED);
    out.extend(runtime_sweep());
    out.extend(large_tables());
    out.extend(export_shapes());
    out
}

const FIXED: &[&str] = &[
    // REA: javascriptStaticAnalysis.no_finding_caps / locations
    r#"
      const push = "push";
      const arr = {};
      arr[push]([[1], { 1: function () {} }]);
    "#,
    r#"
      (globalThis.webpackChunkLeft || globalThis.webpackChunkRight).push([[1], { 1: function() {} }]);
      globalThis.webpackChunkOuter.webpackChunkInner.push([[2], { 2: function() {} }]);
    "#,
    r#"(globalThis.webpackChunkApp satisfies unknown).push([[1], { "entry": function () {} }]);"#,
    r#"(globalThis.webpackChunkApp as any).push([[1], { "entry": function () {} }]); (<any>self.webpackChunkB!).push([[2], { b: () => {} }]);"#,
    r#"
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[179], {
        7: (e, t, n) => { "use strict"; n.r(t), n.d(t, { default: () => r, named: () => i }); var r = n(9), i = n.e(42).then(n.bind(n, 5)); },
        "str-key": function (e, t, n) { e.exports = n(7); },
        9() { return 1; },
        [computed]: function () {},
        ["lit"]: function () {},
        ...spread,
        11: 5,
        get 12() { return 1; },
        13: async function* () {},
        0x14: function () {},
        1.5: function () {},
        "": function () {},
        [`tpl`]: function () {},
      }, (e) => { var t = (t) => e(e.s = t); e.O(0, [1, 2], () => t(100)), t(100); e.e(3); e.e(x); e.e("named"); }]);
    "#,
    r#"
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[1], {}, function (n) { n.s = 1; }]);
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[1], {}, function (n) { n.s = 1; }]);
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[2, , "s", 3, 3, x], { 2: (a, b, req) => { req("dep"); req.e("lazy"); req.e(5); req.e(5); } }, 5]);
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[3], { 3: (a, b) => { __webpack_require__("global"); } }, () => {}]);
      (self.webpackChunkapp = self.webpackChunkapp || []).push([[4], { 4: (a, b, req) => { req.bind(null, "bound"); req(req.e("a")); } }, ({ x }) => {}]);
    "#,
    r#"
      var __webpack_module_cache__ = {};
      (self.rspackChunkapp = self.rspackChunkapp || []).push([["main"], { "m": function (module, exports, __webpack_require__) { __webpack_require__("x"); } }]);
      (window.RspackChunk = []).push([[1], { 1: () => {} }]); window["webpackChunk" + name].push([[1], { 1: () => {} }]);
    "#,
    r#"
      var installedModules = {};
      webpackChunk.push([[1], { 1: () => {} }]); self.webpackChunk_foo.push([1, { 1: () => {} }]); self.webpackChunk_bar.push([[1], x]); self.webpackChunk_baz.push([x, {}]);
      self.webpackChunk_q.push(); self.webpackChunk_q.push([]); self.webpackChunk_q.push([[1]]); self.webpackChunk_q.push([[1], {}, null]);
    "#,
    r#"
      var installedModulesX = 1; var xinstalledModules = 2; var __webpack_module_cache__x = 3;
      self.webpackChunk_z.push([[1], { 1: (a, b, c, d) => {} }, "str"]);
    "#,
    // esbuild
    r#"
      var require_a = __commonJS({ "src/a.js"(exports, module) { module.exports = { a: 1 }; exports.b = 2; } });
      var init_b = __esm({ "src/b.js"() { init_a(); } });
      var x = __commonJS({ "src/c.js": function (exports2, module2) { module2.exports.z = 1; Object.defineProperty(exports2, "d", { value: 1 }); exports2.d(1); } });
      __esm({}); __commonJS({}); __commonJS(); __commonJS(x); a.__commonJS({ "k"() {} }); a.__esm({ "k": () => {}, "j": 1 });
    "#,
    r#"
      var f = __commonJS({ "m"(exports, module) { __require("x"); require("y"); import("z"); new Worker("w.js"); } }); var f = __commonJS({ "m"(exports, module) { __require("x"); require("y"); import("z"); new Worker("w.js"); } });
    "#,
    // module attribution
    r#"
      require("outside");
      globalThis.webpackChunkApp.push([[1], {
        "module-0": function(module, exports, req) { globalThis.webpackChunkInner.push([[2], { "inner": function(innerModule, innerExports, req) { req("nested-dependency"); } }]); req("dependency-0"); },
        "module-1": function(module, exports, req) { req("dependency-1"); fetch("/in-module"); localStorage.getItem("k"); new BrowserWindow({}); import("./dyn"); },
        "module-2": (module, exports, req2) => { req2("dep2"); req("dep2b"); },
      }]);
      require("after");
    "#,
    // exports shapes
    r#"
      globalThis.webpackChunkApp.push([[1], {
        1: function(e, t) { e.exports = { a: 1, "b": 2, 3: 4, [c]: 5, d() {}, get e() { return 1; }, ...f }; },
        2: function(e, t) { e.exports = function () {}; t.x = 1; t["y"] = 2; t[z] = 3; exports.w = 4; module.exports.v = 5; this.u = 6; },
        3: function(e, t, n) { n.d(t, { A: () => a, B: function () {} }); n.d(exports, { C: 1 }); n.d(); n.d(t); n.d(t, x); },
        4: function(e, t) { Object.defineProperty(t, "__esModule", { value: true }); Object.defineProperty(exports, "q", { get: () => 1 }); Object.defineProperty(t, name, {}); Object.defineProperty(t, "", {}); },
        5: function(e, t) { exports = module.exports = { z: 1 }; module.exports = foo; exports.default = 1; exports["default"] = 2; exports[""] = 3; },
      }]);
    "#,
];

fn runtime_sweep() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    let runtimes = [
        "self.webpackChunkapp",
        "globalThis.webpackChunk_N_E",
        "window.rspackChunk_x",
        "(self.webpackChunkapp = self.webpackChunkapp || [])",
        "(window.a = window.b = window.webpackChunkapp)",
        "self[\"webpackChunkapp\"]",
        "self[name]",
        "self[`webpackChunkapp`]",
        "(a, self.webpackChunkapp)",
        "(a && self.webpackChunkapp)",
        "(a ?? self.webpackChunkapp)",
        "self.webpackChunkapp.push.bind(self.webpackChunkapp)",
        "self.WEBPACKCHUNK",
        "self.webpackchunk",
        "self.RSPACKchunk",
        "self.\u{212a}x.webpackChun\u{212a}",
    ];
    let entries = [
        "[[1], { 1: function(){} }]",
        "[[1, \"a\", x], { 1: function(){} }, function(r){ r.s = 1; r(1); r.e(2); r.e(\"n\"); }]",
        "[[\"a\"], { \"a\": () => {}, \"b\": function(){}, \"c\"() {} }, (r) => { r(\"a\"); }]",
        "[[1], { 1: function(){} }, 5]",
        "[[1], { 1: function(){} }, , 9]",
        "[[1], { 1: function(){} }, function(...r){ r[0](1); }]",
        "[[1], { 1: function(){} }, function({ a }){ }]",
        "[[1], { 1: function(){} }, function(r, x){ r.e(1); r.e(1); r.e(2); r(5); r(\"s\"); r(x); }]",
        "[[1], { 1: function(a, b, c){ c.e(7); c.e(8); c(1); } }]",
        "[[1], { 1: function(a, b, c){ c.e(7); } , 2: function(a, b, c){ c.e(7); c.e(y); } }]",
        "[[1,2,3], { 2: function(){ } , 1: function(){ }, 10: function(){}, 9: function(){} }]",
        "[[1], {}]",
        "[[], { a: function(){} }]",
        "[[1.5, -0, 1e21, 0x10], { 1: function(){} }]",
    ];
    for runtime in runtimes {
        for entry in entries {
            sources.push(format!("{runtime}.push({entry});"));
        }
    }
    sources
        .chunks(7)
        .enumerate()
        .map(|(index, chunk)| (format!("runtime_{index:03}.js"), chunk.join("\n")))
        .collect()
}

fn large_tables() -> Vec<(String, String)> {
    // REA: attribution across many real factory ranges.
    let factories = (0..200)
        .map(|index| {
            if index == 0 {
                "\"module-0\": function(module, exports, req) { globalThis.webpackChunkInner.push([[2], { \"inner\": function(innerModule, innerExports, req) { req(\"nested-dependency\"); } }]); req(\"dependency-0\"); }".to_string()
            } else {
                format!("\"module-{index}\": function(module, exports, req) {{ req(\"dependency-{index}\"); }}")
            }
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let attribution = format!("require(\"outside\");\nglobalThis.webpackChunkApp.push([[1], {{\n{factories}\n}}]);");
    // REA: member path depth.
    let chain = ".next".repeat(12_000);
    let ordinary = ".next".repeat(64);
    // REA: 10,001-key literals.
    let names: Vec<String> = (0..10_001).map(|index| format!("key{index}")).collect();
    let mut caps: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(index, name)| format!("import value{index} from \"./{name}.js\";"))
        .collect();
    caps.push(format!(
        "new BrowserWindow({{ webPreferences: {{ {} }} }});",
        names.iter().map(|name| format!("{name}: true")).collect::<Vec<_>>().join(", ")
    ));
    caps.push(format!(
        "contextBridge.exposeInMainWorld(\"api\", {{ {} }});",
        names.iter().map(|name| format!("{name}: () => true")).collect::<Vec<_>>().join(", ")
    ));
    caps.push(format!("const {{ {} }} = require(\"./addon.node\");", names.join(", ")));
    vec![
        ("large_attribution.js".into(), attribution),
        ("large_member_chain.js".into(), format!("exports{chain}.last = 1;")),
        (
            "large_member_misc.js".into(),
            "exports[\"\"].value = 1;\nexports[\"\"] = 0;\nexports[key].value = 2;\nthis.exports.ignored = 3;\nclass Example { #private = 0; read() { this.#private = 1; } }\n".into(),
        ),
        (
            "large_runtime_chain.js".into(),
            format!("globalThis.webpackChunkApp{ordinary}.push([[1], {{ 1: function(module) {{ module.exports.ok = 42; }} }}]);"),
        ),
        ("large_caps.js".into(), caps.join("\n")),
    ]
}

fn export_shapes() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for left in ["exports", "module.exports", "exports.a", "module.exports.a", "this.exports", "exports.a.b", "exports[\"q\"]", "exports[k]", "module[\"exports\"]", "exports?.x", "(exports).y", "exports.a?.b", "a.exports", "module.exports.default"] {
        for right in ["1", "{ a: 1, \"b\": 2, 3: 4, [c]: 5, d() {}, ...e }", "function () {}", "{}", "x", "{ get g() { return 1; }, set s(v) {} }"] {
            sources.push(format!("{left} = {right};"));
        }
    }
    for call in [
        "Object.defineProperty(exports, \"a\", {})",
        "Object.defineProperty(module.exports, \"b\", {})",
        "Object.defineProperty(exports, \"\", {})",
        "Object.defineProperty(exports, k, {})",
        "Object.defineProperty(this, \"c\", {})",
        "n.d(exports, { a: 1, b() {}, \"c\": 2, [d]: 3, ...e })",
        "r.d(module.exports, { z: () => 1 })",
        "foo.bar.d(exports, { y: 1 })",
        "d(exports, { x: 1 })",
        "n.d(exports, x)",
        "n.d(a, { w: 1 })",
        "x.d()",
    ] {
        sources.push(format!("{call};"));
    }
    // each source wrapped as the body of a webpack factory so exports are reported
    sources
        .chunks(6)
        .enumerate()
        .map(|(index, chunk)| {
            let body = chunk.join(" ");
            (
                format!("exports_{index:03}.js"),
                format!("self.webpackChunkx.push([[{index}], {{ f: function (module, exports, n) {{ {body} }}, g: (exports, module) => {{ {body} }} }}]);\n{body}\n"),
            )
        })
        .collect()
}
