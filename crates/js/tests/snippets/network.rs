//! References, endpoints, storage, workers, routes, sanitization.

use super::named;

pub fn snippets() -> Vec<(String, String)> {
    let mut out = named("network_fixed_", FIXED);
    out.extend(endpoint_sweep());
    out.extend(storage_sweep());
    out.extend(reference_sweep());
    out.extend(sanitize_sweep());
    out
}

const FIXED: &[&str] = &[
    // REA: JavaScriptOpenClassification
    r#"
      const popup = window;
      popup.open(url, "/preview");
      {
        const indexedDB = { open() {} };
        indexedDB.open("PROPFIND", "/dav");
        indexedDB.open(databaseName, "2");
      }
      const xhr = new XMLHttpRequest();
      xhr.open(method, "/api");
      parent.open("GET", "/parent-target");
      self.open("POST", "/self-target");
      document.open("GET", "/document-target");
      {
        const parent = new XMLHttpRequest();
        parent.open(method, "/shadowed-parent");
      }
      indexedDB.open("records", "2");
    "#,
    r#"
      const req = new XMLHttpRequest();
      req.open("GET", "/a"); req.open("get", "/b"); req.open("PROPFIND", "/c"); req.open("Weird", "/d");
      req.open(m, "/e"); req.open(m, "_blank"); req.open(m, "w"); req.open(m, "r+"); req.open(m, "http://x/y");
      window.open("/w"); window.open("/w", "_blank"); top.open("/t", "x"); globalThis.open("/g"); open("/bare");
      fs.open("/tmp/f", "r"); fs.open(path, "w+"); fs.promises.open("/p", "a");
      indexedDB.open("db", 3); caches.open("cache"); window.indexedDB.open("db2"); self.caches.open("c2");
    "#,
    r#"
      const w1 = window; w1.open("/p1"); const w2 = globalThis; w2.open("GET", "/p2");
      let idb = indexedDB; idb.open("name", "GET"); idb.open("name", 5);
      const c = caches; c.open("k"); const cs = window.caches; cs.open("k2");
      function f(indexedDB) { indexedDB.open("param", "/x"); }
      class K { m() { this.indexedDB.open("m", "/y"); } }
    "#,
    // storage
    r#"
      localStorage.setItem("a", 1); localStorage.getItem("a"); window.localStorage.removeItem("b");
      sessionStorage.setItem("s", 2); globalThis.sessionStorage.clear(); localStorage[key]; localStorage.getItem(k);
      const db = new Database("file.sqlite"); new sqlite3.Database(path); new Database(); Database("x");
      const local = { localStorage: { setItem() {} } }; local.localStorage.setItem("q", 1);
    "#,
    // routes / properties
    r#"
      router.route("/users"); app.addRoute({}); useRoutes(routes); createBrowserRouter("/x"); createHashRouter(`/h`);
      const routes = [{ path: "/home" }, { route: "/r" }, { path: `/tpl` }, { path: x }, { "path": "/quoted" }, { ["path"]: "/computed" }, { path() {} }];
      app.route("/a").get(h); app.get("/b", h); axios.post("/c", d); http.request("/d"); superagent.delete("/e");
    "#,
    // references
    r#"
      import a from "./a.js"; import "./side.js"; export * from "./b.js"; export { c } from "./c.js"; export { a as d };
      import("./dyn.js"); import(name); import(`./tpl${x}.js`); import("./one" + "two.js"); await import(`./plain.js`);
      require("./r.js"); require(name); require(`./t.js`); require(1); require.resolve("./res.js"); module.require("./m.js");
      new Worker("./w.js"); new Worker(url); new Worker(new URL("./w2.js", import.meta.url)); new SharedWorker("./sw.js"); new worker_threads.Worker("./wt.js");
      navigator.serviceWorker.register("/sw.js"); serviceWorker.register(); navigator.serviceWorker.register(`/t.js`, { scope: "/" });
    "#,
    r#"
      function f(__webpack_require__) { __webpack_require__("./x"); __webpack_require__.e("chunk"); __webpack_require__.bind(null, 5); }
      __webpack_require__(12); __webpack_require__("str"); __webpack_require__.e(7); __webpack_require__.e(name); __webpack_require__.bind(null, "m"); __webpack_require__.bind();
      __webpack_require__.t(1, 2); __webpack_require__.r(exports); __webpack_require__.d(exports, {});
    "#,
    // vite preload map
    r#"
      const __vite__mapDeps = (i, m = __vite__mapDeps, d = (m.f || (m.f = ["assets/a.js", 'assets/b.css', "assets/with\"quote.js", "assets/c.js"]))) => i.map((i) => d[i]);
      import("./x.js", __vite__mapDeps([0, 1])); __vite__mapDeps([2, 3, 9]); __vite__mapDeps([0, x]); __vite__mapDeps(i); __vite__mapDeps([0.5, -1, 1e3]);
    "#,
    r#"
      const f = (m.f||(m.f=['one', "two"])); __vite__mapDeps([1, 0]); x.f = ["no", "match"]; __vite__mapDeps([]);
    "#,
    // top-level await style imports and TS type-only
    "import type { T } from './types'; import { type U, u } from './u'; export type { V } from './v'; import('./typed').then((m) => m.x as number); import x = require('./eq');",
];

fn endpoint_sweep() -> Vec<(String, String)> {
    let callees = [
        "fetch", "window.fetch", "self.fetch", "xfetch", "WebSocket", "new WebSocket", "axios", "axios.get", "axios.post", "axios.delete", "$.get",
        "http.request", "request", "got.put", "api.patch", "client.get", "this.http.get", "headers.get", "searchParams.delete", "form.get", "map.get", "params.get",
        "win.loadURL", "mainWindow.webContents.loadURL", "loadURL", "xhr.open", "req.open", "window.open", "x.open",
    ];
    let args = [
        r#""/api/users""#, r#""https://api.example.com/v1/x?token=abc""#, r#""//cdn.example.com/lib.js""#, r#""./relative""#, r#""../up""#, r#""key""#, r#""ws://host/s""#, r#""WSS://HOST/s""#, r#""HTTP://Host/p""#,
        r#"`/tpl`"#, r#"`/tpl/${id}`"#, r#"url"#, r#"("/paren")"#, r#""GET", "/with-method""#, r#""POST", "https://u:p@example.com/x""#, r#""user:pw@host/path""#,
        r#""https://user:pass@example.com:8080/a b?q=1#frag""#, r#""https://exa mple.com/""#, r#""http://[::1]/x""#, r#""http://[bad/x""#, r#""data:text/plain,hi""#, r#""file:///etc/hosts""#, r#""mailto:a@b.c""#, "",
    ];
    let mut sources = Vec::new();
    for callee in callees {
        for arg in args {
            sources.push(format!("{callee}({arg});"));
        }
    }
    // keyed collection receivers
    for receiver in ["new Headers()", "new FormData()", "new URLSearchParams(x)", "new Map()", "new Set()", "new WeakMap()", "new Foo()", "req.headers", "url.searchParams", "obj.other", "a.b.headers", "x[\"headers\"]", "x[h]"] {
        for method in ["get", "delete", "post", "request"] {
            for arg in [r#""content-type""#, r#""/path""#, r#""https://h/x""#, r#""./rel""#] {
                sources.push(format!("{receiver}.{method}({arg});"));
            }
        }
    }
    sources
        .chunks(16)
        .enumerate()
        .map(|(index, chunk)| (format!("endpoint_{index:03}.js"), chunk.join("\n")))
        .collect()
}

fn storage_sweep() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for object in ["localStorage", "window.localStorage", "sessionStorage", "self.sessionStorage", "xlocalStorage", "indexedDB", "window.indexedDB", "caches", "self.caches", "Database", "sqlite.Database", "db.Database"] {
        for method in ["", ".open", ".setItem", ".getItem"] {
            for arg in [r#""name""#, "", "x", r#""name", 2"#] {
                let call = if object.ends_with("Database") && method.is_empty() {
                    format!("new {object}({arg});")
                } else {
                    format!("{object}{method}({arg});")
                };
                sources.push(call);
            }
        }
    }
    sources
        .chunks(10)
        .enumerate()
        .map(|(index, chunk)| (format!("storage_{index:03}.js"), chunk.join("\n")))
        .collect()
}

fn reference_sweep() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for callee in ["require", "x.require", "module.require", "__webpack_require__", "Worker", "new Worker", "a.Worker", "serviceWorker.register", "navigator.serviceWorker.register", "__vite__mapDeps"] {
        for arg in [r#""./m""#, "`./t`", "1", "1.5", "name", "...a", r#""a", "b""#, "", "(0, x)", r#"("p")"#, "-1", "0x10", "1e21", "1_000"] {
            sources.push(format!("{callee}({arg});"));
        }
    }
    sources
        .chunks(15)
        .enumerate()
        .map(|(index, chunk)| (format!("reference_{index:03}.js"), chunk.join("\n")))
        .collect()
}

fn sanitize_sweep() -> Vec<(String, String)> {
    let urls = [
        "https://user:pass@example.com/path", "https://user@example.com/path", "https://:pass@example.com/path", "//user:pass@example.com/x", "http://u:p@[::1]:80/x", "HTTP://U:P@EXAMPLE.COM/",
        "https://user:pass@example.com", "https://user:pa@ss@example.com/p", "https://us%40er:pa%3Ass@example.com/p", "ws://u:p@h/", "ftp://u:p@h/f", "git+ssh://u:p@h/r", "https://u:p@h/?a=b@c", "https://u:p@h#f@g",
        "https://example.com/a b", "https://EXAMPLE.com:443/", "http://example.com:80/", "http://xn--bcher-kva.example/", "http://bücher.example/", "http://example.com/%7Euser", "http://example.com/./a/../b", "http://example.com/?q=%zz",
        "https://u:p@@h/", "https://u:p@h:bad/", "https://\\u:p@h/", "/rel/path", "mailto:u:p@h.com",
    ];
    let mut sources = Vec::new();
    for url in urls {
        sources.push(format!("fetch({});", serde_json::to_string(url).unwrap()));
        sources.push(format!("axios.get({});", serde_json::to_string(url).unwrap()));
    }
    sources
        .chunks(9)
        .enumerate()
        .map(|(index, chunk)| (format!("sanitize_{index:03}.js"), chunk.join("\n")))
        .collect()
}
