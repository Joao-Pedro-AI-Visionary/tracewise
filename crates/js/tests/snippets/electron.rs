//! Electron windows, preload, contextBridge, IPC, sender validation, utility processes, native addons.

use super::named;

pub fn snippets() -> Vec<(String, String)> {
    let mut out = named("electron_fixed_", FIXED);
    out.extend(native_addons());
    out.extend(window_options());
    out.extend(context_bridge());
    out.extend(ipc());
    out.extend(validation());
    out.extend(utility());
    out.extend(renamed_roots());
    out
}

const FIXED: &[&str] = &[
    // REA: native addon loader provenance
    r#"
      const required = require("./addon.node#literal.node");
      module.exports = require("./addon.node#literal.node");
      import imported from "./addon.node#literal.node";
      export { default } from "./addon.node#literal.node";
    "#,
    r#"
      const script = require("./addon.node#helper.js");
      import native from "./addon.node#helper.js";
    "#,
    r#"
      const script = require("./addon.node?helper.js");
      import native from "./addon.node?helper.js";
    "#,
    // REA: Electron option evidence
    r#"
      new BrowserWindow({ webPreferences: { preload: "./kept.js", sandbox: true }, title: "App" });
      utilityProcess.fork("./worker.js", [], { serviceName: "kept", cwd: "/app" });
    "#,
    r#"
      jsx("audio", { controls: true, preload: "metadata", src });
      (0, React.createElement)(`video`, { preload: "auto" });
      jsx("webview", { preload: "./guest.js" });
      const options = { preload: "./preload.js" };
    "#,
    r#"
      new BrowserWindow({ webPreferences: { preload: "./maybe.js" }, [key]: null });
      utilityProcess.fork("./worker.js", [], { serviceName: "maybe", [key]: null });
    "#,
];

fn native_addons() -> Vec<(String, String)> {
    let sources = [
        r#"const a = require("./a.node"); const { x, y: z, ["w"]: w, [dyn]: d, ...rest } = require("./b.node");"#,
        r#"const m = require("./a.node").member; const n = require("./a.node")[k]; const o = require("./a.node")["lit"];"#,
        r#"const deep = require("./a.node").one.two;"#,
        r#"module.exports = require("./a.node"); exports.x = require("./b.node"); module.exports.y = require("./c.node").q;"#,
        r#"exports = require("./a.node"); module.foo = require("./a.node"); this.exports = require("./a.node"); obj.exports = require("./a.node");"#,
        r#"import a from "./a.node"; import * as ns from "./b.node?x#y"; import { p, q as r, "str" as s } from "./c.NODE"; import "./d.node"; import def, { e } from "./e.node";"#,
        r#"export { a, b as c } from "./a.node"; export * from "./b.node"; export * as ns from "./c.node"; export { default } from "./d.node"; export { default as e } from "./e.node"; export v, { w } from "./f.node"; export {} from "./g.node";"#,
        r#"const addon = __webpack_require__("./native/addon.node"); const { b } = __webpack_require__(123);"#,
        r#"const a = require(`./tpl.node`); const b = require("./" + name + ".node"); const c = require(name);"#,
        r#"var a = require("./a.node"), b = require("./a.node"), c = require("./b.node"); let { a: aa } = require("./a.node");"#,
        r#"const x = require("./a.node"); const y = require("./a.node");"#,
        r#"const { ["a\0b"]: q, 'a': r } = require("./z.node"); const { a: s } = require("./z.node");"#,
        r#"const [first] = require("./arr.node"); let plain; plain = require("./plain.node");"#,
        r#"const maybe = require?.("./opt.node"); const viaBind = require.bind(null, "./bind.node");"#,
        r#"const m = (0, require)("./seq.node"); const n = (require("./paren.node")).member;"#,
        r#"const a = foo.require("./foo.node"); const b = a.b.require("./bar.node").x.y;"#,
        r#"module.exports = { addon: require("./obj.node") };"#,
        r#"const t = require("./a.node") as any;"#,
        "import native from './ts.node'; const x = require('./ts.node') as Native;\nexport = require('./eq.node');",
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("native_{index:03}.ts"), (*source).to_string()))
        .collect()
}

fn window_options() -> Vec<(String, String)> {
    let sources = [
        r#"new BrowserWindow(); new BrowserWindow(opts); new BrowserWindow({}); new BrowserWindow({ webPreferences });"#,
        r#"new BrowserWindow({ webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: false, webSecurity: -1, zoomFactor: 1.5, spellcheck: null, devTools: !0 } });"#,
        r#"new BrowserWindow({ webPreferences: { ...base, preload: "./p.js" } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: "./p.js", ...base } });"#,
        r#"new BrowserWindow({ webPreferences: { [k]: 1, "quoted-key": 2, 3: 4, method() {}, get g() { return 1; }, async *gen() {} } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: "./a.js", preload: "./b.js" } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: "./a.js" }, webPreferences: { preload: "./b.js" } });"#,
        r#"new BrowserWindow({ webPreferences: cond ? { preload: "x" } : {} });"#,
        r#"new BrowserWindow({ ...rest, webPreferences: { preload: "./late.js" } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: "./a.js" }, ...rest });"#,
        r#"new BrowserWindow({ "webPreferences": { "preload": `./tpl.js` } }); new BrowserWindow({ ["webPreferences"]: { preload: "c" } });"#,
        r#"new electron.BrowserWindow({ webPreferences: { preload: __dirname + "/p.js" } }); new remote.BrowserWindow({}); new BrowserWindow2({});"#,
        r#"new BrowserWindow({ webPreferences: { preload: `${dir}/p.js`, a: `lit`, b: `x${y}`, c: "s".length, d: [1], e: {a: 1}, f: -x, g: -0, h: -5, i: +3, j: 10n, k: 1e999, l: /re/g, m: null, n: undefined, o: this, p: (1), q: void 0 } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: path.resolve(__dirname, "p.js") } });"#,
        r#"new BrowserWindow({ webPreferences: { preload: "\n  padded  \n", a: "  ", b: "" } });"#,
        "new BrowserWindow({ webPreferences: { a: \u{1F600}x, b: `\u{e9}`, c: \"\u{2028}\" } });",
        r#"win = new BrowserWindow({ width: 800 }); win.loadURL("https://example.com/app?x=1#h"); win.loadFile("index.html"); win.loadFile(path.join(__dirname, "i.html")); win.loadURL(`http://localhost:3000`); win.loadURL(url);"#,
        r#"mainWindow.loadFile("a.html"); mainWindow.loadFile("a.html"); other.loadFile("a.html"); w.loadURL("file:///a.html"); w.loadURL("data:text/html,<p>x</p>");"#,
        r#"const o = { preload: "./one.js" }; const p = { preload: "./one.js" }; const q = { "preload": `./two.js`, ["preload"]: "./three.js" }; const { preload } = cfg; const { preload: pre = "./d.js" } = cfg;"#,
        r#"const o = { preload: __dirname + "/p.js", preload2: "x" }; const p = { preload: path.join(__dirname, "..", "p.js") }; const r = { preload: "/abs/p.js" }; const s = { preload: "http://x/p.js" };"#,
        r#"const o = { preload: "a" + "b" + `c` }; const p = { preload: "a" + x }; const q = { preload: `a${x}` }; const r = { preload: 1 + 2 };"#,
        r#"jsx("audio", { preload: "a" }); createElement("video", { ...p, preload: "b" }); jsx("audio"); jsx("video", props); jsx("audio", { ["preload"]: "none" }); jsx("audio", { preload() {} });"#,
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("window_{index:03}.js"), (*source).to_string()))
        .collect()
}

fn context_bridge() -> Vec<(String, String)> {
    let sources = [
        r#"contextBridge.exposeInMainWorld("api", { ping: () => 1, nested: { deep: { deeper: 1 }, list: [1] }, "quoted": 2, 3: 4, ...spread, [computed]: 5, method() {}, get g() { return 1; } });"#,
        r#"contextBridge.exposeInMainWorld("api"); contextBridge.exposeInMainWorld("api", api); contextBridge.exposeInMainWorld(name, {}); contextBridge.exposeInMainWorld(`tpl`, {}); contextBridge.exposeInMainWorld(42, {});"#,
        r#"contextBridge.exposeInIsolatedWorld(1004, "isolated", { a: 1 }); contextBridge.exposeInIsolatedWorld(worldId, key, api); contextBridge.exposeInIsolatedWorld(1, "k");"#,
        r#"electron.contextBridge.exposeInMainWorld("x", {}); a.b.contextBridge.exposeInMainWorld("y", {}); notcontextBridge.exposeInMainWorld("z", {});"#,
        r#"contextBridge.exposeInMainWorld("a", { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } } });"#,
        r#"contextBridge.exposeInMainWorld("a", { x: 1 }); contextBridge.exposeInMainWorld("a", { y: 2 }); contextBridge.exposeInMainWorld("a", { x: 1 });"#,
        r#"contextBridge.exposeInMainWorld("dup", { "a.b": 1, a: { b: 2 }, a: { c: 3 } });"#,
        r#"const { contextBridge: cb } = require("electron"); cb.exposeInMainWorld("renamed", { z: 1 });"#,
        r#"import { contextBridge as bridge } from "electron"; bridge.exposeInMainWorld("imported", { q: () => {} });"#,
        r#"import * as e from "electron"; e.contextBridge.exposeInMainWorld("ns", {});"#,
        r#"const electron = require("electron"); electron.contextBridge.exposeInMainWorld("el", {}); const { ipcRenderer } = electron; ipcRenderer.send("ch");"#,
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("bridge_{index:03}.js"), (*source).to_string()))
        .collect()
}

fn ipc() -> Vec<(String, String)> {
    let mut sources: Vec<String> = Vec::new();
    for object in ["ipcRenderer", "electron.ipcRenderer", "window.electron.ipcRenderer", "ipcMain", "a.ipcMain", "xipcMain", "myipcRenderer"] {
        for method in ["send", "sendSync", "invoke", "postMessage", "sendToHost", "on", "once", "handle", "handleOnce", "off", "removeListener", "sendTo", "a.b"] {
            for args in [
                r#""channel""#,
                r#""channel", () => {}"#,
                r#"`tpl`, handler"#,
                r#"name, function () {}"#,
                r#"42, h"#,
                r#"cond ? "a" : "b", obj.handler"#,
                r#""a" + b"#,
                "",
                r#""ch", ...rest"#,
                r#""ch", async function named() {}"#,
                r#""ch", (event) => event.sender.getURL()"#,
            ] {
                sources.push(format!("{object}.{method}({args});"));
            }
        }
    }
    // Several per file so the dedupe keys and spans interact.
    sources
        .chunks(12)
        .enumerate()
        .map(|(index, chunk)| (format!("ipc_{index:03}.js"), chunk.join("\n")))
        .collect()
}

fn validation() -> Vec<(String, String)> {
    let sources = [
        r#"ipcMain.handle("c", (event) => { if (event.senderFrame.url !== "https://app.example") throw new Error(); if (event.sender.getURL() === "x") {} if (event.senderFrame.origin == 'o') {} });"#,
        r#"ipcMain.on("c", (e) => { if (e.senderFrame !== mainFrame) return; if (e.sender.id === 1) {} if (mainId != e.frameId) {} if (e.processId !== -1) {} if ("k" in e.senderFrame) {} });"#,
        r#"ipcMain.on("c", (e) => { e.senderFrame.url.startsWith("https://"); e.sender.getURL().endsWith(".html"); e.senderFrame.origin.includes(x); e.sender.getURL().startsWith(); e.senderFrame.url["startsWith"]("a"); });"#,
        r#"ipcMain.on("c", (e) => { if (e.sender.getURL() < "a") {} if (e.sender.getURL() instanceof X) {} if (e.sender.id > 1) {} if (e.senderFrame.url === dyn) {} if (`t` === e.senderFrame.url) {} });"#,
        r#"ipcMain.on("c", (e) => { if (e.sender.id === 1.5) {} if (e.sender.id === -2) {} if (e.sender.id === true) {} if (e.sender.id === null) {} if (e.frameId === e.processId) {} });"#,
        r#"if (event?.senderFrame?.url === "a") {} if (a.b.sender.id === 3) {} if (xsender.id === 3) {} if (sender.id === 3) {} if (this.sender.getURL() == "z") {}"#,
        r#"if (event.senderFrame.url !== "https://a/b?c=d") {} if (event.senderFrame.url !== "https://a/b?c=d") {}"#,
        r#"class K { #p; m(o) { return #p in o.senderFrame; } }"#,
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("validation_{index:03}.js"), (*source).to_string()))
        .collect()
}

fn utility() -> Vec<(String, String)> {
    let sources = [
        r#"utilityProcess.fork("./w.js"); utilityProcess.fork(); utilityProcess.fork(path); utilityProcess.fork(path.join(__dirname, "w.js"), [], { serviceName: "svc" });"#,
        r#"utilityProcess.fork("./a.js", [], { serviceName: name }); utilityProcess.fork("./b.js", [], opts); utilityProcess.fork("./c.js", [], {}); utilityProcess.fork("./d.js", [], { ...o });"#,
        r#"utilityProcess.fork("./a.js", [], { serviceName: "x" }); utilityProcess.fork("./a.js", [], { serviceName: "y" }); electron.utilityProcess.fork(`./t.js`);"#,
        r#"utilityProcess.fork(fileURLToPath(new URL("./w.js", import.meta.url))); utilityProcess.fork(new URL("./w.js", import.meta.url).pathname);"#,
        r#"utilityProcess.fork(__dirname + "/w.js", [], { serviceName: __filename }); utilityProcess.fork(...args);"#,
        r#"const { utilityProcess: up } = require("electron"); up.fork("./renamed.js"); import { utilityProcess as u2 } from "electron"; u2.fork("./imported.js");"#,
        r#"utilityProcess.fork("./a.js", [], { serviceName: "x", serviceName: dyn }); utilityProcess.fork("./a.js", [], { serviceName: "x", ["serviceName"]: dyn });"#,
        r#"utilityProcess.fork("./a.js", [], { "serviceName": `s${1}` });"#,
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("utility_{index:03}.js"), (*source).to_string()))
        .collect()
}

fn renamed_roots() -> Vec<(String, String)> {
    let sources = [
        r#"const { BrowserWindow: BW, ipcMain: main, ipcRenderer: rend } = require("electron"); new BW({ webPreferences: { preload: "p" } }); main.handle("a", h); rend.send("b");"#,
        r#"import { BrowserWindow as BW, ipcMain as main, ipcRenderer as rend } from "electron"; new BW({}); main.on("a", h); rend.invoke("b");"#,
        r#"import electron, { app } from "electron"; electron.ipcMain.on("x", h); const e = electron; e.ipcMain.on("y", h);"#,
        r#"import * as ns from "electron"; ns.ipcMain.handle("z", h); new ns.BrowserWindow({});"#,
        r#"const e = require("electron"); const { ipcMain } = e; const im = e.ipcMain; im.on("q", h); ipcMain.on("r", h);"#,
        r#"const { remote } = require("electron"); const { BrowserWindow: RB } = remote; new RB({}); const R = remote.BrowserWindow; new R({});"#,
        r#"let w; w = require("electron").BrowserWindow; new w({ webPreferences: { preload: "z" } });"#,
        r#"const { ipcMain: x } = require("electron"); function f() { const x = other; x.on("shadow", h); } x.on("real", h);"#,
        r#"const { ipcMain } = require("electron"); { const ipcMain = { on() {} }; ipcMain.on("local", h); } ipcMain.on("global", h);"#,
        r#"import { ipcRenderer } from "electron"; export function send(m) { return ipcRenderer.invoke("msg", m); } export default ipcRenderer;"#,
        r#"const { BrowserWindow } = require("electron/main"); new BrowserWindow({}); const { ipcRenderer } = require("electron/renderer"); ipcRenderer.send("r");"#,
        r#"const E = require("electron"); new E.BrowserWindow({ webPreferences: { preload: __dirname + "/p.js" } }); E.contextBridge.exposeInMainWorld("a", {});"#,
    ];
    sources
        .iter()
        .enumerate()
        .map(|(index, source)| (format!("renamed_{index:03}.js"), (*source).to_string()))
        .collect()
}
