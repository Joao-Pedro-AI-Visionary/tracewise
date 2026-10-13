
const path = require("node:path");
const { BrowserWindow, ipcMain, utilityProcess } = require("electron");
const { read, write: nativeWrite } = require("./native/addon.node");

new BrowserWindow({
  width: 900,
  webPreferences: {
    preload: path.join(__dirname, "preload.js"),
    nodeIntegration: true,
    contextIsolation: false,
    sandbox: false,
    webSecurity: false,
  },
});
new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
  },
});
new BrowserWindow(windowOptions);

ipcMain.handle("rea:read", async (event, key) => {
  if (!event.senderFrame.url.startsWith("file://")) throw new Error("denied");
  return read(key);
});
ipcMain.on("rea:write", (event, value) => {
  if (event.sender.getURL() !== "file://fixture/index.html") return;
  nativeWrite(value);
});
ipcMain.handle("rea:ambiguous", async () => 1);
ipcMain.handle("rea:ambiguous", async () => 2);
ipcMain.handle(dynamicChannel, dynamicHandler);

utilityProcess.fork("./utility/worker.js", [], { serviceName: "fixture-db" });
module.exports.nativeRead = require("./native/addon.node").read;

globalThis.__rea_electron_fixture_executed = true;
throw new Error("Electron boundary fixture must never execute");
