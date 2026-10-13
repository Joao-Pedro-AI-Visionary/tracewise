// Derived from morluto/rea (MIT), Copyright (c) 2026 morluto, commit 0fa0b04: tests/conformance/readiness/electron/preload.js.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("readiness", {
  echo: (value) => ipcRenderer.invoke("readiness:echo", value),
  onDeepLink: (listener) => ipcRenderer.on("deep-link", listener),
});
