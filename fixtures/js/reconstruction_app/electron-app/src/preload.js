const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("invoices", {
  exportPdf: (invoice) => ipcRenderer.invoke("invoice:export", invoice),
  print: () => ipcRenderer.send("invoice:print"),
});
