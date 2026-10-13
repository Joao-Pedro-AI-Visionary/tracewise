
const { contextBridge, ipcRenderer } = require("electron");
const { read, write } = require("./native/addon.node");

contextBridge.exposeInMainWorld("reaApi", {
  read: (key) => ipcRenderer.invoke("rea:read", key),
  nested: {
    write: (value) => ipcRenderer.send("rea:write", value),
  },
  nativeRead: read,
  nativeWrite: write,
});
contextBridge.exposeInMainWorld(dynamicApiKey, dynamicApi);
ipcRenderer.on("rea:event", (_event, value) => console.log(value));
ipcRenderer.invoke("rea:ambiguous");
ipcRenderer.invoke("rea:missing");
ipcRenderer.invoke(dynamicChannel);
