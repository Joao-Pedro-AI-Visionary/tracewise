
const { ipcRenderer } = require("electron");
ipcRenderer.invoke("rea:read", "renderer-key");
ipcRenderer.send("rea:write", "renderer-value");
ipcRenderer.on("rea:event", (_event, value) => console.log(value));
