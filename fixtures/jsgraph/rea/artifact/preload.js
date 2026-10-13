
        import { contextBridge, ipcRenderer } from "electron";
        contextBridge.exposeInMainWorld("fixture", {
          lookup: (id) => ipcRenderer.invoke("fixture:lookup", id)
        });
      