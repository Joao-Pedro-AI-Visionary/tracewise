import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("mixed", {
  greet: (name: string): Promise<string> => ipcRenderer.invoke("mixed:greet", name),
});
