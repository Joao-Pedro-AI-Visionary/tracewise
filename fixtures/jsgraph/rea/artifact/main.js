
        import { BrowserWindow } from "electron";
        import path from "node:path";
        const window = new BrowserWindow({
          webPreferences: { preload: path.join(__dirname, "preload.js") }
        });
        window.loadFile("./renderer/index.html");
        require("./native/addon.node");
      