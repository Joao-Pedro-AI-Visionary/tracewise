const { ipcMain } = require("electron"); ipcMain.handle("feature:open", () => require("./native.node"));
