const { app, BrowserWindow, ipcMain } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const { renderInvoice } = require("./invoice-core");

// The feature to clone: the renderer asks the main process to export an invoice.
ipcMain.handle("invoice:export", async (_event, invoice) => {
  const rendered = renderInvoice(invoice);
  const file = path.join(app.getPath("temp"), "invoice.pdf");
  fs.writeFileSync(file, `%PDF-fixture\n${rendered.lines.join("\n")}\ntotal ${rendered.total}\n`);
  return { file: path.basename(file), total: rendered.total, lines: rendered.lines.length };
});

app.whenReady().then(() => {
  const window = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, "preload.js") } });
  window.loadFile(path.join(__dirname, "renderer.html"));
});
