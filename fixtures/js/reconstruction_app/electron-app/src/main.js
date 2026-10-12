const { app, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const fs = require("node:fs");

ipcMain.handle("invoice:export", async (_event, invoice) => {
  const response = await fetch("https://api.example.com/invoices/render", {
    method: "POST",
    body: JSON.stringify(invoice),
  });
  const pdf = await response.arrayBuffer();
  fs.writeFileSync("invoice.pdf", Buffer.from(pdf));
  return "invoice.pdf";
});

ipcMain.on("invoice:print", () => {
  const child = spawn("lp", ["invoice.pdf"]);
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  process.on("SIGTERM", () => child.kill());
  setTimeout(() => child.kill(), 30000);
});

app.whenReady().then(() => {});
