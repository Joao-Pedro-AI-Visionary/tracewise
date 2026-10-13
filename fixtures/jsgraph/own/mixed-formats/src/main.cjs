"use strict";
const path = require("node:path");
const { app, BrowserWindow, ipcMain } = require("electron");
const config = require("./config.json");
const tiny = require("tiny");
const scoped = require("@scope/pkg/feature");
const { greet } = require("./lib.mjs");
const helper = require("./helper");

ipcMain.handle("mixed:greet", async (_event, name) => greet(name, config.greeting, helper.suffix));

app.whenReady().then(() => {
  const window = new BrowserWindow({
    webPreferences: { preload: path.join(__dirname, "preload.ts"), contextIsolation: true },
  });
  window.loadFile(path.join(__dirname, "..", "web", "index.html"));
  console.log(tiny.id, scoped.name);
});

module.exports = { start: () => app.whenReady() };
exports.version = require("../package.json").version;
