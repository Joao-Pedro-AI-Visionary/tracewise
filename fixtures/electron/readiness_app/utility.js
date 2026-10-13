// Derived from morluto/rea (MIT), Copyright (c) 2026 morluto, commit 0fa0b04: tests/conformance/readiness/electron/utility.js.
const { parentPort } = require("electron");

parentPort.on("message", (event) => {
  parentPort.postMessage({ echoed: event.data });
});
