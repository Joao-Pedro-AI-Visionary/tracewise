// Derived from morluto/rea (MIT), Copyright (c) 2026 morluto, commit 0fa0b04: tests/conformance/readiness/electron/renderer.js.
document.querySelector("#run").addEventListener("click", async () => {
  document.querySelector("#result").textContent =
    await window.readiness.echo("renderer");
});
window.readiness.onDeepLink((_event, url) => {
  document.querySelector("#result").textContent = url;
});
