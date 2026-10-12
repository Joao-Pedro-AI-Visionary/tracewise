window.exportPdf = () => {
  document.getElementById("title").textContent = "exported";
};
document.getElementById("export").addEventListener("click", window.exportPdf);
