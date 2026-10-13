document.querySelector("#export").addEventListener("click", async () => {
  const exported = await window.invoices.exportPdf({ items: [3, 4.5, 2.25] });
  document.querySelector("#result").textContent = `${exported.file}: ${exported.total}`;
});
