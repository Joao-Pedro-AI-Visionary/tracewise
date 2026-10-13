"use strict";

// Original feature: format an invoice total (the same arithmetic as fixtures/js/reconstruction_app/original.js).
const defaultItems = [3, 4.5, 2.25];

function renderInvoice(invoice) {
  const items = invoice && Array.isArray(invoice.items) ? invoice.items : defaultItems;
  const total = items.reduce((sum, value) => sum + value, 0);
  return {
    total: total.toFixed(2),
    lines: items.map((value, index) => `${index + 1}: ${value.toFixed(2)}`),
  };
}

module.exports = { renderInvoice };

if (require.main === module) {
  console.log(`invoice total: ${renderInvoice().total}`);
}
