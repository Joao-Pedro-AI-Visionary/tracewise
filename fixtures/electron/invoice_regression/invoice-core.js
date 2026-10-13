"use strict";

// A tempting but wrong reimplementation: the total is rounded to one decimal.
const defaultItems = [3, 4.5, 2.25];

function renderInvoice(invoice) {
  const items = invoice && Array.isArray(invoice.items) ? invoice.items : defaultItems;
  const total = items.reduce((sum, value) => sum + value, 0);
  return {
    total: total.toFixed(1),
    lines: items.map((value, index) => `${index + 1}: ${value.toFixed(2)}`),
  };
}

module.exports = { renderInvoice };

if (require.main === module) {
  console.log(`invoice total: ${renderInvoice().total}`);
}
