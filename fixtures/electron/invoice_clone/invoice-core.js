"use strict";

// Reimplementation written from the trace of invoice:export, not copied from the original:
// integer cents instead of floating point, same observable output.
const defaultCents = [300, 450, 225];

function toCents(value) {
  return Math.round(value * 100);
}

function money(cents) {
  return `${Math.trunc(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
}

function renderInvoice(invoice) {
  const cents = invoice && Array.isArray(invoice.items) ? invoice.items.map(toCents) : defaultCents;
  return {
    total: money(cents.reduce((sum, value) => sum + value, 0)),
    lines: cents.map((value, index) => `${index + 1}: ${money(value)}`),
  };
}

module.exports = { renderInvoice };

if (require.main === module) {
  console.log(`invoice total: ${renderInvoice().total}`);
}
