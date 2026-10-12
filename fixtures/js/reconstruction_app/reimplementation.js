// Reimplementation of the invoice total feature.
function invoiceTotal(items) {
  let sum = 0;
  for (const value of items) sum += value;
  return sum;
}
console.log(`invoice total: ${invoiceTotal([3, 4.5, 2.25]).toFixed(2)}`);
