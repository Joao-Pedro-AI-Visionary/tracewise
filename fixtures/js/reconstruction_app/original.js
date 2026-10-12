// Original feature: format an invoice total.
const items = [3, 4.5, 2.25];
const total = items.reduce((sum, value) => sum + value, 0);
console.log(`invoice total: ${total.toFixed(2)}`);
