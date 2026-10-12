// Broken reimplementation: drops the last item.
const items = [3, 4.5];
console.log(`invoice total: ${items.reduce((a, b) => a + b, 0).toFixed(2)}`);
