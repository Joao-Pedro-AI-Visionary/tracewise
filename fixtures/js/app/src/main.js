import { add } from "./math.js";

export function total(values) {
  let sum = 0;
  for (const value of values) {
    sum = add(sum, value);
  }
  return sum;
}
