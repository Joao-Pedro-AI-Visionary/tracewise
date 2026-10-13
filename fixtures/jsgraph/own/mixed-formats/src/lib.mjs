import data from "./data.json" with { type: "json" };
import { suffix as helperSuffix } from "./helper.js";
import * as view from "./view.tsx";
export { view };
export const settings = { ...data, retries: 3, mode: "fast" };
export function greet(name, greeting = data.greeting, suffix = helperSuffix) {
  return `${greeting}, ${name}${suffix}`;
}
export default async function load() {
  const { debounce } = await import("./util.ts");
  return debounce(greet, 10);
}
