export interface Options<T> {
  readonly delay: number;
  callback?: (value: T) => void;
}

export enum Level {
  Low,
  High = 10,
}

export type Handler<T> = (value: T) => Promise<void> | void;

export function debounce<T>(fn: (...args: any[]) => T, delay: number): (...args: any[]) => Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return (...args) =>
    new Promise<T>((resolve) => {
      if (timer !== undefined) clearTimeout(timer);
      timer = setTimeout(() => resolve(fn(...args)), delay);
    });
}

export class Store<T extends object = {}> {
  private items = new Map<string, T>();
  constructor(public readonly name: string) {}
  get size(): number {
    return this.items.size;
  }
  set(key: string, value: T): this {
    this.items.set(key, value);
    return this;
  }
}

export const level: Level = Level.High as Level;
