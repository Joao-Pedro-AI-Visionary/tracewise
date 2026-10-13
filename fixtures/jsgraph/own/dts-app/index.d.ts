/// <reference path="./types/extra.d.mts" />
export declare function load(file: string): string;
export declare class Client {
  constructor(base: string);
  fetchJson(path: string): Promise<unknown>;
  get base(): string;
  set base(value: string);
}
declare class Internal {
  run(): void;
}
export { Internal as Runner };
declare namespace Options {
  class Flags {
    verbose: boolean;
  }
  export { Flags };
}
export { Options };
declare module 'dts-app/plugin' {
  import { Client } from 'dts-app';
  export function connect(client: Client): void;
  export { Client };
}
declare global {
  interface Window {
    dtsApp: typeof import('dts-app');
  }
  var dtsAppVersion: string;
}
