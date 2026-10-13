//! Adversarial inline scenarios for the derived collectors, one per behavior of the TS sources
//! (`javascriptSemantic{Calls,Promises,AsyncEffects,ChildProcesses,DataEffects,Resources,Objects,
//! Fingerprints}.ts`). The oracle supplies the expected IR for each; nothing here is hand-checked.

pub const SCENARIOS: &[(&str, &str)] = &[
    (
        "dsc_calls_shapes.ts",
        r#"
function add(a, b = 2, ...rest) { return a + b; }
function destructured({ x, y: [z] }, [p, , q] = []) { return x + z + p + q; }
const alias = add; let reassigned = add; reassigned = destructured;
const r1 = add(1), r2 = alias(1, 2, 3), r3 = reassigned(1);
add(...[1, 2], 3); add(1, ...[2]); destructured({ x: 1, y: [2] }, [3, 4, 5]);
const picked = cond ? add : destructured; picked(1); (cond && add)(1); (cond || add)(1); (0, add)(1);
add?.(1); (add as any)(1); (<any>add)(1); add!(1);
class K { constructor(a) { this.a = a; } m(b) { return b; } static s(c) { return c; } }
new K(1); const k = new K(2); k.m(3); K.s(4); new (K)(5); new (cond ? K : add)(6);
const { a1, b1: [c1] } = add(1); let d1; d1 = add(2); [d1] = add(3); ({ d1 } = add(4));
const aw = async () => { const v = await add(1); const [w] = await Promise.all([add(2)]); return v + w; };
const nested = (function outer(a) { return function inner(b) { return a + b + r1; }; })(1);
eval('x'); eval?.('y'); with (obj) { add(1); }
o[dyn]; o[1]; o['s']; o[`t`]; o[`t${1}`]; o[-1]; o[1n]; o?.[dyn]; this.#x; ({ [dyn]: 1, ['s']: 2, [3]: 3, [`u`]: 4, [`v${1}`]: 5, [dyn2]() {}, ['m']() {} });
class P { #priv = 1; [dyn]() {} static [dyn2] = 1; get [dyn3]() { return this.#priv; } }
import('dyn-mod'); require('x')(1); super_call();
"#,
    ),
    (
        "dsc_closures.js",
        r#"
let counter = 0; const shared = {}; var hoisted = 1;
function a() { counter++; shared.x = 1; hoisted += 1; function b() { return counter + shared.x; } return b; }
const arrow = () => () => () => counter;
class C { field = counter; static s = shared; m() { return () => hoisted; } get g() { return counter; } set g(v) { counter = v; } static { counter = 2; } }
const objm = { m() { return counter; }, get g() { return shared; }, f: function () { return hoisted; }, ar: () => counter };
function params(x, y = () => x, { z = counter } = {}) { return () => x + y + z; }
function shadow() { let counter = 1; return () => counter; }
try { risky(); } catch (e) { const f = () => e; }
for (const i of [1]) { setTimeout(() => i); }
label: { (() => label)(); }
"#,
    ),
    (
        "dsc_promises_ownership.ts",
        r#"
const awaitedNew = async () => { await new Promise((res) => res(1)); };
const assigned = new Promise((res) => res(1));
let reassign; reassign = Promise.resolve(2);
const returnedFn = () => new Promise((r) => r(1));
function returnedFn2() { return Promise.reject(new Error('x')); }
async function ret3() { return await Promise.resolve(1); }
function ret4() { return Promise.resolve(1).then((v) => v); }
Promise.resolve(1);
void Promise.resolve(2);
foo(Promise.resolve(3));
x.y = Promise.resolve(4);
[Promise.resolve(5)];
({ k: Promise.resolve(6) });
const { d1 } = Promise.resolve(7);
const [e1] = await Promise.all([Promise.resolve(8)]);
const chained = assigned.then((v) => v).catch((e) => e).finally(() => 1);
const aliased = assigned; aliased.then(() => 1);
let mutable = Promise.resolve(1); mutable = Promise.resolve(2); mutable.then(() => 1);
Promise.all([assigned, Promise.resolve(1), 1, 'x', {}, () => 1, class {}, ...more, , aliased]);
Promise.allSettled([new Promise(() => {}), assigned.then(() => 1)]);
Promise.all(variable); Promise.all([...spread]); Promise.all();
Promise.race([assigned]); Promise.any([assigned]);
await await Promise.resolve(1);
await (Promise.resolve(1) as Promise<number>);
await (await Promise.resolve(1));
await other();
await x;
p?.then(() => 1); p['then'](() => 1); p[`catch`](() => 1); p[dyn](() => 1);
(async () => { await (assigned); return (assigned); })();
const arrowRet = () => (Promise.resolve(1));
const arrowRet2 = () => (Promise.resolve(1) as any);
class Svc { async run() { return Promise.resolve(1); } m() { return new Promise(() => {}).then(() => 1); } }
function shadowed(Promise) { return new Promise(() => {}); }
const Promise2 = Promise; new Promise2(() => {});
if (c) Promise.resolve(1); else Promise.reject(2);
for (const q of [Promise.resolve(1)]) { await q; }
label: Promise.resolve(1);
const t = c ? Promise.resolve(1) : Promise.resolve(2);
const l = Promise.resolve(1) || Promise.resolve(2);
return_in_nested: function outer() { return [Promise.resolve(1)]; }
function* gen() { yield Promise.resolve(1); }
async function* agen() { yield await Promise.resolve(1); }
"#,
    ),
    (
        "dsc_events.js",
        r#"
const { EventEmitter } = require('node:events'); const em = new EventEmitter(); const other = new EventEmitter();
function h() {} const ar = () => 1;
em.on('a', h); em.once('b', ar); em.addListener('c', function () {}); em.prependListener('d', h); em.prependOnceListener('e', h);
em.off('a', h); em.removeListener('b', ar); em.removeAllListeners('c'); em.removeAllListeners(); em.emit('a', 1, 2); em.emit();
em['on']('x', h); em[`emit`]('y'); em[dyn]('z', h); em.on(name, h); em.on(`tpl`, h); em.on(`tpl${1}`, h); em.on(1, h); em.on('same', h, extra);
this.on('t', h); super.on && 1; globalThis.on('g', h); process.on('exit', h); window.addEventListener('load', h);
getEmitter().on('call', h); a.b.c.on('deep', h); (em).on('paren', h); em?.on('opt', h); em?.emit('opt2'); (em as any).on('ts', h); em!.on('nn', h);
unknownGlobal.on('u', h);
function inner(em2) { em2.on('param', h); em.on('captured', () => em2.emit('x')); }
class Bus extends EventEmitter { constructor() { super(); this.on('self', h); } m() { this.emit('self'); } }
let rebind = new EventEmitter(); rebind.on('r1', h); rebind = new EventEmitter(); rebind.on('r2', h);
em.on('spread', ...handlers); em.on('a', undefined); em.on('a', null); em.on('a', obj.method); em.on('a', async () => {});
var hoistedEm; function late() { hoistedEm.on('late', h); }
"#,
    ),
    (
        "dsc_timers.ts",
        r#"
import { setTimeout as st, clearTimeout as ct, setInterval } from 'node:timers';
import * as T from 'timers'; import timersDefault from 'timers';
const T2 = require('node:timers'); const { setImmediate: si, clearImmediate: ci } = require('timers');
const t1 = setTimeout(() => 1, 100); clearTimeout(t1);
const t2 = st(() => 1, 5.5); ct(t2);
const t3 = T.setInterval(() => 1, 0x10); T.clearInterval(t3);
const t4 = T2.setImmediate(() => 1); T2.clearImmediate(t4); timersDefault.setTimeout(() => 1, 1);
const i1 = setInterval(() => 1, -5); const i2 = setInterval(() => 1, 1e3); const i3 = setInterval(() => 1, 100n);
const s5 = si(() => 1); ci(s5);
let reused = setTimeout(() => 1, 1); clearTimeout(reused); reused = setTimeout(() => 2, 2); clearTimeout(reused);
let multi; multi = setTimeout(() => 1, 1); if (c) { multi = setTimeout(() => 2, 2); } clearTimeout(multi);
const [first] = [setTimeout(() => 1, 1)]; const { id } = setTimeout(() => 1, 1); const [pa, pb = setTimeout(() => 1)] = x; clearTimeout(first); clearTimeout(id);
clearTimeout(); clearTimeout(unknownHandle); clearTimeout(undefined); clearTimeout(this.timer); clearTimeout(t1 as any);
setTimeout(() => 1); setTimeout(); setTimeout(cb, delay); setTimeout(cb, '100'); setTimeout(cb, -0); setTimeout(cb, NaN);
window.setTimeout(() => 1, 5); globalThis.setTimeout(() => 1, 5); self.clearTimeout(1);
function shadowed(setTimeout) { setTimeout(() => 1, 5); }
const clearTimeout2 = clearTimeout; clearTimeout2(t1);
const x = (setTimeout(() => 1, 1), 2);
const handle = await new Promise((r) => setTimeout(r, 10));
const shorthand = { timer: setTimeout(() => 1, 1) };
this.timer = setTimeout(() => 1, 1);
const afterAwait = await setTimeout(() => 1, 1);
setTimeout?.(() => 1, 5); T?.setTimeout(() => 1, 5);
setTimeout(() => { clearTimeout(inner); }, 5); const inner = setTimeout(() => 1, 5);
"#,
    ),
    (
        "dsc_child.js",
        r#"
const cp = require('node:child_process'); const { spawn, exec: run, execFile, fork } = require('child_process');
import * as cpns from 'child_process'; import def, { spawn as sp2 } from 'node:child_process';
const p1 = spawn('ls', ['-l'], { env: process.env, stdio: 'inherit' });
const p2 = cp.spawn('node', ['a', 'b', ...c], { stdio: ['pipe', 'pipe'] });
const p3 = run('echo hi', { env }); const p4 = execFile('f', (e) => e); const p5 = fork('./w.js', [], { env: { A: 1 }, stdio: dyn });
const p6 = cpns.spawn(cmd); const p7 = sp2(`tpl`); const p8 = def.spawn('d'); const p9 = spawn(`t${1}`, 'notarray');
const p10 = spawn('a', [], { [env]: 1 }); const p11 = spawn('b', [], { env }); const p12 = spawn('c', [], { env() {}, stdio() {} });
const p13 = spawn('d', [], { stdio: `pipe` }); const p14 = spawn('e', [, ,], {}); const p15 = spawn('f', undefined, { env: 1 });
require('child_process').spawn('direct'); cp?.spawn('opt'); (cp).spawn('paren');
const [q1] = [spawn('arr')]; const { stdout, pid } = spawn('obj'); const { a: [q2] } = spawn('nested');
p1.on('exit', () => 1); p1.once('error', function () {}); p1.addListener('exit', h); p1.on('close', h); p1.on(dyn, h); p1.on('exit');
p1.kill(); p1.kill('SIGINT'); p1.kill(sig); p1.kill(`SIGHUP`); p1?.kill(); p1['kill'](); p1[`on`]('exit', h);
p1.stdout.on('data', h); p1.stdin.end(); spawn('chain').on('exit', h); spawn('chain2').kill();
q1.on('exit', h); stdout.on('exit', h); q2.kill();
let p16 = spawn('re1'); p16.on('exit', h); p16 = spawn('re2'); p16.kill();
function inner() { const local = spawn('in'); local.on('error', h); p1.kill('SIGTERM'); }
class Runner { start() { this.proc = spawn('cls'); this.proc.on('exit', h); } }
function shadowed(spawn) { spawn('x'); } function shadowed2(cp) { cp.spawn('x'); }
"#,
    ),
    (
        "dsc_data.ts",
        r#"
import process2 from 'node:process'; import * as pns from 'process'; import { env as penv } from 'node:process';
import fs, { readFile, readFileSync as rfs } from 'node:fs'; import * as fsns from 'fs'; const fs2 = require('fs'); const { readFileSync } = require('node:fs');
const a = process.env.A, b = process.env['B'], c = process.env[dyn], d = process.env[''], e = process.env[`C`], f = process.env[1];
const g = process.argv[2], h = process.argv['3'], i = process.argv[dyn], j = process.argv.length, k = process.argv.slice(2), l = process.argv[-1], m = process.argv[1.5], n = process.argv['01'], o = process.argv[4294967295], p = process.argv[4294967294];
const { HOME, USER = 'x', ...rest } = process.env; const [x0, x1] = process.argv;
const q = process2.env.Q, r = pns.env.R, s = penv.S;
const d1 = process.env.D1 || 'a'; const d2 = process.env.D2 ?? 5; const d3 = process.env.D3 || true; const d4 = process.env.D4 ?? null; const d5 = (process.env.D5) || 'p';
const d6 = (process.env.D6 as string) ?? 'q'; const d7 = process.env.D7 || `tpl`; const d8 = process.env.D8 || other; const d9 = process.env.D9 ?? -1; const d10 = process.env.D10 && 'x';
const d11 = process.env.D11 || process.env.D12 || 'z'; const d12 = (process.env.D13 ?? 'a') || 'b';
function shadowed(process) { return process.env.X; }
const cfg1 = readFileSync('a.json', 'utf8'), cfg2 = rfs(name), cfg3 = fs.readFileSync(`b.json`), cfg4 = fsns.readFile('c', () => 1), cfg5 = fs2.readFileSync('d'), cfg6 = fs.promises.readFile('e'), cfg7 = fs['readFileSync']('f'), cfg8 = readFile(`t${1}`);
const cfg9 = JSON.parse(fs.readFileSync('x.json')); readFileSync(); readFileSync(...args);
const r1 = await fetch('https://api/x', { method: 'POST', body, headers: { a: 1 }, [dyn]: 1, 'quoted': q, ...spread, mth() {} });
const r2 = await fetch(url); const r3 = fetch(`https://t`); const r4 = fetch(`https://t${1}`); const r5 = fetch({ url: 'x' }); const { data } = await fetch('/d');
r1.json(); r2.text(); r2.arrayBuffer(); r2.blob(); r3?.json(); r1['json'](); data.json(); const parsed = await r1.json(); const { z } = await r2.json();
const ws = new WebSocket('wss://x'); new WebSocket(url, ['p']); new WebSocket('wss://y', { headers: 1 }); new fetch('x'); fetch?.('opt');
const http = require('http'); const https = require('node:https'); import * as h2 from 'http';
const rq1 = http.get('http://a', { headers: { b } }); const rq2 = https.request({ host: 'h', path: dyn, method: 'POST', port: 1 }, cb); const rq3 = h2.request('http://c', { agent }, cb); const rq4 = http.request(opts); http.get(`http://t`); http.createServer();
rq1.json(); rq2.text();
function shadowedFetch(fetch) { return fetch('x'); } function shadowedWs(WebSocket) { return new WebSocket('y'); }
String(a); Number(b); Boolean(c); parseInt(d, 10); parseFloat(e); String(); Number(x, y); BigInt(1); Symbol('s');
function shadowedCoerce(String, JSON) { String(a); JSON.parse(b); }
JSON.parse(text); JSON.parse(); JSON['parse'](text); JSON?.parse(text); JSON.stringify(a);
schema.parse(input); z.object({}).safeParse(x); validator.validate(v); assert(c); is(c); a.assert(x); t.is(1); parser.parse(); this.parse(z); obj?.safeParse(q); obj['validate'](w);
const v1 = schema.parse(input); const { value } = schema.safeParse(input); let v3; v3 = JSON.parse(text); const v4 = Number(await x);
"#,
    ),
    (
        "dsc_resources.js",
        r#"
const fs = require('fs'); const fsp = require('node:fs/promises'); const net = require('net'); const tls = require('node:tls'); import * as nfs from 'node:fs'; import { open as o2, createReadStream } from 'fs'; const { connect, createConnection: cc } = require('net');
const fd = fs.openSync('a', 'r'); fs.closeSync(fd); const s = fs.createReadStream('a'); s.close(); s.destroy(); s.end(); s.pause();
const w = nfs.createWriteStream('b'); w.end(); w.end('data'); w.destroy(err);
const handle = await fsp.open('x'); await handle.close(); const h2 = await o2('y'); h2.close();
const sock = net.connect(80); sock.end(); const sock2 = connect(81); sock2.destroy(); const sock3 = cc(82); const sock4 = tls.connect(443); sock4.end(); net.createConnection(83);
const rs = createReadStream('z'); rs.close(); rs?.close(); rs['close'](); this.stream.close(); getStream().close(); other.close();
let reacq = fs.createReadStream('1'); reacq.close(); reacq = fs.createReadStream('2'); reacq.close();
let multi; if (c) { multi = fs.createReadStream('a'); } else { multi = fs.createWriteStream('b'); } multi.end();
const [arr] = [fs.createReadStream('arr')]; arr.close(); const { x } = fs.createReadStream('obj'); x.close();
fs.createReadStream('unassigned').close(); fs.open('cb', () => 1); fs.promises.open('p').then((hh) => hh.close());
function shadowed(fs) { return fs.openSync('s'); } function shadowed2(open) { open('s'); }
const http = require('http'); http.connect(); const srv = http.createServer(); srv.close(); const db = new Database(); db.close();
fs.openSync(...args); fs.createReadStream(); const copy = fs.openSync; copy('c');
function inner() { const local = fs.createReadStream('l'); return () => local.close(); }
class R { open() { this.s = fs.createReadStream('c'); } close() { this.s.close(); } }
"#,
    ),
    (
        "dsc_objects.ts",
        r#"
const o = { a: 1, b: { c: [1, 2, { d: 3 }] }, 'q-r': 5, 1: 'one' };
o.a; o.b.c; o.b.c[2].d; o['a']; o["b"]['c']; o[0]; o[1]; o[`a`]; o[dyn]; o.b[dyn].c; o[dyn].b; o?.a; o?.b?.c; o!.a; (o as any).a; (<any>o).a; (o).a;
o.a = 5; o.b.c = 1; o[dyn] = 1; o.a += 1; o.a ||= 2; o.a++; --o.b.c; delete o.a; typeof o.a; void o.a; [o.a] = [1]; ({ x: o.a } = {}); for (o.a of []) ; for (o.b in {}) ;
this.x; this.x.y = 1; super.method(); new.target.x; import.meta.url;
const { a, b: { c }, 'q-r': qr, [dyn]: dd, [`k`]: kk, 1: one, ...rest } = o;
const [h, , i, ...t] = [1, 2, 3, 4]; const [[n1], { n2 }] = x; const { p1 = 1, p2: { p3 = 2 } = {} } = o; const [r1 = 1, [r2] = []] = o.b.c;
const { l1 } = o.b, [{ l2 }] = o.b.c, { l3 } = o[dyn], { l4 } = dyn(), { l5 } = o.b[dyn], { l6 } = this, { l7 } = (o as any), { l8 } = await o;
function f({ pa, pb }, [pc]) { return pa; } for (const { fa } of []) {} try {} catch ({ ce }) {} const g = ({ aa }) => aa;
const copy = { ...o, ...o.b, ...o[dyn], ...dyn(), ...(o as any), ...[1], z: 1 }; const arr2 = [...o.b.c, ...x]; f(...o.b.c);
const obj2 = { a, b, [k]: 1, get g() { return o.a; }, set g(v) { o.a = v; }, m() { return o.b.c; } };
class C { x = o.a; static y = o.b.c; #p = 1; m() { return this.#p + this.x + o.a; } }
a.b.c.d.e = 1; a.b().c; a().b.c; a.b.c(); a[b][c]; a?.[b]?.c; a.b?.c.d; (a.b).c;
let w1; w1 = o.a; ({ w2: w1 } = o);
export const { ex1, ex2: [ex3] } = o;
"#,
    ),
    (
        "dsc_fingerprint_shapes.ts",
        r#"
export async function load<T extends object = {}>(id: string, opts?: { retries?: number; mode: 'fast' | 'slow' }, ...more: number[]): Promise<T> {
  const r = await fetch('/x/' + id); if (!r.ok) { throw new Error('bad'); }
  for (const k of [1, 2n, 0x10, 1e21, 0.1, -0, 1_000]) { setTimeout(() => k, 10); }
  for (let i = 0; i < 3; i++) { if (i) continue; else break; } while (true) { break; } do {} while (false); for (const q in {}) {}
  try { return (await r.json()).n; } catch (e) { return 0 as any; } finally { console.log('done'); }
  switch (id) { case 'a': return 1; default: return 2; }
  const re = /ab+c/gi, tpl = `a${1}b\n`, ok = true, no = null, un = undefined, neg = -1, upd = i++, un2 = !x, tn = typeof x;
  const t2 = x ? y : z; const lg = a && b || c ?? d; a ||= b; a &&= c; a ??= d; a **= 2;
  yield_ok: label: for (;;) { break label; }
}
class K<T> extends Base implements I { static s = 1; private p?: number; declare d: string; readonly r = 'ro'; #h = 2; accessor acc = 1;
  constructor(public a: string, private b = 2, readonly c?: T) { super(); }
  get g(): number { return 1; } set g(v: number) {} static async *ag(): AsyncGenerator<number> { yield 1; } [Symbol.iterator]() { return 1; } 'quoted'() {} 42() {} #pm() {} async #apm() {} *#gpm() {} get #gp() { return 1; } set #sp(v) {} static #sm() {} abstract_m?(): void;
  @dec() decorated(@param() x: number) { return x; } }
abstract class A { abstract am(): void; abstract get ag(): number; protected abstract ap: string; }
enum E { A = 1, B, C = 'c' } declare function df(a: number): void; declare const dc: number; namespace NS { export const v = 1; } declare module 'm' { export const x: number; }
type M = { [K in keyof T]?: T[K] }; type M2 = { readonly [K in keyof T]-?: T[K] }; type M3 = { -readonly [K in keyof T]+?: T[K] }; interface I2 { m(): void; p?: number; readonly q: string; [k: string]: any; get a(): number; set a(v: number); (x: number): string; new (x: number): I2; }
function typed(this: Window, a: keyof T, b: unique symbol, c: readonly string[], d: [a: string, b?: number, ...r: boolean[]], e: typeof import('x'), f: asserts a is string, g: (x: number) => void, h: new () => X, i: abstract new () => X): a is string { return true; }
const sat = { a: 1 } satisfies X, asc = <const>['a'], nn = a!.b!, tt = f<string>(1), inst = g<number>;
const o = { m() {}, async am() {}, *gm() {}, async *agm() {}, get g() { return 1; }, set g(v) {}, ['c' + 1]() {}, 'str': 1, 2: 3, [`t`]: 4, f: function* () {}, af: async () => {}, a: async function () {} };
function* gen() { yield 1; yield* other(); const x = yield; } async function* agen() { for await (const x of y) { yield x; } }
const html = <div className="a" {...p}>{x}<b/></div>;
tag`a${1}\unicode`; `\u{zz}`; tagged`\xg${2}b`;
"#,
    ),
    (
        "dsc_fingerprint_effects.js",
        r#"
const cp = require('child_process'); const fs = require('fs'); const em = new (require('events'))();
async function everything(a) {
  const p = new Promise((r) => r(1)); await p;
  em.on('x', () => 1); setTimeout(() => 1, 1); cp.spawn('ls'); fetch('/x'); fs.createReadStream('f'); a.b.c(); a(); new A(); (() => 1)();
  return p;
}
function plain() { return 1; } function onlyEvent() { em.emit('a'); } function onlyTimer() { setTimeout(plain, 5); } function onlyNet() { return fetch('x'); } function onlyChild() { cp.exec('ls'); }
function onlyResource() { fs.openSync('a'); } function onlyPromise() { return Promise.resolve(1); } function nested() { function inner() { fetch('inner'); } return inner; }
const arrow = async () => { await 1; }; const arrow2 = () => { throw new Error('x'); }; const arrow3 = () => 'expr';
class Svc { constructor(x) { this.x = x; } async run() { await fetch('/r'); } static create() { return new Svc(1); } get v() { return this.x; } }
function sameShapeA(a, b) { if (a) { return b + 1; } return b; } function sameShapeB(x, y) { if (x) { return y + 1; } return y; } function sameShapeC(x, y) { if (x) { return y + 2; } return y; }
function strings() { void ['b', 'a', 'a', 'B', 'é', '\u{1f600}', '\ud800', '\udc00x', '😀', 'z￿z', '', ' ', 'a\nb', 'quote"d', 'back\\slash', '\u0000', '\u007f', ' ']; }
function numbers() { return [1, 1.0, 1.5, 1e3, 1e21, 1e-7, 0xff, 0b11, 0o7, .5, 5., 1_0, 0.1 + 0.2, 123456789012345680000, 2 ** 53]; }
function regexes() { return [/a/, /a/g, /[/]\//u, /(?<n>x)/v, /\u{1f600}/u]; } function bigs() { return [1n, 0x10n, 9007199254740993n]; }
function templates() { void [`a`, `a${1}b`, `${x}${y}`, `\n`, `\\`, `line1
line2`, tag`raw\n`, `\u{1f600}`, `\ud800`]; }
"#,
    ),
    (
        "dsc_recovery.js",
        r#"
function f(a, b) { return a + b; }
f(1, , 3);
f(,);
const x = f(;
"#,
    ),
    (
        "dsc_edge_misc.mjs",
        r#"
export default async function () { await Promise.resolve(1); setTimeout(() => 1, 1); }
export const arrow = async () => { await fetch('/a'); };
export class Named { async m() { return await fetch('/b'); } }
export { arrow as renamed };
const lazy = () => import('./other.js'); lazy();
export function* g() { yield fetch('/c'); }
const top = await fetch('/top'); const topJson = await top.json();
if (top.ok) { await Promise.all([top.json(), top.text()]); }
queueMicrotask(() => 1); process.nextTick(() => 1); setImmediate(() => 1);
(async () => { try { await risky(); } catch { await fallback(); } })();
"#,
    ),
];
