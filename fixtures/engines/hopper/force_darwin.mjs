// Preloaded into the REA oracle (node --import force_darwin.mjs rea.mjs mcp): only the Hopper
// provider constructor sees "darwin", so it takes the direct (native) launch path against the
// fake launcher instead of the Linux private-display demo adapter. Every other module keeps
// the real platform (process ownership inspection is POSIX-generic on Linux).
const real = process.platform;
Object.defineProperty(process, "platform", {
  get() {
    return new Error().stack?.includes("/hopper/HopperProvider.js") ? "darwin" : real;
  },
});
