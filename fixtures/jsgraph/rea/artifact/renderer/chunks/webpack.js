
        globalThis.__rea_bundle_executed = true;
        (globalThis.webpackChunkfixture = globalThis.webpackChunkfixture || []).push([
          [101],
          {
            1: (module, exports, r) => {
              const dependency = r(2);
              exports.lookup = () => dependency;
            },
            2: (module) => { module.exports = { value: 42 }; }
          }
        ]);
        throw new Error("bundle execution must never happen");
      