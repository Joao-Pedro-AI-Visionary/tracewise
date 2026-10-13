
  (globalThis.webpackChunkfixture = globalThis.webpackChunkfixture || []).push([
    [909],
    {
      "stable-new": (module, exports) => { exports.stable = () => 42; },
      "a": (module, exports) => {
        const b = 1;
        exports.changedName = () => b + 2;
      },
      "collision-x": (module, exports) => { exports.duplicate = () => 7; },
      "collision-y": (module, exports) => { exports.duplicate = () => 7; },
      "added": (module, exports) => { exports.added = true; }
    }
  ]);
  //# sourceMappingURL=right-bundle.js.map
