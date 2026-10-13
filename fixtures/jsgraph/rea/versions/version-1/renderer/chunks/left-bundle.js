
  (globalThis.webpackChunkfixture = globalThis.webpackChunkfixture || []).push([
    [101],
    {
      "stable-old": (module, exports) => { exports.stable = () => 42; },
      "descriptive-name": (module, exports) => {
        const descriptiveValue = 1;
        exports.changedName = () => descriptiveValue + 2;
      },
      "duplicate-a": (module, exports) => { exports.duplicate = () => 7; },
      "duplicate-b": (module, exports) => { exports.duplicate = () => 7; },
      "removed": (module, exports) => { exports.removed = true; }
    }
  ]);
  //# sourceMappingURL=left-bundle.js.map
