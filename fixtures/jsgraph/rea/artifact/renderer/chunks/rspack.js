
        (self.rspackChunkfixture = self.rspackChunkfixture || []).push([
          ["editor"],
          {
            "src/editor.ts": (module, exports, r) => {
              exports.render = () => r("src/model.ts");
            },
            "src/model.ts": (module) => { module.exports = "model"; }
          }
        ]);
      