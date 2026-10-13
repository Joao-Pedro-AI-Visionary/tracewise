'use strict';
const fs = require('node:fs');
function load(file) {
  return fs.readFileSync(file, 'utf8');
}
class Client {
  constructor(base) {
    this.base = base;
  }
  fetchJson(path) {
    return fetch(this.base + path).then((r) => r.json());
  }
}
module.exports = { load, Client };
