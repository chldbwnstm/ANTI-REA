#!/usr/bin/env node
"use strict";
// Owned mixed-module sample (CommonJS). Selected roots and their reachable owned
// helpers are virtualized; the require, the UI functions, the unselected caller
// of a virtualized helper, and this module's exports are preserved. No module
// global is loaded by selected code: constants are passed as arguments.

const labels = require("./labels.js");

// Pre-definition call across the JS hoisting boundary: this top-level const runs
// at module load and reaches the selected `checksum` (defined far below) through
// the unselected `preview` function. Because the injected VM entrypoints are
// hoisted function declarations with lazy init, this must work in the protected
// module exactly as in the original.
const BOOTSTRAP = preview(7, 11);

// --- Unselected ordinary functions (preserved verbatim) -----------------------
function preview(seed, salt) {
  return labels.tagline(checksum(seed, salt));
}

function render(seed, salt) {
  const value = checksum(seed, salt);
  return "checksum(" + seed + "," + salt + ")=" + value + " digits=" + digitSum(value);
}

// Unselected code that calls a *virtualized owned helper* (`mix`). The call
// routes through the generated VM entrypoint; `mix` is not shipped in plaintext.
function digitSum(value) {
  let n = Math.abs(value | 0), total = 0;
  while (n > 0) { total = mix(total, n % 10); n = (n - (n % 10)) / 10; }
  return total;
}

// --- Selected root and reachable owned helpers (virtualized) ------------------
function checksum(seed, salt) {
  let acc = mix(seed, salt);
  for (let i = 0; i < 6; i++) {
    acc = mix(acc, i) ^ rotate(acc, i & 7);
    if (acc % 3 === 0) acc += seed;
  }
  return acc % 100000;
}

function mix(x, y) {
  return (Math.imul(x ^ y, 2654435761) + (x << 3) - y) | 0;
}

function rotate(value, by) {
  const v = value | 0;
  return ((v << by) | (v >>> (32 - by))) | 0;
}

module.exports = { checksum, mix, render, preview, digitSum, bootstrap: BOOTSTRAP };
