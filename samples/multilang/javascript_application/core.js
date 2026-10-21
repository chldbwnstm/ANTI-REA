"use strict";
// Owned PURE scalar core (Number subset) for the phase24 JavaScript application
// integration sample. The pure javascript_vm producer selects the exported roots
// `weigh`, `combine` and `atLeast`, virtualizes them plus their reachable owned
// helper `scale` into a self-contained CommonJS artifact, and never ships this
// source in the protected bundle. No imports, objects, closures or module-global
// function values appear here: inputs arrive as primitive Number arguments.

function scale(value, step) {
  return value + step;
}

export function weigh(base, factor) {
  let total = base;
  for (let i = 1; i <= 3; i++) {
    total = scale(total, factor * i);
  }
  return total;
}

export function combine(x, y) {
  let result = x * 3 + y;
  if (x < 0) {
    result = y - x;
  }
  return result;
}

export function atLeast(x, y) {
  return x >= y;
}
