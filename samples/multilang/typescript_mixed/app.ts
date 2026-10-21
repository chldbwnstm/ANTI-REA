"use strict";
// Owned TypeScript mixed-module sample. The whole module is transpiled once via
// isolatedModules (whole-module CommonJS transpilation); selected roots and reachable owned
// helpers are then virtualized in the resulting CommonJS. Unselected code
// (LABEL, describe) is preserved modulo erased type annotations. Selected code
// loads no module global; constants are passed as arguments.

export const LABEL: string = "ts-mixed";

export function describe(seed: number, salt: number): string {
  return LABEL + ":" + score(seed, salt);
}

export function score(seed: number, salt: number): number {
  let acc: number = blend(seed, salt);
  for (let i: number = 0; i < 5; i++) {
    acc = blend(acc, i) ^ (acc >>> 1);
    if (acc % 2 === 0) {
      acc = acc + i;
    }
  }
  return acc % 100000;
}

export function blend(x: number, y: number): number {
  return (Math.imul(x ^ y, 2246822519) + x - (y << 2)) | 0;
}
