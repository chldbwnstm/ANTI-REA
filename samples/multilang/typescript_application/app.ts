import { label } from "./labels.js";

// Runtime-bearing TypeScript remains ordinary emitted JavaScript.
export enum Band { Low = 0, Middle = 1, High = 2 }
export namespace UI {
  export function band(value: number): Band {
    return ((value % 3) + 3) % 3;
  }
}

function preview(seed: number, salt: number): string {
  return label(score(seed, salt));
}

// Ordinary startup reaches the selected core before its textual declaration.
const startup = preview(7, 11);

function score(seed: number, salt: number): number {
  let acc = blend(seed, salt);
  for (let i = 0; i < 5; i++) {
    acc = blend(acc, i) ^ (acc >>> 1);
    if (acc % 2 === 0) acc += i;
  }
  return acc % 100000;
}

function blend(x: number, y: number): number {
  return (Math.imul(x ^ y, 2246822519) + x - (y << 2)) | 0;
}

// Preserved ordinary caller also reaches a protected helper.
function digitSum(value: number): number {
  let n = Math.abs(value | 0), total = 0;
  while (n > 0) {
    total = blend(total, n % 10);
    n = (n - (n % 10)) / 10;
  }
  return total;
}

module.exports = { score, digitSum, preview, startup, Band, UI };
