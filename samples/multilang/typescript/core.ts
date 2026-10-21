const BIAS: bigint = 193n;

function mixBig(value: bigint, salt: bigint): bigint {
  return ((value ^ salt) << (salt % 5n)) * 17n + BIAS;
}

export function bigintScore(x: bigint, y: bigint): bigint {
  let total: bigint = mixBig(x, y);
  for (let index: bigint = 0n; index < 5n; index++) {
    if (index === 2n && x < 0n) continue;
    total = (total * 7n + index) ^ (x >> index);
    if (total % 3n === 0n) total += mixBig(y, index);
    else total -= x / ((y % 23n) || 1n);
  }
  return total;
}

export function bigintErrors(x: bigint, y: bigint): bigint {
  if (x % 3n === 0n) return x / y;
  if (x % 3n === 1n) return x << y;
  return x % y;
}

export function booleanGate(x: boolean, y: boolean): boolean {
  return (x && !y) || (!x && y);
}
