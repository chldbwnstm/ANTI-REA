// Owned PURE scalar core (BigInt subset) for the phase24 TypeScript CLI
// application integration sample. Built with the pure `javascript_vm` producer
// under language=typescript: the primitive annotations are erased and the
// exported roots `scaled`, `fold` and `below` plus the reachable owned helper
// `scale` are virtualized into a self-contained CommonJS artifact. This `.ts`
// source is NEVER shipped in the protected bundle; the protected overlay is the
// producer's CommonJS artifact. No imports, objects or module-global function
// values appear here.

function scale(value: bigint, step: bigint): bigint {
  return value + step;
}

export function scaled(base: bigint, factor: bigint): bigint {
  let total: bigint = base;
  for (let i: bigint = 1n; i <= 3n; i++) {
    total = scale(total, factor * i);
  }
  return total;
}

export function fold(x: bigint, y: bigint): bigint {
  let result: bigint = x * 2n + y;
  if (x < 0n) {
    result = y - x;
  }
  return result;
}

export function below(x: bigint, y: bigint): boolean {
  return x < y;
}
