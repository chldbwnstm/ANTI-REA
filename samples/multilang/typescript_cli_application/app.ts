// Ordinary surrounding TypeScript application (the integration `entrypoint`). It
// is independently transpiled to CommonJS `app.js` with the pinned compiler
// options and imports the core through the runtime `./core.js` specifier, which
// resolves to the staged core module in both arms. The original `.ts` is never
// shipped. Runtime-bearing typed code (the import, typed locals, a union return)
// stays ordinary emitted JavaScript; only the core roots are virtualized.

import { scaled, fold, below } from "./core.js";
import { describe } from "./format.js";

function usage(message: string): never {
  process.stderr.write(message + "\n");
  process.exit(2);
}

function parseOperand(text: string): bigint {
  if (!/^-?(0|[1-9][0-9]*)$/.test(text)) {
    usage("invalid integer operand: " + text);
  }
  return BigInt(text);
}

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    usage("usage: app <scaled|fold|below> x y");
  }
  const op = argv[0];
  const rest = argv.slice(1);
  if (op !== "scaled" && op !== "fold" && op !== "below") {
    usage("unknown operation: " + op);
  }
  if (rest.length !== 2) {
    usage(op + " requires 2 operands");
  }
  const x = parseOperand(rest[0]);
  const y = parseOperand(rest[1]);
  let result: bigint | boolean;
  if (op === "scaled") {
    result = scaled(x, y);
  } else if (op === "fold") {
    result = fold(x, y);
  } else {
    result = below(x, y);
  }
  process.stdout.write(describe(op, result) + "\n");
}

main();
