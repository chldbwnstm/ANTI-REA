// Ordinary unselected typed sibling module. It is independently transpiled to
// `format.js` with the same pinned options in both arms and shipped in the deploy
// bundle; it never touches the protected core.
export function describe(op: string, value: bigint | boolean): string {
  return op + " -> " + String(value);
}
