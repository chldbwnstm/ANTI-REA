# TypeScript CLI application integration fixture (phase24)

A minimal multi-file ordinary TypeScript application whose protected build
substitutes a single protected scalar core for the original core. The ordinary
unselected `.ts` files are independently transpiled to CommonJS `.js` with the
pinned compiler options (same options in both runtime arms); the original `.ts`
sources never appear in a runtime tree or the deploy bundle. It is a defender
fixture only; it does not attack, and it performs no transpiles or runs by
itself.

## Canonical files

- `core.ts` — the owned **pure scalar** core (`scaled`, `fold`, `below` plus the
  reachable owned helper `scale`). The pure `javascript_vm` producer under
  `language=typescript` erases the primitive annotations and virtualizes these
  into a self-contained CommonJS artifact. The raw `.ts` is **excluded** from the
  protected bundle.
- `app.ts` — the ordinary application (the integration `entrypoint`),
  independently transpiled to `app.js`. It dispatches
  `app <scaled|fold|below> x y`, parses BigInt operands, and imports the core via
  the runtime `./core.js` specifier.
- `format.ts` — an ordinary unselected typed sibling, independently transpiled to
  `format.js` in both arms and shipped in the bundle.
- `project.json` — the single-source producer project (no `protection_mode`; a
  pure scalar source build, independent of the application graph).
- `core-contract.json` — the existing `javascript_scalar_samples` contract for
  the core, used by the public source-validate step.
- `integration.json` — the fixed `script_application_integration` spec
  (`language` typescript, `protected_source` `core.ts`, `entrypoint` `app.ts`).
- `app-contract.json` — the fixed `script_application_samples` contract. The
  first success case (`scaled-basic`) reaches the core, so the engine's
  missing-module control proves the protected app depends on the loaded core.

## Expected outputs

Expected `stdout` values were derived by hand from the exact BigInt semantics
(`scaled(b,f)=b+6f`, `fold` is `x*2+y` or `y-x` when `x<0`, `below` is `x<y`),
**not** by executing Node or a compiler. The root driver re-qualifies every
expectation against the real original build before acceptance; these are not a
self-certified pass.

## Boundaries

CommonJS Node, Windows. TypeScript transpilation is a whole-module type erasure
(`isolatedModules`, no project graph, no full type check) with the same pinned
options for both arms; `.d.ts`, `.tsx`, ESM-only and explicit `.ts` runtime
specifiers are rejected rather than leaking original TypeScript. Generation and
these fixtures are not compilation, functional-equivalence, performance or
reverse-engineering-resistance evidence; the actual transpile receipts, the
three-arm sample comparison, the missing-module control and the exact bundle
inventory are owned by root and run only under its bounded runner after freeze.
