# JavaScript ordinary-application integration fixture (phase24)

A minimal ordinary CommonJS Node application whose protected build substitutes a
single protected scalar core module for the original core, keeping every other
application file byte-for-byte identical. It is a defender fixture only; it does
not attack, and it performs no builds, transpiles or runs by itself.

## Canonical files

- `core.js` — the owned **pure scalar** core (`weigh`, `combine`, `atLeast` plus
  the reachable owned helper `scale`). The pure `javascript_vm` producer
  virtualizes these into a self-contained CommonJS artifact. Uses `export`
  syntax; the raw source is **excluded** from the protected bundle.
- `app.js` — the ordinary application (the integration `entrypoint`). It
  dispatches `app <weigh|combine|atleast|name> operands...`, validating operands
  before it lazily `require("./core.js")`, so a usage failure never loads the
  core. `name` reads `labels.json`; the compute operations reach the protected
  core.
- `format.js` — an ordinary unselected CommonJS sibling (output formatting),
  preserved byte-for-byte in both arms and in the bundle.
- `labels.json` — an ordinary data file read by the `name` operation; preserved
  byte-for-byte and shipped in the bundle.
- `project.json` — the single-source producer project consumed by the JavaScript
  frontend to build the reused protected core (`weigh`/`combine`/`atLeast`).
- `core-contract.json` — the existing `javascript_scalar_samples` contract for
  the core, used by the public source-validate step (random scalar vectors).
- `integration.json` — the fixed `script_application_integration` spec
  (`language` javascript, `protected_source` `core.js`, `entrypoint` `app.js`,
  explicit `application_files`).
- `app-contract.json` — the fixed `script_application_samples` contract. The
  first success case (`weigh-basic`) reaches the core, so the engine's
  missing-module control proves the protected app depends on the loaded core.
  `expect` carries only `returncode` and `stdout` (no stderr equivalence).

## Expected outputs

Expected `stdout` values were derived by hand from the exact scalar semantics
(`weigh(b,f)=b+6f`, `combine` is `x*3+y` or `y-x` when `x<0`, `atLeast` is
`x>=y`), **not** by executing Node. The root driver re-qualifies every
expectation against the real original build before acceptance; these are not a
self-certified pass.

## Boundaries

CommonJS Node, Windows. Generation and these fixtures are not compilation,
functional-equivalence, performance or reverse-engineering-resistance evidence;
the actual fresh source-validate, the three-arm sample comparison
(original/protected/copied deployment), the missing-module control and the exact
bundle inventory are owned by root and run only under its bounded runner after
freeze.
