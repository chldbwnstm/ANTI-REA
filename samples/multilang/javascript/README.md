# Direct JavaScript/TypeScript scalar VM route

This is source-function protection, not a native-library binding or a minifier.
An installed, hash-pinned TypeScript parser reads owned JavaScript/TypeScript ASTs.
Inspection can run the trusted parser but never executes the target. No npm
installation, target imports, build hooks or plugins are invoked. Build performs
TS syntax erasure for a private baseline, then independently lowers selected
functions and acyclic helpers to an encoded custom stack program. Generated
`protected.cjs` interprets that program without eval, Function or original bodies.

The primitive subset supports Number, BigInt and boolean; actual native JS
arithmetic/comparison operators; lexical let/const scopes and temporal-dead-zone
errors; assignments and ++/--; if/conditional/short-circuit expressions;
for/while/do loops, break/continue; owned helper calls; selected fixed Number,
BigInt, Boolean and Math builtins. Helpers are automatically included. Module
constants must be primitive literals. TS annotations are limited to primitive
types; this is syntax/subset checking, not full TypeScript type checking.

Rejected: imports, var, closures, recursion, objects/arrays, classes, async,
generators, exceptions handlers, destructuring, default/rest/optional parameters,
general property access/mutation, TypeScript enums/namespaces/decorators/generics.
The whole single source module must fit the subset, including unselected functions.
Input public types are primitive values, not objects with custom coercion.

Private build outputs include `source.js`/`source.ts`, `baseline.cjs`, coverage and
report files. Do not deploy that directory; `protected.cjs` is the deployment
candidate and needs its own validation/deployment review. No whole-package,
browser/Electron integration or automatic call-site replacement is claimed.

The sampling contract is `javascript_scalar_samples`. Number random bounds are
inclusive safe integers; additional special/fractional edges deliberately extend
beyond those random bounds (NaN, ±Infinity, -0, ±0.5 and ±2**53). BigInt bounds are
decimal strings, preserving JSON precision; booleans have no bounds. Validation
compares exact tagged float64/bigint/boolean results and native exception classes,
with two behavior repeats. Tiny Boolean domains are exhaustive, not padded to
8,192 duplicate inputs. Error messages/traces are not compared; all-error-only
behavior cannot pass. Runtime time/memory/output exhaustion is not a pass.

Opcode numbering and encoded operands differ by build seed. Keys and decoded
instructions are available locally. The import-time SHA-256 data check is not
authentication and does not cover runtime code. Native Kagura/hardening passes
are not applied. Functional samples do not establish acceptable overhead or
external attack resistance. No REA attack or publishing is part of this workflow.
