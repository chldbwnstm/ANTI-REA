# Experimental mixed JavaScript / TypeScript modules

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

The source-plan/build API accepts `protection_mode: "mixed_module"` for JavaScript
and TypeScript. This protects selected top-level scalar functions and their
reachable owned helpers while retaining the rest of one application module.
Omit the option to keep the existing pure-module route.

```json
{
  "schema_version": 1,
  "name": "owned-calculation",
  "language": "javascript",
  "sources": ["app.js"],
  "functions": ["checksum"],
  "protection_mode": "mixed_module"
}
```

Use the existing `protection_source_plan` and `protection_source_build` MCP tools,
or `ProjectService.plan()` and `.build()`. Planning parses owned source and pins
the project directory and engine/compiler inputs. Building requires that plan's
fingerprint and creates private `baseline.cjs`, `protected.cjs` and coverage
records under `.runs/source-protection/`. Neither operation imports the app.
Ordinary startup code, imports and UI may execute when the resulting module is
later loaded; a build is not permission or evidence for that execution.

## Supported boundary

- Selected functions use the existing Number / BigInt / boolean scalar subset.
  Their reachable acyclic owned helpers also enter the VM, including helpers
  called by unselected ordinary code.
- JavaScript keeps unselected text and order, aside from stripping a UTF-8 BOM.
  Hoisted lazy VM entrypoints preserve supported calls before a function's
  textual declaration, shebangs and directive prologues.
- TypeScript is transpiled as a whole CommonJS module with the pinned installed
  TypeScript parser. This is not full type-checking or merely removing types:
  enums, namespaces and other runtime constructs can be emitted as unprotected
  ordinary code. Only the supported scalar functions are virtualized.
- Module-global values in selected functions, closure captures, dynamic calls,
  protected-name rebinding/shadowing, direct eval and with-statements are rejected.
  Bindings that shadow runtime dependencies are also rejected. Unsupported input
  must not silently become a different calculation.
  Writes to CommonJS `require` are rejected, including nested scopes and harmless
  writes to a local shadow, because the VM uses the module wrapper's loader.
- The format-2 VM uses per-function opcode/codec choices and current-instruction
  fetch/operand decoding. Its program checksum runs at the first selected call.
  It is not authenticated tamper resistance, and its keys/runtime remain local.

## Execution and deployment

JavaScript and TypeScript have separate, explicit application validation contracts through
`protection_source_validate`, `ProjectService.validate()` or the bridge CLI.
The pure scalar contract cannot authorize ordinary application imports.
TypeScript uses `typescript_mixed_module_application_samples` and the original
relative `.ts` source path. It requires a fresh, independently invoked reference
transpilation with the pinned compiler and matching build-baseline bytes. The
current route supports one `.ts` entry with owned JavaScript/JSON siblings; other
TS source files, arbitrary TS import graphs and runtime-entry collisions are
refused. See the [owned TS application example](../samples/multilang/typescript_application/project.json).

Use [the owned application contract](../samples/multilang/javascript_mixed/application-contract.json)
as a starting point. Its `kind` is `javascript_mixed_module_application_samples`;
`source` identifies the original relative `.js`/`.cjs` module, `entrypoints`
declares selected exported functions and `preserved_entrypoints` optionally adds
unprotected exported functions. Parameters declare `number`/`bigint` inclusive
integer sampling bounds or `boolean`. The validator adds numeric edge cases,
including negative zero, infinities and NaN. Unsupported return objects/strings
are refused; only scalar values and bounded thrown-type tags are compared.
Create the contract before planning if it lives in the project directory;
adding or changing a file there after planning invalidates the pinned snapshot.

```powershell
python -m antirea.defense_mcp source-validate --plan-id <built-plan-id> --contract samples/multilang/javascript_mixed/application-contract.json --random-cases 8192
```

This call explicitly runs ordinary owned application startup in two separate
bounded Node processes. Each gets a fresh staged package, allow-listed environment
and private temporary directory. Requests/replies and process logs remain private
under the source plan's new `validation-*` directory. The original reference is
the planned JS source (UTF-8 BOM normalized), not a regenerated equivalent program.
The working-source hash is separately checked against that original before VM
replacement, excluding a leading shebang as the compiler does.
For TypeScript the reference invocation uses the same pinned compiler/options
but no protection transform. Raw and BOM-normalized TS identity, emitted JS
identity, helper/compiler pins, persisted reference and process-cleanup evidence
are checked. Both staged trees replace the original `.ts` entry with a `.cjs`
entry, rather than leaving the original TS body as a fallback. This is not a
second compiler implementation, full type checking or a whole-project TS build.
Saved plan/result, engine/compiler/runner pins, original sources and staged
inventories are checked around execution. Result arrays are retained for two
repetitions per arm, and the parent computes agreement and repeatability itself.

`mixed_application_samples_passed` means matching sampled scalar observations
only, not whole-application equivalence. UI text, stdout and general side effects
are not compared. The require-path bound and Windows Job cleanup are not an OS
sandbox; owned code still has Node's normal APIs. Before/after hashes cannot prove
the absence of a transient swap-and-restore. Timing is call/observation overhead,
not an application startup benchmark or performance acceptance test.

Deploying a module requires preserving its original package/import context and
testing the whole owned application separately. The builder does not install or
copy dependencies and does not automatically replace a user's source module.
CommonJS Node is the target; ESM, browsers and arbitrary bundles are not claimed.
Global monkeypatching, reflective/introspection equivalence and general object or
runtime behavior are outside the supported scalar contract.

An additional explicit
[script application integration route](multilanguage-development.md#script-application-integration)
now stages an ordinary CommonJS app around the saved protected module and checks
original/protected/copied-deployment CLI cases. Fresh public JS Number and TS
BigInt sample workflows passed 15 and 13 cases respectively, with missing-module
controls and exact bundles. Those two samples use the **pure** producer; mixed
JS/TS integration has adapter/unit coverage but no corresponding real app
workflow in this checkpoint. All TS originals and pure JS originals are
independently transpiled for comparison, never taken from a producer baseline.
See the phase-24 evidence (local-only record: `../results/2026-10-21/infrastructure/defense-loop/multilanguage-phase24/README.md`);
this does not establish general module/project compatibility.

New builds generate separate flattened dispatch functions for protected roots
and helpers, an indirect function-ID dispatch table, seeded state IDs with
modular-add masking, and permuted handler groups. Fetch/operand/operator helpers
remain shared. The `runtime_hardening` profile
`per_function_flattened_dispatch_v1` records generated-source structure only:
it does not prove that a JavaScript engine retains that structure after JIT
optimization. State masks, tables and decoded instructions remain locally
available. See the
phase-23 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase23/README.md`)
for fresh qualification and separately reported costs.

This is a separate JavaScript VM, **not Kagura/native hardening**. A successful
build is not proof of functional equivalence, acceptable performance or defense
against REA. External attack evaluation remains `not_evaluated`.

Owned examples: [JavaScript](../samples/multilang/javascript_mixed/project.json)
and [TypeScript](../samples/multilang/typescript_mixed/project.json).
