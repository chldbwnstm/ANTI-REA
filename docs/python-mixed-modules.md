# Python mixed-module protection reference

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

The experimental `mixed_module` mode transforms selected integer/bool functions
inside an ordinary owned Python module. Imports, presentation code, classes and
unselected functions remain ordinary Python. The selected roots and their
supported same-module helpers become format-2 VM instructions and callable
wrappers at their original names. This is a single-module replacement route,
not whole-Python or package-wide protection.

Use the [quote application how-to](../samples/multilang/python_mixed/README.md)
for the reviewed plan/build workflow. The existing
[pure-module route](../samples/multilang/python/README.md) remains the default.

## Manifest

These six fields are required; additional fields are rejected:

```json
{
  "schema_version": 1,
  "name": "python-mixed-quote",
  "language": "python",
  "sources": ["quote_app/pricing.py"],
  "functions": ["quote_cents"],
  "protection_mode": "mixed_module"
}
```

| Field | Accepted value |
| --- | --- |
| `schema_version` | Integer `1`, not a boolean |
| `name` | 1..64 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` |
| `language` | Exactly `"python"` |
| `sources` | Exactly one existing relative `.py` path inside the manifest directory; no drive, parent traversal or linked path |
| `functions` | 1..64 unique top-level selected function names, matching `[A-Za-z_][A-Za-z0-9_]{0,127}`; `__`, `_ar_` and `_arm_` generated/reserved prefixes are unavailable |
| `protection_mode` | Exactly `"mixed_module"` |

The manifest is UTF-8 JSON, at most 256 KiB. Source must be UTF-8, at most
512 KiB and 20,000 AST nodes. Selection may expand to at most 128 functions
including helpers. Keep the manifest in a dedicated owned project directory,
not the workspace root. Source planning snapshots its bounded directory tree,
including unselected package dependencies: at most 1,024 entries, 16 MiB per
nonempty file and 64 MiB total. Changing a sibling source or configuration after
planning requires a new plan.

Omit `protection_mode` entirely to use the existing pure-module schema. Neither
`"pure_module"` nor `null` is a valid explicit mode in that schema.

## Supported selected code

Selected roots must be top-level synchronous functions. Owned acyclic helpers
are discovered from direct calls in the same module. Inputs are exact Python
`int`/`bool` values. Supported operations include integer arithmetic, comparisons,
short-circuit conditions, local assignments, supported loops and the existing
pure frontend's small builtin set. Ordinary parameter names and optional
`int`/`bool` annotations are retained. Internal helper calls use positional
arguments. The pure subset reference lists the
[operations and exclusions](../samples/multilang/python/README.md).

Mixed mode additionally rejects selected reads of **all module-global values**,
even a seemingly constant integer. Pass configuration through parameters; do
not expect mutable application state to be silently captured during build.
Only supported functions are VM-protected. Selected defaults, decorators,
positional-only/keyword-only/variadic parameters, recursive helpers, imported
calls, objects, floating point, async and generators remain unsupported.

Explicit protected-name rebinding/import/deletion is rejected. Comprehension
iteration variables are local, while walrus assignments to an enclosing
protected global are rejected. Generator writes are checked even when deferred
or never consumed. `import *` and the `_arm_` identifier prefix are rejected
throughout the module. Dynamic namespace mutation/reflection is outside the
supported contract, not proven harmless.

Reached helper and builtin calls check expected bindings. Rebinding can raise
an explicit unsupported-behavior error; this is not equivalent to arbitrary
Python monkeypatching. Missing helper bindings retain `NameError`. These checks
are correctness guards, not authentication or anti-tamper protection.

## Commands and artifacts

From the repository root, using its configured Python environment:

```powershell
python -m antirea.defense_mcp languages --language python
python -m antirea.defense_mcp source-plan --project samples/multilang/python_mixed/project.json --seed 1729
```

After reviewing a `planned` response with no blockers, pass its exact `plan_id`
and lowercase SHA-256 `fingerprint` to `source-build`. The
[how-to](../samples/multilang/python_mixed/README.md) shows PowerShell JSON capture
without placeholder arguments. MCP equivalents are `protection_languages`,
`protection_source_plan` and `protection_source_build`. Seed defaults to 1729;
the shared source-plan interface accepts integers 1..2,147,483,647.

The default config is `.runs/protectors.local.json`; an alternate config goes
before the command: `python -m antirea.defense_mcp --config PATH source-plan ...`.
The config's workspace root defines the owned boundary. No Kagura/native
compiler or third-party application dependency is installed or needed by this
Python transformation. A build attempt consumes its plan; retry with a fresh
plan instead of rewriting old evidence. STOP remains authoritative.

Plan/build parse source and write private outputs; they do not import the user
module, execute application startup or run the generated VM. Success is
`artifact_created_unvalidated`, with backend `python_mixed_module_vm` and
`source_executed: false` / `execution_authorized: false`.

| Artifact | Meaning |
| --- | --- |
| `protected.py` | Candidate replacement bytes for the selected original module |
| `baseline.py` | Exact original selected module; defender-private |
| `coverage.json` | Selected roots, helper coverage, replacement spans and artifact hashes; defender-private |
| `report.json` | Build inputs, hashes, mechanism and unevaluated statuses; defender-private |

Private service outputs live under `.runs/source-protection/`. Check the returned
paths and hashes; do not hardcode a generated job ID or copy the entire build
directory into a deployment.

## Deployment and validation boundary

Keep the original package name, module path, sibling modules and resources. In
a **fresh private deployment copy**, replace only the selected module with the
bytes at the returned `protected` path. For the sample, that means replacing
`quote_app/pricing.py`, not running the standalone file as `protected.py` or
changing callers to import a new module name. Preserve relative imports and
normal application entry points. The frontend does not assemble/install a
package or patch the original source tree.

Use a fresh source-only deployment tree for this module. Do not carry old
`__pycache__`/`.pyc` files or a same-name native extension that could be loaded
instead of the replacement source. A later application-level check must confirm
the intended module and protected callable bindings actually execute; matching
business outputs alone would not establish that protection was used.

This replacement retains same-module calls and imported public names through
wrappers. It adds runtime initialization/import cost, and selected docstrings,
source lines, tracebacks and introspection are not preserved identically.
Unselected code remains unprotected and can reveal behavior or context.

`source-validate` accepts mixed builds only with the explicit
`python_mixed_module_application_samples` contract. This authorizes imports and
ordinary startup of the owned package in separate baseline/protected child
processes. `python_integer_samples` still cannot authorize those imports. Do not
relabel the backend or use the pure validator to bypass the contract boundary.

The exact contract has five fields: `schema_version: 1`, `kind`, the dotted
`module` name, nonempty `entrypoints`, and `preserved_entrypoints` (possibly empty).
Each entrypoint has `name` and `parameters`; each parameter has `name`, integer
`minimum` and integer `maximum`. Selected entrypoints must be selected VM roots;
preserved ones must be declared unprotected functions. All sampled entrypoints
must accept the supported scalar inputs and return exact int/bool values or
raise exceptions. See the [sample contract](../samples/multilang/python_mixed/application-contract.json).

The service verifies the original plan fingerprint, build identity and unchanged
engine/toolchain, then binds every copied source sibling to that plan before
launch. Staging excludes bytecode caches and rejects links, namespace packages,
overlapping output directories, excess files/entries/depth/bytes and source
drift. Each target must load from its exact staged file using the standard source
loader. Timeout/STOP and process-tree cleanup are checked; this is not an OS
sandbox and cannot make hostile application startup safe.

Success is `mixed_application_samples_passed`: sampled values, types and
exception classes match, with repeated observations and consistent public
surface/signatures. Reports and raw child replies remain private and append-only.
It does not compare UI text, stdout, side effects or exception messages, prove
all-input equivalence, establish VM dispatch independently, or accept performance.
Import hooks and already-loaded modules are not isolated. Whole-application
behavior and deployment checks remain necessary before distribution.

## Protection limits

An additional explicit `source-integrate` route now stages an ordinary Python
app around the saved protected module, using a fixed private `runpy` bootstrap
and an explicit file inventory. The [owned package fixture](../samples/multilang/python_application/)
passed four CLI cases across original/protected/copied-deployment arms and a
missing-module control, in a fresh public workflow. This is separate from the
scalar validation above: stdout/return codes are checked only for the declared
app cases, not all package behavior or side effects. See
[script app integration](multilanguage-development.md#script-application-integration)
and the phase-24 evidence (local-only record: `../results/2026-10-21/infrastructure/defense-loop/multilanguage-phase24/README.md`).

The Python VM uses function-local instruction encoding and current-instruction
decoding. New builds also generate a separate flattened dispatch function for
each protected function, a function-ID dispatch table, seeded state IDs with
XOR masking, and permuted handler groups. Fetch/operand/operator helpers remain
shared; these are Python functions, not separate native VMs. The emitted
`runtime_hardening` evidence describes generated source, not JIT retention or
measured attack resistance.

Import-time checksum data is not authenticated and does not cover runtime code.
Keys, state masks, tables and decoded instructions remain locally available.
No native Kagura passes, anti-debug/dump, whole-application constants protection,
performance guarantee or external REA resistance is implied. See the
phase-23 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase23/README.md`)
for fresh functional qualification and separately reported costs.

See [multi-language development](multilanguage-development.md) and
[hardening capabilities](hardening-capabilities.md) for the broader boundaries.
