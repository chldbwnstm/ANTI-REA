# How to protect a calculation inside an ordinary Python package

This owned sample keeps normal relative imports, input validation, display text
and a command-line caller while selecting an integer calculation for VM
protection. It demonstrates single-module integration and an explicit sampled
application contract, not automatic whole-app deployment or full UI validation.

## Package and selection

```text
python_mixed/
  project.json
  application-contract.json
  quote_app/
    __init__.py
    __main__.py       ordinary argparse entry point
    settings.py       public display settings
    pricing.py        selected calculation plus unselected presentation code
```

`project.json` selects `quote_cents` in `quote_app/pricing.py`.
`rounded_discount` is an included helper. Both use only integer inputs/local
values; the presentation function `render_quote` reads settings, validates UI
inputs and calls `quote_cents` by its original name. The entry point imports
`render_quote` normally. Monetary values use cents; 100 basis points means 1%.
This small example rounds a nonnegative discount to the nearest cent, half up.

The [reference](../../../docs/python-mixed-modules.md) describes the exact
six-field manifest, supported selected syntax and all limitations. An explicit
`"protection_mode": "mixed_module"` is required. Do not add that field to a
pure-module project unless you intend to change its route.

## Prerequisites

Use the repository's configured Python environment from its root, with a bridge
config whose owned workspace contains this sample. The default CLI config is
`.runs/protectors.local.json`; pass a different `--config` before the subcommand
if needed. This route does not require native Kagura or install dependencies.
Do not clear a defense STOP marker just to run an example.

The commands below require the mixed frontend and application validator to be
present in your checkout. The sample contract authorizes package import and
scalar checks of `quote_cents`, not arbitrary test commands or a release verdict.

## 1. Create and review a source plan

```powershell
$mixedPlanText = python -m antirea.defense_mcp source-plan --project samples/multilang/python_mixed/project.json --seed 1729
if ($LASTEXITCODE -ne 0) { throw "Source planning failed" }
$mixedPlan = $mixedPlanText | ConvertFrom-Json
$mixedPlan | ConvertTo-Json -Depth 30
```

Inspect the returned source and sibling-file hashes, selected root/helper scope,
tool/engine hashes, output directory and blockers. The status must be `planned`.
The plan writes private records but does not import `quote_app`, run `argparse`
or execute the selected functions. Keep captured JSON outside the source tree:
adding output files beneath the manifest directory changes its snapshot.

## 2. Build the reviewed plan

After reviewing the plan, use the exact returned identity and fingerprint:

```powershell
if ($mixedPlan.status -ne "planned" -or $mixedPlan.blockers.Count -ne 0) {
    throw "Review and resolve source-plan blockers first"
}
$mixedBuildText = python -m antirea.defense_mcp source-build --plan-id $mixedPlan.plan_id --fingerprint $mixedPlan.fingerprint
if ($LASTEXITCODE -ne 0) { throw "Source build request failed" }
$mixedBuild = $mixedBuildText | ConvertFrom-Json
$mixedBuild | ConvertTo-Json -Depth 30
if ($mixedBuild.status -ne "artifact_created_unvalidated") {
    throw "No successful unvalidated artifact was produced"
}
```

The generated paths live under `.runs/source-protection/`. An attempted plan
cannot be reused. If a source, sibling, engine or tool changes, create/review a
new plan rather than editing the old fingerprint.

## 3. Inspect coverage without executing the application

Check these fields in the returned build JSON:

| Field | Required sample value |
| --- | --- |
| `backend` | `python_mixed_module_vm` |
| `coverage.selected_functions` | `["quote_cents"]` |
| `coverage.helper_closure` | `["quote_cents", "rounded_discount"]` |
| `coverage.format_version` | `2` |
| `source_executed` and `execution_authorized` | Both `false` |
| `coverage.validation_exports` | `[]` |

These are checks of applied mechanism and scope, not proof of unchanged behavior,
accepted speed or resistance to analysis. Use the returned `protected` path and
artifact SHA-256 as the candidate identity. `baseline.py` is the original source;
keep it and build reports private.

## 4. Explicitly validate sampled calculation behavior

This step executes ordinary owned package startup in fresh baseline/protected
children. Review the sample sources and contract before invoking it:

```powershell
python -m antirea.defense_mcp source-validate --plan-id $mixedPlan.plan_id --contract samples/multilang/python_mixed/application-contract.json --random-cases 8192 --timeout-seconds 120
if ($LASTEXITCODE -ne 0) { throw "Validation request failed" }
```

Require result status `mixed_application_samples_passed`; a successful CLI
transport alone is not acceptance. Each declared function must have matching
sampled values/types/exception classes and repeated behavior. Plan, engine and
package changes cause refusal. Validation records and raw replies are private.
The contract intentionally has no preserved entrypoints: `render_quote` returns
a string, which this scalar contract does not compare. UI output, side effects,
deployment, performance and external defense effectiveness remain separate gates.

## Deployment is a separate step

Prepare a fresh private copy of `quote_app` and retain its package name,
`__init__.py`, `__main__.py` and `settings.py`. Replace only that copy's
`quote_app/pricing.py` with the exact bytes from `$mixedBuild.protected`. Do not
overwrite your source project or ship the private build directory. ANTI-REA
currently produces the replacement file, not an assembled package or installer.
Use fresh source files, not copied `__pycache__`/`.pyc` caches or same-name native
extension artifacts that could prevent the replacement source from loading.

The package's ordinary invocation, from the directory containing `quote_app`, is:

```powershell
python -m quote_app --unit-cents 2500 --quantity 3 --discount-bps 1000
```

Its expected display is `Quote: 3 items, total USD 67.50`, derived from the
sample calculation, not recorded execution evidence. This command executes
application imports/startup and is **not** part of source-plan/source-build or an
ANTI-REA validation gate. Run application checks only with explicit execution
authorization and appropriate bounds.

Do not feed this build to `python_integer_samples` or another pure scalar
validator. Only the explicit mixed application contract above authorizes package
execution. Whole-application output/side effects and performance need separate
evaluation before use.

## Troubleshooting

- Unknown field or missing opt-in: use the exact manifest; pure mode omits
  `protection_mode`, while mixed mode requires `"mixed_module"`.
- Selected global-value error: pass required state through function arguments.
  Moving a value to an apparent module constant does not make it supported.
- Protected-name rebind error: do not overwrite selected roots/helpers. Dynamic
  monkeypatching is unsupported; runtime guards do not promise equivalent behavior.
- Plan fingerprint/input change: create a fresh plan and review it again.
- Relative import failure: preserve `quote_app/pricing.py` in its package; do
  not import or run the replacement as a top-level `protected` module.
- Validation refusal: this is an intentional execution-authority boundary,
  not a reason to strip the backend metadata or use the pure validator.

The selected algorithm still has locally available VM/runtime data. Native
Kagura passes and external attack resistance are not established by this sample.
