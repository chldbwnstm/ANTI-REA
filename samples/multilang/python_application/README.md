# Integrate a protected calculation into an ordinary Python CLI

This owned sample is a real command-line package whose integer settlement
calculation is selected for VM protection while all of its ordinary surrounding
code -- package layout, relative imports, argument parsing, input validation,
display labels and a bundled data file -- is preserved byte-for-byte. It
demonstrates the script **application integration** route: staging an original
and a protected copy of the package, running explicit sampled CLI cases against
both plus an independently copied deployment bundle, and a missing-module
control. It is not automatic whole-application deployment, UI validation, or any
attack-resistance claim.

## Package and selection

```text
python_application/
  project.json               producer plan (mixed_module, selects net_settlement)
  core-contract.json         mixed-module scalar-validator contract for net_settlement
  integration.json           script_application_integration file inventory
  app-contract.json          script_application_samples CLI cases
  integration-spec.json      alias of integration.json (preserved original name)
  application-samples.json   alias of app-contract.json (preserved original name)
  ledger_app/
    __init__.py              package marker
    __main__.py              ordinary argparse entry point (the integrated caller)
    billing.py               selected calculation plus unselected presentation code
    labels.py                public display labels
    notes.txt                ordinary bundled data file
```

The public runner reads the canonical names `project.json`, `core-contract.json`,
`integration.json` and `app-contract.json`. `integration-spec.json` and
`application-samples.json` hold identical content under the earlier names and are
kept for continuity.

`project.json` selects `net_settlement` in `ledger_app/billing.py`;
`rounded_fee` is an included helper. Both use only integer parameters and local
values -- never module globals -- as the mixed-module backend requires. The
presentation function `render_statement` reads the public labels, validates CLI
input and calls `net_settlement` by its original name. The entry point imports
`render_statement` normally, reads the first line of `notes.txt` and prints a
statement. Monetary values are in cents; 100 basis points is 1%; the fee is
rounded to the nearest cent, half up.

The protected build replaces exactly one file -- `ledger_app/billing.py` -- with
the producer's protected artifact. Every other file is identical in the original
and protected trees. `baseline.py`, build reports and extracted-scope evidence
are defender-private and are never placed in a deployment bundle.

## 1. Plan and build the protected module

Use the repository's configured Python environment from its root with a bridge
config whose owned workspace contains this sample (default
`.runs/protectors.local.json`). This route does not require native Kagura and
installs no dependencies. Do not clear a defense STOP marker to run an example.

```powershell
$plan = (python -m antirea.defense_mcp source-plan --project samples/multilang/python_application/project.json --seed 20261020 | ConvertFrom-Json)
if ($plan.status -ne "planned" -or $plan.blockers.Count -ne 0) { throw "Resolve source-plan blockers first" }
$build = (python -m antirea.defense_mcp source-build --plan-id $plan.plan_id --fingerprint $plan.fingerprint | ConvertFrom-Json)
if ($build.status -ne "artifact_created_unvalidated") { throw "No unvalidated protected artifact was produced" }
```

The build JSON must show `backend` = `python_mixed_module_vm`,
`coverage.selected_functions` = `["net_settlement"]`, and `source_executed`
false. Use the returned `protected` path and artifact SHA-256 as the candidate
identity; this is applied-mechanism evidence, not proof of unchanged behaviour,
accepted speed or analysis resistance.

## 2. Validate the selected calculation on bounded random vectors

`core-contract.json` authorizes the existing mixed-module scalar validator to
compare the baseline and protected `net_settlement` on sampled integer vectors
within the declared bounds (`gross_cents` 0..100000000, `item_count` 0..1000,
`fee_bps` 0..10000 -- a domain far larger than the sample count), plus finite
edges:

```powershell
python -m antirea.defense_mcp source-validate --plan-id $plan.plan_id --contract samples/multilang/python_application/core-contract.json --random-cases 8192 --timeout-seconds 120
if ($LASTEXITCODE -ne 0) { throw "Scalar validation request failed" }
```

Require result status `mixed_application_samples_passed`; matching sampled
values/types/exception classes are functional-preservation evidence for those
vectors only, not all-input equivalence or acceptance.

## 3. Integrate the ordinary application around it

The integration spec names the single protected source, the ordinary entry
point, and the explicit file inventory. The samples contract lists CLI cases as
`{label, args, expect:{returncode, stdout}}` with stdout compared under newline
normalization only. Supply this reused build (no fresh native build):

```powershell
python -m antirea.defense_mcp protection-source-integrate `
  --plan-id $plan.plan_id `
  --integration samples/multilang/python_application/integration.json `
  --app-contract samples/multilang/python_application/app-contract.json `
  --fresh-protected-build:$false --timeout-seconds 120
```

A pass (`script_application_samples_passed`) requires that the same cases match
on the original tree, the protected tree and an independently copied deployment
bundle, and that a separate private copy with the protected module removed fails
a successful case. That control proves the protected dependency is present and
reached by the caller; it is not proof that every selected function path is
exercised, nor VM call tracing.

Ordinary invocation from a directory containing the deployed `ledger_app` is:

```powershell
python -m ledger_app --gross-cents 2500 --count 3 --fee-bps 1000
```

Its expected display is:

```text
Statement: 3 items, net USD 67.50
Thank you for your business.
```

derived from the sample calculation, not recorded execution evidence. This runs
ordinary application imports and startup and is **not** part of plan/build or any
ANTI-REA validation gate; run it only with explicit execution authorization.

## Deployment bundle

The bundle contains only the protected runtime file and the explicit unselected
runtime and data files (`__init__.py`, `__main__.py`, `billing.py` as the
protected artifact, `labels.py`, `notes.txt`). It never contains the original
`billing.py`, `baseline.py`, build reports, the spec/contract, the runpy runner
or any private path. Use fresh source files, not copied `__pycache__`/`.pyc`
caches or same-name native extensions that could shadow the replacement source.

## Limitations

- The protected calculation still carries locally available VM/runtime data;
  no secrecy, native Kagura parity or external attack resistance is established.
- Only selected top-level pure integer/bool roots and acyclic owned helpers are
  virtualized; selected code cannot read module globals -- pass them as
  arguments.
- Matching sampled outputs is functional-preservation evidence for these cases
  only, not all-input equivalence, performance acceptance or a release verdict.
- Whole-application output, side effects, performance and defense effectiveness
  remain separate, later gates.
