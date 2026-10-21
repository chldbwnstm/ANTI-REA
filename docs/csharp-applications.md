# C# application integration

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

The experimental `source-integrate` command connects a reviewed C# source build
to an ordinary managed application. It replaces selected supported method bodies
with calls into that build's protected native core, preserves unselected code,
compiles original and protected applications, and compares explicitly declared
command-line cases. It is an **execution command**, not a dry-run planner.

Phase20 integration and qualification are tracked in
the development record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase20/README.md`).
Use that record for verified results; the existence of a command is not evidence
of whole-language support or external defense strength.

The fresh public qualification (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase20/public-csharp-qualification.md`)
passed on Windows: three methods × 8,516 original CLR inputs, ten managed-app
cases, and the same ten cases after relocating only the three deployment files.
The read-only raw audit verified 75 process-cleanup records. This establishes the
recorded sample workflow, not arbitrary .NET compatibility or defense strength.

## Owned project inputs

Keep the source manifest, C# files, integration specification and both validation
contracts in the same dedicated project directory. All must exist when planning;
changing or adding source inputs after planning requires a new plan/build.

- `project.json`: existing `language: csharp` manifest with source files and selected
  method type/name/export entries.
- `integration.json`: schema version 1, source list and selected type/name/parameter/
  export mappings, with `interop_type: global::NativeCore` and
  `native_library: antirea_contract`.
- `native-contract.json`: scalar ABI signatures for original CLR vs native baseline/
  protected validation.
- `application-contract.json`: schema version 1, kind `csharp_application_samples`,
  explicit `cases` containing `label`, `kind`, and `args`, with optional `expect`.
  Normal values and usage/exception cases are distinct observations. A finite
  collection of CLI cases does not establish full GUI or side-effect equivalence.

Include at least one value case with `expect.returncode: 0` that exercises the
protected core. The first such case supplies the arguments for the missing-core
and unset-core controls; no sample arguments are inserted implicitly.

Example shape:

```json
{
  "schema_version": 1,
  "kind": "csharp_application_samples",
  "cases": [
    {"label": "ordinary", "kind": "value", "args": [7, 3],
     "expect": {"returncode": 0, "stdout_is_integer": true}},
    {"label": "usage", "kind": "value", "args": [],
     "expect": {"returncode": 2}}
  ]
}
```

## Explicit workflow

Using an existing local defense-bridge configuration and toolchain:

```powershell
python -m antirea.defense_mcp source-plan --project samples/multilang/csharp_application/project.json
python -m antirea.defense_mcp source-build --plan-id <plan-id> --fingerprint <fingerprint>
python -m antirea.defense_mcp source-validate --plan-id <plan-id> --contract samples/multilang/csharp_application/native-contract.json --random-cases 8192
python -m antirea.defense_mcp source-integrate --plan-id <plan-id> --integration-spec samples/multilang/csharp_application/integration.json --contract samples/multilang/csharp_application/application-contract.json
```

The MCP equivalent is `protection_source_integrate`, with `plan_id`,
`integration_spec_path`, `contract_path` and optional `timeout_seconds` (1–600).
Source planning/building does not execute the application. Scalar validation and
application integration do. Compilers and owned startup code are not sandboxed;
do not use received or untrusted source.

The integration command derives the native artifact from the saved source plan,
not a caller-supplied DLL path. It checks source/tool/producer evidence and creates
an append-only integration record. The engine consumes an already-built native
artifact, so its reuse flag remains explicit. A new source-build earlier in the
same workflow is separate evidence of fresh protection, not something integration
alone may claim.

## Deployment and boundaries

Only the compiled protected managed DLL, its runtime configuration and the native
DLL belong in the local deployment bundle. Original sources, lowered C/LLVM,
baseline binaries and internal test evidence stay outside it. Launch instructions
identify the compatible installed .NET runtime and `ANTIREA_NATIVE_CORE` binding.
No package restore, installation, remote publication or automatic synchronization
is performed by this route.

Supported selected methods are call-free `public static` integer leaves using
`int`, `uint`, `long` or `ulong` within the existing IL lowering subset. Unsupported
constructs fail instead of being approximated. This is not whole-assembly rewriting,
NativeAOT, arbitrary csproj/MSBuild hooks, general managed objects, exceptions inside
protected leaves, or macOS support. Surrounding application code may remain ordinary
managed code and is not thereby protected.

Saved hashes and process receipts detect retained changes and verify cleanup;
they are not cryptographic signatures, an atomic hostile-code sandbox or proof
against transient changes. Functional correctness, performance acceptance and
external reverse-engineering resistance remain separate evaluations.
