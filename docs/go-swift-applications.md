# Native application source-integrate (Go / Swift)

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

> **Status (2026-10-20, Windows fixture qualification passed):** both fresh public
> workflows and independent raw-evidence audits passed. Go: 68,128 scalar
> comparisons, 17 app cases and 17 copied-deployment cases. Swift: 136,256 scalar
> comparisons, 15 app cases and 15 copied-deployment cases. Both passed
> missing/unset-core controls. Final full discovery passed **2,506 tests with
> 82 explicit opt-in skips**, zero failures/errors/xfails (2,588 total).
> A stale C# test-fixture assumption and the new tests' temporary-directory
> setup were corrected with all failed runs retained.
> Runtime implementation, tools and sample bytes are unchanged since the passing
> application runs; an exact test-only delta audit and independent full-suite
> audit verified that boundary. The four Orca worker contributions are settled and released.
> External attack resistance, performance and defense strength are **not evaluated**.
> See the Phase22 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase22/README.md`).

## What this route does

The existing `go_frontend` / `swift_frontend` turn a *separated, pure scalar
core* Go/Swift source project into a protected native DLL (fixed-width integer
roots plus an owned helper closure). On its own, an application that *uses* that
core still ships and calls the original Go/Swift implementation — the protection
is never reached.

The **application source-integrate** route closes that connection gap for a
specific, bounded architecture. The owned scalar core files are already compiled
into a pinned protected native DLL by the existing source frontend. Ordinary app
files are separate but live in the **same fingerprinted project directory**. Two
compilations are defined:

1. **Original app:** unchanged app sources + unchanged original core sources.
2. **Protected app:** the **same app source bytes** + generated **same-name core
   facade declarations** and trusted loader/binding sources — **never** the
   original core sources.

The old core/helper/constant implementation must not enter the protected app's
compiler argv or its deployment. There is **no** regex rewriting of user source,
**no** new external dependency, and **no** arbitrary compiler flags or build
hooks. Facade declarations originate only from authenticated producer metadata.
A missing helper/constant reference in the ordinary app **fails compilation** —
there is no silent fallback to the original implementation.

Packaging is **not** a new protection strength: roots and owned helpers still
receive the producer's native core / VM / runtime passes, and an ordinary
unprotected app's references and invocation order remain visible.

## Implementation modules

| Module | Role | Entry point |
| --- | --- | --- |
| `antirea.go_application_facade` | Pure Go facade generation / metadata parse / checking. **No execution.** | `generate_facade(producer, output_dir)` |
| `antirea.swift_application_facade` | Pure Swift facade generation (same API). **No execution.** | `generate_facade(producer, output_dir)` |
| `antirea.native_app_integration` | Reusable execution engine. | `run_integration(*, producer_report_path, integration_spec_path, application_contract_path, output_dir, workspace_root, timeout_seconds=120, trusted_inputs=None)` |
| `antirea.native_application` | Public service binding (parity with the JVM / C# source-integrate). | `integrate_source_application(service, plan_id, integration_spec_path, contract_path, *, timeout_seconds=120)` |

Public routing, the toolchain module list, and CLI/MCP help are owned by root in
`projects.py` / `defense_mcp.py`. The service dispatches to the native engine
only for a successful source-build plan whose backend is `go_typed_native`
(Go) or `swift_llvm_native` (Swift). The public CLI uses
`source-integrate --plan-id <id> --integration-spec <path> --contract <path>
--timeout-seconds <n>`. Application specs and cases are separate from the scalar
native-core validation contract. Both must have been present in the source
snapshot when `source-plan` created the plan.

### Example workflow

With the reviewed local toolchain configured, start with either
`samples/multilang/go_application` or `samples/multilang/swift_application`.
For the Go fixture:

```powershell
python -m antirea.defense_mcp source-plan --project samples/multilang/go_application/project.json --seed 20261022
# Review the returned plan; replace the placeholders with its exact values.
python -m antirea.defense_mcp source-build --plan-id <plan_id> --fingerprint <fingerprint>
python -m antirea.defense_mcp source-validate --plan-id <plan_id> --contract samples/multilang/go_application/native-contract.json --random-cases 8192 --timeout-seconds 300
python -m antirea.defense_mcp source-integrate --plan-id <plan_id> --integration-spec samples/multilang/go_application/integration.json --contract samples/multilang/go_application/application-contract.json --timeout-seconds 120
```

The angle-bracket values are placeholders, not literal PowerShell arguments.
Use `swift_application` in all three sample paths for Swift. `source-validate`
and `source-integrate` explicitly execute the owned programs; plan/build do not
run the target. Changing a source/spec/case/tool requires a new plan.

### Generated runtime binding and loader

Facade generation reuses the existing `antirea.bindings.generate_bindings` pure
generator in a **private subdirectory**, and the facade manifest exposes only the
trusted compile inputs. The generated `NativeCore` wrapper (Go `Call_<symbol>` /
Swift `call_<symbol>`) calls the protected native core through the common C
bridge's fail-closed loader:

- The loader initializes on the **first protected call** from the absolute
  local-drive DLL path named by the `ANTIREA_NATIVE_CORE` environment variable —
  with **no** fallback, default-path, or ambient-`PATH` search dependency.
- The core is initialized **once** and retained for the process lifetime. The
  C bridge publishes its handle and function pointers only after **every** export
  symbol resolves; a missing symbol fails the load, and a call issued before a
  successful init aborts rather than fabricating a result.
- There is **no** original algorithm body and **no** embedded lookup in the
  facade — the emitted declaration body only loads and calls the generated
  `NativeCore` bridge and returns.

The protected native core DLL is expected to export the **plain** contract symbol
names (both the C-bridge and the Go Windows/amd64 syscall path resolve exports by
the plain name).

## Go specifics

- One `package main`, **Windows/amd64**, **no** cgo, modules, build hooks, or
  network fetch. The generated core binding package is `nativecore`; the Windows/
  amd64 binding uses the standard library (`syscall`) with no cgo and no separate
  C bridge DLL. Existing Go-source protection of *other* package names is
  unchanged; the app route **rejects a non-`main` package** rather than silently
  renaming the user app or core.
- Ordinary standard-library features are allowed in app code. Root compiles with
  explicit file argv and `GOWORK`/`GOENV`/modules/proxy/sumdb/telemetry disabled,
  using a private cache.
- Facade metadata: `metadata.json` is located under
  `Path(producer["contract_path"]).parent`, pinned by
  `producer["frontend_artifact_hashes"]["metadata.json"]`; roots are matched
  against the producer methods/selectors/contract and the metadata signatures.
- In the facade manifest, Go `c_sources` and `include_dirs` are **empty**, and
  `source_roots[].external_labels` is `[]`.

## Swift specifics

- Explicit app sources including `main.swift`, compiled as the **same module**.
  Original Swift names **and** external argument labels are preserved from the
  pinned compiler-produced `.swiftinterface`. The original core remains untouched.
- Linking uses the **existing common C bridge** statically linked into `app.exe`
  plus the generated Swift `NativeCore` — not a newly invented ABI. Reviewed
  installed runtime DLLs are packed; the exact pinned runtime DLL list is supplied
  by root. There is **no** SwiftPM, macOS, or general package-graph claim.
- Facade metadata: the contract is authenticated from the producer's
  `contract_path` against `artifact_hashes["frontend/contract.json"]` (there is
  **no** inline contract field for Swift). Labels are derived from
  `producer["public_interface"]` at its pinned path+sha — from the compiler
  interface, **not** the original source — and the facade matches
  `source_functions` + contract. The external/internal label distinction
  (including the unlabeled `_` form and named labels) is preserved and reflected
  in `source_roots[].external_labels`.
- In the facade manifest, Swift `c_sources` is the exact common C bridge
  implementation and `include_dirs` is the modulemap/header directory required by
  `import AntireaBridge` (the binding generator supplies the modulemap).
- Windows SDK preparation makes private copies of three pinned Swift module
  maps (`ucrt`, `winsdk_shared`, `winsdk_um`). Both app compilations receive the
  same explicit map flags. The original maps, private copies and explicitly
  mapped headers are checked between child processes; installed SDK files are
  not changed. This is not an inventory of all transitive SDK headers.
- `nonisolated(unsafe)` in generated facade state suppresses Swift concurrency
  checking. It does **not** establish thread-safe concurrent VM calls.

## Integration spec (strict schema)

```json
{
  "schema_version": 1,
  "kind": "native_application_integration",
  "language": "go",
  "application_sources": ["main.go"]
}
```

`language` is exactly `go` or `swift`. Sources are resolved relative to the spec
parent, must be members of the same project snapshot, must **not overlap** the
original core set, and number **1..32** unique files of the proper suffix. No
caller-supplied flags, commands, DLL paths, imports directories, or runtime-path
fields are accepted.

## Application contract (strict schema)

```json
{
  "schema_version": 1,
  "kind": "native_application_samples",
  "cases": [
    {"label": "normal", "args": ["7", "3"], "expect": {"returncode": 0, "stdout": "42\n"}}
  ]
}
```

- **1..64** unique case labels; `expect` keys are **exactly** `returncode` and
  `stdout` — there is no `stderr` equivalence. At least one success case is
  required.
- The **first** success case must exercise the native roots, proven by the
  missing/unset-core negative controls. A well-formed app contract should cover
  all selected exports, signed/unsigned edges, and normal/zero/multi-iteration
  and usage-failure behavior.
- Core semantics are **not** changed to produce passing evidence, and
  `expectedFailure` placeholders are not accepted.
- Standard output is compared byte-for-byte after UTF-8 encoding the declared
  string. The checked Windows Swift fixture declares `\r\n`; no newline
  normalization or numeric-result substitution is performed.

## Engine report and deployment

The engine persists its exact report at `<output_dir>/integration.json`
(`kind: native_application_integration`). Each executed child carries exactly one
reference record (`label, kind, arm, case_label, control, receipt_path,
receipt_sha256, stdout_log, stderr_log`), and the comparison uses the exact labels
`case:<label>:original|protected`, `control:missing_core`, and
`control:unset_core`. Unlike the JVM route there is **no** adapter control: neither
runtime uses an external adapter DLL. Preparation steps use the exact labels
`compile-original` / `compile-protected` (Go) and `sdk-capture` / `compile-bridge`
/ `compile-original` / `compile-protected` (Swift).

The deployment bundle contains **only** `app.exe`, the protected native core DLL
(`protected.dll`), and the exact pinned Swift runtime DLL list — all suffixes
`.exe` / `.dll`. No original app exe, baseline, source, IR, object, library,
report, or metadata is deployed; the verifier rechecks exact membership, hash and
size and rejects forbidden original hashes. The integration itself **reuses** the
producer's protected DLL (`fresh_protected_native_build: false`); building a fresh
protected core is a separate root-owned workflow that runs first.

Source/app/core/facade/toolchain/native pins are checked **before and after each
child** and at postflight. The original and protected compiler input snapshots
differ **only** in original core sources (original build) versus generated facades
and trusted bindings (protected build); no original core source appears in the
protected compiler argv.

## Honest limits

An authenticated `native_application_samples_passed` result means
only this: for the explicit sampled cases, the protected application produced the
same `stdout` and exit status as the original, with authentic source / core /
toolchain / staged-artifact pins, present missing-core and unset-core fail-closed
controls, an exact deployment allowlist, and a final STOP/pin recheck.

It will **not** establish all-input equivalence, `stderr`/exception equivalence,
REA / attack resistance, performance acceptance, macOS support, or arbitrary
SwiftPM / Go-module / package-graph support. Owned source executes only inside
bounded owned processes with Windows Job cleanup; **process cleanup is not a
security sandbox.** A mock or pure unit test is **not** a compiler or application
qualification. Each language needs its own fresh source/runtime evidence, and the
full qualification requires fresh source builds, ≥8192 original-runtime inputs
per export, application cases, missing/unset-core controls, copied-deployment
reruns, full regression, and independent raw audits. Retained failures and
subsequent test-only snapshot changes must remain explicit.

The overall goal — C / Rust / Swift / Go / C# / Java / Kotlin / Python / JS / TS
plus the engine's existing protection capabilities — remains open; this route
closes only the ordinary Go/Swift *application connection* gap.
