# JVM application source-integrate (Java / Kotlin) — experimental

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

> **Status (2026-10-20):** fresh public Java **and** Kotlin workflows passed
> source build, original-JVM comparison, app integration, missing/unset-core and
> adapter controls, and relocation. An independent read-only audit checked the
> raw records: per language, 51,096 scalar comparisons, 11 original/protected app
> cases and 11 relocated cases; 75/76 clean process records. See
> the qualification record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase21/public-jvm-qualification.md`).
> The separate frozen full regression passed 2,271 tests with 82 explicit opt-in
> skips and zero failures/errors. These are **sampled functional**
> results, not whole-application equivalence, performance acceptance or measured
> defense strength. External attack resistance remains **not evaluated**.

## What this route does

The existing `jvm_frontend` turns a *separated, pure scalar core* Java/Kotlin
source project into a protected native DLL (int/long static roots plus an owned
acyclic static-helper closure). On its own, an application that *uses* that core
still ships and calls the original JVM implementation — the protection is never
reached.

The **application source-integrate** route closes that gap for a specific,
bounded architecture:

1. A **core source project** (already accepted by `jvm_frontend`) is built into
   the protected native core DLL, exactly as today.
2. **Ordinary application source files** live in the same fingerprinted project
   tree and are compiled against the *original* core classes. The application
   bytecode is preserved unchanged.
3. In the protected bundle, the original core classes are **replaced in place by
   same-name facade classes**. Each facade keeps the original class's identity
   and path but forwards every original public static *root* descriptor to
   packaged JNI bindings and the pinned protected native core DLL. The
   application binds to the same method identities, so its unchanged bytecode now
   calls the protected core.

There is **no** regex rewriting of Java/Kotlin source, **no** new external
bytecode dependency, **no** arbitrary compiler flags or build hooks, and **no**
whole-JAR or whole-language claim.

## The three modules (lanes)

| Module | Role | Entry point |
| --- | --- | --- |
| `antirea.jvm_facade` | Pure parsing / generation / checking. **No execution.** | `generate_facades(producer, output_dir)`, `inspect_application_classes(class_files, producer)`, `validate_facade_classes(class_files, producer)` |
| `antirea.jvm_app_integration` | Reusable execution engine. | `run_integration(*, producer_report_path, integration_spec_path, application_contract_path, output_dir, workspace_root, timeout_seconds=120, trusted_inputs=None)` |
| `antirea.jvm_application` | Public service binding (parity with the C# source-integrate). | `integrate_source_application(service, plan_id, integration_spec_path, contract_path, *, timeout_seconds=120)` |

Public routing, the toolchain module list, and CLI/MCP help are owned by root in
`projects.py` / `defense_mcp.py`. The service dispatches to the JVM engine only
when the bound source-build result has backend `jvm_bytecode_native`.

> **Shared-schema (reconciled).** The facade's producer argument (the full
> producer report), the status token each facade function returns
> (`accepted`/`rejected` with a `violations` list; no separate boolean) and the
> fields the engine consumes now agree across the three lanes; the engine hands
> the facade the full
> re-hashed report and derives its booleans from the facade's `accepted` status.
> The earlier mismatch (audit finding **X1**) is resolved and locked by the audit
> lane's cross-seam agreement tests.

### Generated runtime namespace

Generation uses the existing `bindings` pure generator under a **fixed trusted
package `antirea.runtime`**. The generated `NativeCore` is moved into that package
and its JNI export symbols are renamed consistently to the fully-qualified name
(`Java_antirea_runtime_NativeCore_*`); JNI paths are **not** user-controlled.
Facade methods call `antirea.runtime.ProtectedBootstrap.ensureReady()` and then
the appropriate packaged `NativeCore` call. Bootstrap class initialization loads
the explicit **absolute** `ANTIREA_JNI_ADAPTER` and `ANTIREA_NATIVE_CORE` paths
exactly once in a static initializer.

**Fail closed.** If either path is unset or empty, bootstrap throws and the class
never initializes; there is **no original-algorithm fallback**.

## Integration spec (strict schema)

```json
{
  "schema_version": 1,
  "kind": "jvm_application_integration",
  "language": "java" | "kotlin",
  "application_sources": ["App.java" , "..."],
  "main_class": "sample.App"
}
```

Sources are resolved relative to the spec's parent, must be members of the same
fingerprinted project snapshot, number at most 32, and must **not overlap** the
core source set. `main_class` is a dotted ordinary class name (nested / `$` names
are rejected initially). No caller-supplied runtime jars, native libraries,
flags, or commands are accepted.

## Application contract (strict schema)

```json
{
  "schema_version": 1,
  "kind": "jvm_application_samples",
  "cases": [
    {"label": "ok", "args": ["7", "3"], "expect": {"returncode": 0, "stdout": "42\n"}}
  ]
}
```

- Every case's `expect` is **exactly** `returncode` and `stdout` — no `stderr` or
  exception/stack field is accepted, so no stack-equivalence claim can ride the
  contract.
- At most 64 cases; argv at most 16 bounded strings; NUL/control characters are
  rejected in pure preflight.
- The run compares **original vs protected** `stdout` and `returncode` only; raw
  `stderr` is recorded but never compared.
- At least one success case (`returncode == 0`) is required: it is the control
  used for the missing-core / missing-adapter fail-closed proofs.

## Deployment bundle (exact allowlist + launch metadata)

The engine produces a `deployment` block the service independently re-verifies
against the on-disk bundle. Launch metadata is fixed:

- `path` — the bundle directory,
- `files` — exact `{relative_path, sha256, bytes}` entries (suffixes limited to
  `.class` / `.dll` / `.jar`),
- `allowlist` — must equal the `files` set and the on-disk set exactly,
- `main_class`, `classpath_entries` (each the exact bundle root `.` or a packaged
  JAR member — not arbitrary relative directories), `native_core` and
  `jni_adapter` (relative DLLs) — each must name a real bundle member,
- raw process receipts (or pinned receipt paths) are retained, not just
  flattened cleanup flags.

The bundle contains **only**: generated facade + bootstrap + `NativeCore`
classfiles, the unchanged application classfiles, the JNI adapter DLL, the
protected native core DLL, and Kotlin runtime jar(s) only if actually needed from
the pinned installed toolchain.

**No original bytes.** The facade classes legitimately keep the original class
*identities/paths*, but no deployed file may carry the original core/helper
classfile bytes or the baseline (unprotected) native artifact bytes — the
verifier rejects any deployed file whose sha256 matches a forbidden original.
Original source / IR / build reports / baseline / native-link intermediates are
never deployed. After integration, root relocates the bundle and re-runs every
case **without** the original build trees on the classpath.

## Rejected by contract (not supported)

The scalar/type restrictions below apply to the **protected core**. Ordinary
application code may still perform parsing, loops, console I/O and other
unprotected JVM work; its direct references into the core are inspected.

- Non-root methods outside the recorded protected closure; non-private helper
  methods not explicitly selected.
- Interfaces, instance state, fields, class initializers, inheritance beyond
  `java.lang.Object`.
- Nested / `$` class identities (initially rejected).
- Objects, arrays, floating point, division/remainder, synchronization, dynamic
  calls; only `int`/`long` scalar roots and their acyclic static-helper closure.
- An **application** class that reuses an original core class identity, extends or
  implements a core class, or references a protected constructor, helper, field,
  or any non-root core member (the only sanctioned app→core path is a public
  static root through the same-name facade). This is distinct from the generated
  same-name *facade*, which is authorized at the core identity/path.
- **Reflection / dynamic name construction cannot be proven absent.** It is
  unsupported and explicitly outside this contract. No general JVM API
  equivalence, no metadata/reflection preservation, and no downstream Kotlin
  recompilation of the deployment bundle are claimed.

## Honest limits (what a green run does and does not mean)

A `jvm_application_samples_passed` result means: for the explicit sampled cases,
the protected application produced the same `stdout` and exit status as
the original, with authentic source / core / toolchain / staged-artifact pins,
present missing-core and missing-adapter fail-closed controls, an exact
deployment allowlist, and a final STOP/pin recheck.
Relocation is a separate qualification step in the linked root evidence; the
service status alone does not prove that a moved deployment was executed.

The first qualifying sample must actually exercise the **protected native
route**: a case whose execution reaches at least one protected native root
(a one-round sample), not a zero-round case that returns before any root is
called — a zero-round "pass" would never touch the native core and so proves
nothing about the protection. Root's first success must therefore drive the
native path end to end.

It does **not** establish: all-input equivalence, exception/stack-trace
equivalence, REA/attack resistance, performance acceptance, macOS support, or
arbitrary Gradle/Maven/JAR support. Owned source executes in bounded owned
processes with Windows Job cleanup; **process cleanup is not a security
sandbox.** Each language needs its own source/runtime evidence.

## Public CLI example

Use a configured local toolchain and review the plan before executing build or
validation. Replace `<plan_id>` and `<fingerprint>` with the returned values:

```text
python -m antirea.defense_mcp source-plan --project samples/multilang/java_application/project.json
python -m antirea.defense_mcp source-build --plan-id <plan_id> --fingerprint <fingerprint>
python -m antirea.defense_mcp source-validate --plan-id <plan_id> --contract samples/multilang/java_application/native-contract.json --random-cases 8192 --timeout-seconds 300
python -m antirea.defense_mcp source-integrate --plan-id <plan_id> --integration-spec samples/multilang/java_application/integration.json --contract samples/multilang/java_application/application-contract.json --timeout-seconds 120
```

Use `kotlin_application` for the independently qualified Kotlin sample. Validation
and integration explicitly execute owned code; none of these commands publishes
the output. The JVM unit-suite E2E placeholder is not the runnable workflow—use
the public CLI above or the recorded root qualification driver.
