# Multi-language protection development

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

User objective (2026-10-20 Australia/Sydney): extend ANTI-REA to C, Rust,
Swift, Go, C#/.NET, Java/Kotlin, Python and JavaScript/TypeScript; complete
general C/C++ project integration and native-core bindings; carry the existing
engine's protection techniques into the new paths.

This is an active implementation objective, **not a whole-language support claim**.
The Windows native-source and native-core integration foundation below is
implemented. The overall objective remains incomplete.

## Verified checkpoint: 2026-10-20

| Route | Actual evidence | Boundary |
|---|---|---|
| C direct source | Selected `native_transform` compiled from C to baseline/protected Windows x64 DLLs; 8,217 cases checked twice against expected outputs for each DLL | Synthetic integer C-ABI fixture, not arbitrary C application compatibility |
| C++ direct source | Two translation units compiled; selected integer core protected, public function left outside selection; same 8,217 × 2 baseline/protected/expected checks | No general C++ runtime, exception, RTTI, template-library or build-system compatibility claim |
| Rust direct source | Actual Rust source compiled through matching LLVM major/minor into baseline/protected DLLs; same 8,217 × 2 checks | One crate root without Cargo hooks/dependencies; selected unmangled C ABI, not general Rust runtime support |
| C/C++ surrounding-function scope | Three translation units; reviewed policy selected core, pre/post-processing and caller functions (four virtualized functions), with a plain public forwarder excluded; 8,217 × 2 baseline/protected/expected checks | Structural call-graph scope, not complete semantic inference or automatic global-data encryption |
| C# direct source | Three public static integer methods compiled to IL, lowered to C and protected with the native VM; baseline and protected DLLs each matched original CLR execution on 8,516 distinct inputs per method | Restricted IL subset, not NativeAOT or whole-assembly protection; app integration is a separate explicit step |
| C# managed app integration | Fresh public CLI plan/build/validate/integrate; three selected method bodies replaced, ten app cases matched, three-file deployment relocation passed | Restricted integer leaves and console sample; unselected managed caller remains unprotected; not arbitrary csproj/MSBuild or GUI equivalence |
| Java/Kotlin direct source | Separate actual Java/Kotlin builds; each has three exports and one private helper covered by the native VM; original JVM versus both DLLs matched on 8,516 inputs per export | Restricted static `int`/`long` bytecode; dispatcher counts depend on the recorded build profile; not whole-class/JAR protection or automatic call-site replacement |
| Go direct source | Actual standard `go/parser`/`go/types` frontend, four exports plus one owned helper; original Go versus both DLLs matched on 8,516 inputs per export; fresh MCP plan/build/validate passed | Fixed-width integer subset, not imports/objects/concurrency/general Go projects or automatic call-site replacement |
| Swift direct source | Actual Swift compiler and LLVM-C parser; four signed/unsigned 32/64-bit exports plus five compiler/helper closure members protected; each export matched original Swift on 8,516 inputs twice for both DLLs | Closed integer graph with wrapping arithmetic, not checked overflow, objects/runtime calls, whole apps or macOS |
| Python pure-module direct source | Actual AST-to-stack-VM protection; three fixtures each matched original Python values/types or exception classes on 8,217 inputs twice | Restricted pure integer/bool module; separate Python VM, not Kagura or whole-package support |
| JavaScript/TypeScript direct source | AST/helper-closure lowering to an encoded JS VM; three Number exports each matched 8,217 inputs twice; two BigInt exports each matched 8,201 twice; Boolean export matched all four pairs twice | Restricted Number/BigInt/boolean module, not whole apps or native Kagura; TS annotations are erased, not fully type-checked |
| Generated native-core bindings | Separate outputs for `c`, `cpp`, `rust`, `swift`, `go`, `csharp`, `java`, `kotlin`, `python`, `javascript`, `typescript` | Generation alone does not compile, execute or protect host-language source |
| Plain-ABI execution | All 11 language IDs compiled/loaded the public ABI fixture, including signed/unsigned boundaries; Go and Swift now have real Windows checks | Windows fixture coverage, not all platforms or application runtimes |
| Protected native-core integration | Python, Node, Java, Kotlin, TypeScript and C# each compared eight calls into a protected C DLL; Go/Swift also call protected native libraries through their generated bindings | Binding smoke coverage, separate from direct source protection and original-runtime comparisons |

The C/C++/Rust and native-context fixture suite contains 8,192 random and 25 edge
cases. Each baseline and protected library is checked against the same independent
fixture expectation, with two repeats. The C# reference suite instead has 8,192
unique random plus 324 boundary tuples per method, each run once in CLR and both
native libraries: 51,096 native-versus-CLR comparisons, not two repeats. Python's
three fixtures compare original execution with VM execution twice, totaling 49,302
observations. Swift's four exports each have 8,516 inputs and two repeats in all
three arms: 68,128 calls per arm and 136,256 original-versus-native comparisons.
Go's four exports instead have one original-reference execution per input per
arm: 68,128 original-versus-native comparisons; its separate native sampling
repeats twice. These are sampled comparisons, not all-input proofs. Native timing includes Python FFI
overhead and currently shows substantial protection overhead; no performance
acceptance threshold has passed merely because outputs match.

Local evidence, when the private `.runs` directories are available. `.runs/`
and `results/` are excluded by this repository's `.gitignore`; the links below
are not a claim that these private reports ship in a clone of the repository:

- C: build report (local-only record: `../.runs/native-project-c-final/report.json`), coverage (local-only record: `../.runs/native-project-c-final/coverage.json`), fixture checks and timing (local-only record: `../.runs/native-project-c-final/fixture-check.json`).
- C++: build report (local-only record: `../.runs/native-project-cpp-final/report.json`), coverage (local-only record: `../.runs/native-project-cpp-final/coverage.json`), fixture checks and timing (local-only record: `../.runs/native-project-cpp-final/fixture-check.json`).
- Rust: build report (local-only record: `../.runs/native-project-rust-final/report.json`), coverage (local-only record: `../.runs/native-project-rust-final/coverage.json`), fixture checks and timing (local-only record: `../.runs/native-project-rust-final/fixture-check.json`).
- Native context: scope (local-only record: `../.runs/native-context-final/scope.json`), coverage (local-only record: `../.runs/native-context-final/coverage.json`), independent expected-output checks (local-only record: `../.runs/native-context-final/fixture-check.json`).
- C#: private build (local-only record: `../.runs/dotnet-source-second/report.json`), original CLR comparison (local-only record: `../.runs/dotnet-reference-first/report.json`).
- Java: private build (local-only record: `../.runs/java-source-second/report.json`), original JVM comparison (local-only record: `../.runs/java-reference-first/report.json`).
- Kotlin: private build (local-only record: `../.runs/kotlin-source-first/report.json`), original JVM comparison (local-only record: `../.runs/kotlin-reference-first/report.json`).
- Go after loop-semantics repair: private build (local-only record: `../.runs/go-source-phase4-final/report.json`), original Go comparison (local-only record: `../.runs/go-source-phase4-final-validation/report.json`), separate loop regression (local-only record: `../.runs/go-loop-semantics-2ab9d0af6c29/README.md`).
- Swift four-width source: private build (local-only record: `../.runs/swift-source-phase4-four-widths-final/report.json`), original Swift comparison (local-only record: `../.runs/swift-source-phase4-four-widths-final/reference-validation/report.json`).
- JavaScript: retained build (local-only record: `../.runs/javascript-source-phase3-final/report.json`), original-versus-VM validation (local-only record: `../.runs/javascript-source-phase3-final/validation/validation.json`).
- TypeScript: retained build (local-only record: `../.runs/typescript-source-phase3-final/report.json`), original-versus-VM validation (local-only record: `../.runs/typescript-source-phase3-final/validation/validation.json`).
- Python: original-versus-VM fixture comparisons (local-only record: `../.runs/python-source-fixture-validation-20261020.json`), [supported subset and deployment boundary](../samples/multilang/python/README.md).
- Binding contract and test procedure: [public ABI fixture](../samples/multilang/bindings/README.md), [binding tests](../tests/test_bindings.py).
- Plain-ABI and protected integration measurements: phase-3 local binding validation (local-only record: `../.runs/multilang-bindings-typescript-api-20261020.json`).
- Actual defender source-plan/build/validate workflow: local E2E record (local-only record: `../.runs/source-protection/source-20261019T141009Z-cc258b933698/workflow-e2e.json`); reproducible test entry point is [test_source_workflow.py](../tests/test_source_workflow.py).

These are new private development artifacts, not updates to the public ledger
experiment. There was no new external attack evaluation or publication in this
checkpoint. macOS/Mach-O/Apple Silicon remains unvalidated. Every language has
an experimental subset route, not ordinary whole-application integration.

## Acceptance criteria

The latest script **application-integration** checkpoint passed 233 focused tests
with no skips (including existing C# bridge coverage) and three fresh public
plan/build/validate/integrate workflows.
Python mixed-module, JavaScript Number and TypeScript BigInt cores matched
57,457 scalar input vectors, retaining two observations per original/protected
arm. The ordinary apps passed 4/15/13 explicit CLI cases across original,
protected and independently copied deployment trees; all three missing-module
controls failed as required. This checks sampled behavior and dependency presence,
not VM call tracing, whole-app correctness or resistance. The first full ordinary
regression had one MCP-description assertion failure, retained in the log.
After the bounded repair, full ordinary discovery passed **2,806 tests with
82 unchanged skips and no failures/errors** (2,888 discovered/executed).
The public app workflows preceded this description-only production repair.
These functional runs are not performance acceptance or resistance evaluation. See the
phase-24 record (local-only record: `../results/2026-10-21/infrastructure/defense-loop/multilanguage-phase24/README.md`).

The latest script-runtime checkpoint added per-function flattened dispatch to
both pure and mixed Python/JS/TS routes. It passed 251 focused tests and six fresh
public workflows with 90,303 input vectors. Full discovery finished with 2,592
passed and 82 explicit opt-in skips, no failures/errors. Three separately run
mixed-sample benchmarks compared original, prior shared VM and new per-function
VM inside the same workers. New/prior median batch times varied by function
from approximately -1.8% to +5.8%, while protected modules grew 32–50%.
These tiny original scalar functions still incurred large VM overhead; no
performance SLA, whole-application qualification or external-resistance gate
passed. See the phase-23 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase23/README.md`)
for raw distributions, exact artifact hashes and independent receipt audits.

The phase-5 Windows checkpoint completed at 2026-10-19 16:59 UTC: 911 tests
passed, zero skipped, and 155 pinned source/test/tool/fixture/configuration
inputs were unchanged. Independent collection matched ten new source MCP
workflows, three compile-database three-arm comparisons and eleven binding
languages. This is a checkpoint of those exact input versions, not validation
of subsequent C++ symbol-mapping changes. The detailed
phase-5 record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase5/README.md`)
separates sample counts, historical DLL reuse, process-cleanup limits and
unfinished full-objective requirements.

A subsequent C++ checkpoint passed four actual compile-database scenarios at
2026-10-19 17:17 UTC: GNU-style clang++ O0/O2, clang-cl O2, and O2 with a
reviewed public forwarder. Real namespace overloads and an internal helper were
mapped only in protection IR; all five selected functions retained three-stage
VM coverage. Each public export matched original-source, LLVM-baseline and
protected DLL outputs on 8,200 samples, with two evaluations per arm. All 166
pinned inputs were unchanged and the independent collector passed. This is
restricted scalar C++ integration, not general object/runtime/application
support or a fresh whole-repository 911-test run. Recorded call overhead remains
large and no performance acceptance gate or external attack evaluation passed.
See the phase-6 checkpoint (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase6/README.md`).

The subsequent shared native-object refactor passed 138 focused mocked checks
and a fresh four-scenario actual C++ checkpoint at 2026-10-19 17:40 UTC. All 168
pinned inputs stayed unchanged and independent collection passed. The internal
object pipeline now separates fixed VM/runtime/object stages from caller-owned
source preparation, original reference and final linking. A separate actual
two-crate Rust IR experiment retained all 13 functions through three VM evidence
stages and all 13 hardened runtimes through object generation. Its status is
`objects_unlinked_not_functionally_validated`: Cargo recipes, final linking and
independent original-runtime comparison are not established by that experiment.
See the phase-7 record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase7/README.md`).

A later private Cargo checkpoint at 2026-10-19 18:24 UTC captured both original
and derivative builds for default and alternate features in a two-local-crate
standard-library project. Actual compiler recipes, local extern producers,
compiler-declared source dependencies and output inventories were hash-connected
to both completed builds. The recorder passed 51 Python / 15 Rust tests and six
compiled self-test vectors; the artifact reader/binder passed 54 pure tests and
then bound both real captures. Per-run PATH/jobserver differences remain
explicitly qualified, not semantic-equivalence evidence. Final protected linking,
original-runtime comparison and production Cargo routing remain unfinished;
the public Rust source builder still uses its single-crate route. See the
phase-8 verification (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase8/cargo-capture-verified.md`).

At 18:38 UTC, both actual Cargo configurations subsequently passed sampled
original-versus-derivative DLL comparison: two exports, 8,200 distinct inputs
per export, two full repetitions per arm. Both actual captured IR files also
passed fixed canonicalization and strict reversible Rust mapping with four
definitions each. The preparation suite passed 43 tests, zero skipped. These
derivatives are unprotected; protected object replacement, final linking,
protected-versus-original behavior, performance and production Cargo routing
remain unfinished. See the reference/IR record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase8/cargo-reference-and-ir.md`).

At 19:06 UTC, both fixed Cargo configurations generated baseline/protected
objects with four retained VM functions and four obfuscated runtime engines.
The default configuration also completed actual native replacement links,
preserving the remaining Cargo/Rust/native inputs while omitting the original
calculation object. The tuple/list report-handoff repair passed 62 module tests;
the replacement adapter/executor passed 100 tests and a bounded wrong-hash
bootstrap rejection. The resulting default baseline/protected DLLs are
103,936/390,656 bytes. Their original-reference behavior is a separate pending
gate, and the public source builder still has no production Cargo route. See
objects (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase8/cargo-native-objects.md`)
and actual replacement linking (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase8/cargo-replacement-linked.md`).

At 19:30 UTC the default Cargo replacement passed original-versus-baseline-versus-
protected sampling: both exports, 8,200 distinct inputs each, two full passes per
arm, all three pairwise comparisons equal. The parent independently rechecked
receipts and source/tool pins. The validator's duplicate full-file sweep was
removed without changing its 32 GiB budget; all 86 module tests passed. This
qualifies only those exact private artifacts. Generic production Cargo builds,
alternate-configuration protected behavior, macOS and performance acceptance
remain unfinished. See protected reference evidence (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase8/cargo-protected-reference.md`).

At 19:48 UTC, production Cargo PLAN passed a real three-local-crate project:
standard, repeated-standard and alternate metadata receipts, an offline
lockfile, stable semantic identity for repeated requests and a distinct
alternate feature selection. Public source-build still explicitly refuses
Cargo; planning does not imply protected-build support. Production recorder,
artifact collection and bounded original/derivative capture modules are now
authored, with fresh verification in progress. See the
phase-9 record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase9/README.md`).

At 19:57 UTC, fresh repository unit discovery including the new Cargo modules
passed: 1,126 tests passed, 80 explicit opt-in integration skips, zero errors or
failures; all 205 pinned inputs were unchanged. The compiled Rust recorder and
actual production capture are separate pending gates, not implied by this run.

At 20:04–20:09 UTC, the fresh recorder gate passed nineteen compiled Rust tests
and six self-test vectors after twenty harness regressions. Full repository
confirmation again passed 1,126 tests with 80 explicit skips and 205 unchanged
pins. Both standard and alternate configurations of the three-crate project
then passed actual production original/derivative Cargo capture and independent
parent verification. Three actual compiler units per arm and their emitted IR
are bound to the saved plans. This is `cargo_capture_verified_not_protected`:
no target execution or VM/native replacement link occurred, and public Cargo
source-build remains disabled. See the production capture record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase9/cargo-capture-verified.md`).

At 21:50-21:55 UTC, the Rust mapper, normalizer and crate qualifier passed 172
staged-package LLVM semantic regressions and were adopted byte-identically into
`antirea`. Source-only package bootstrap passed 43 checks; the independent
native-link structural draft passed 61 pure checks. The post-adoption full suite
passed 1,226 tests with 80 explicit integration skips, zero failures/errors and
214 unchanged inputs. All 46 newly added package/plan-pin tests passed. Public
Cargo build remains disabled: actual native replacement/linking and original
application comparison are still required. See package adoption evidence (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase10/package-and-native-link.md`).

At 22:21 UTC, the package preparation candidate completed fresh three-crate
Cargo capture and independent receipt verification in both standard and alternate
configurations (26/30 surviving selected functions, four exports each). A private
Windows staging-path failure was reproduced and fixed without changing source
or compiler options. The native object adapter passed 60 pure/mock regressions;
its actual native compilation gate and production adoption are not yet complete.
Fresh full regression: 1,298 passed, 80 explicit integration skips, zero failures
or errors, 216 unchanged pins. See actual package evidence (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase10/cargo-package-actual-and-objects.md`).

At 22:32 UTC, the tested Cargo preparation/semantic modules and 145 tests were
adopted into the production package. Both source-plan routes now bind their
bytes; nine Cargo-specific and three expanded general plan tests passed. Fresh
full regression passed 1,452 tests with 80 explicit integration skips and no
failures/errors. Public Cargo BUILD remains disabled pending actual generic
native replacement/link/reference integration. See production adoption and object gate (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase10/cargo-preparation-production-and-native-objects.md`).

At 22:54-22:58 UTC, both unchanged three-crate configurations completed actual
core FLA/SUB/CO, VM, diversification, runtime FLA/SUB/CO and native-object creation.
The standard/alternate selected sets contain 26/30 functions, all with original,
diversified and final VM evidence; each has four public exports. Independent
parent checks bind ten object commands and thirteen watched outputs. The tested
object adapter is adopted byte-identically into production; 85 object, 12 Cargo
PLAN and three general PLAN tests pass. These results do not include final
protected linking, application execution, performance or defense effectiveness.
Fresh full regression passed 1,540 tests with 80 explicit integration skips and
222 unchanged pins. Public Cargo BUILD remains disabled. See SDK repair and actual object evidence (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase10/cargo-sdk-authorization-and-object-build.md`).

A subsequent private unit/native-capture candidate passed 118 pure tests in
separate source-only packages. Its frozen Rust producers then compiled and
passed 28 wrapper plus 40 recorder tests, six self-test vectors per executable,
and a separate actual parent/child identity probe. All eleven bounded commands
and their recorded Job cleanup passed; 55 source/config/interpreter pins and
861 tool/native inventory entries were rechecked. This does not establish
actual Cargo/native forwarding or protect a new application. The revised library
producer subsequently passed 76 Rust tests (including the prior 68), twelve
self-test vectors and its separate process-identity probe. The collector-v3
fixture failed on JSONL framing; a test-helper-only repair in fresh v4 passed
167 collector plus 37 separate producer tests, with 74 unchanged approved pins.
An actual MSVC search experiment then passed 24 pure parser tests and all twelve
fixed cases through 27 compiler/archive/link commands. The first experiment's
wrong missing-file diagnostic expectation and its failed evidence are retained.
Successful DLLs were inspected as bytes, not executed; binder receipts in that
experiment are synthetic, not native-recorder-produced. Actual Cargo native
forwarding and public Cargo BUILD remain unfinished. See the
phase-11 qualification record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase11/README.md`).

1. Protect selected application code actually written in each requested language.
   A language name in a registry, a generated wrapper, a packaged interpreter,
   or a pre-existing C++ sample does not satisfy this criterion.
2. Integrate ordinary projects, not only `antirea_score`, fixed ledger constants,
   or saved experimental IR. Preserve source inputs and build a comparable
   unprotected baseline from the same input and toolchain.
3. Distinguish direct source protection from native-core integration. Provide
   the latter for the requested languages without claiming it protects the
   surrounding original-language source.
4. Include the selected core's relevant callers, helpers and shared constants
   in a reviewed protection scope. Explicitly report unsupported operations,
   remaining clue-bearing code and excluded public UI/interop code.
5. For each artifact, record which transformations actually ran and survived
   compilation. Requested settings, helper definitions and manifest labels are
   not evidence that a protection mechanism was applied.
6. Validate same-input behavior, boundary cases, repeated calls and measured
   performance. Record test coverage and unsupported language features; do not
   generalize a small integer-function test to a whole language runtime.
7. Verify Windows and macOS targets separately, including architecture, native
   loading, packaging/signing compatibility and OS-specific protection features.
   A Windows compiler probe is not a macOS pass.
8. Expose inspected plans, explicit build execution, bindings and honest
   capabilities through the defender MCP/CLI. Do not add local attack execution.
9. Preserve the public ledger artifact and external experiment history. New
   multi-language builds stay private until their own gates and publication
   review pass. External resistance remains `not_evaluated` without evidence.

## Workstreams and sequencing

| Workstream | Required result | Current implementation work |
|---|---|---|
| General native project build | C/C++ sources to baseline and protected libraries, per-function coverage | Windows x64 builder and reviewed pre-optimization caller/helper scope implemented; bounded integer fixtures validated, arbitrary project integration incomplete |
| Native language frontends | Actual Rust and Swift source protection, toolchain/ABI handling | Both actual source subsets built and validated; Cargo/SwiftPM, dependencies and general runtimes remain unfinished |
| Native-core bindings | C/C++, Rust, Swift, Go, C#, Java, Kotlin, Python, JS and TS | 11 generators and plain-ABI language checks; eight languages have additional protected-library smoke checks |
| Other direct source routes | Go, .NET, JVM, Python and JS/TS source protection | Restricted Go/C#/JVM-to-native and Python/JS AST-to-VM paths implemented; ordinary project/language integration remains unfinished |
| Protection evidence | Each existing technique applied or an explicit gap | Artifact evidence distinguishes retained checksum, helper-only features, removed decoys and missing mechanisms |
| Platform coverage | Windows x64 and macOS/Apple Silicon tests | Windows available; macOS execution not yet established |
| Agent workflow | Source plan/build and binding generation via one bridge | Source plan/build/validate, language inventory and binding tools implemented in defender MCP/CLI |

The native builder is a shared dependency for direct LLVM frontends and native
bindings, so it comes first. Language-specific VM/transformation backends remain
part of the objective rather than being silently removed from scope.

Go's direct-source fixture and full MCP workflow now pass with a verified portable
Go 1.27.2 toolchain. Swift 6.4.0 compiler/SDK files were extracted locally from
the verified official installer without running installation actions; actual
four-width source protection and original-language comparison now pass. Both
still require ordinary-project integration beyond scalar subset experiments.

## Source-project workflow

Use the repository's configured Python environment, an existing pinned
`.tools/kagura-toolchain.json`, LLVM/Kagura binaries and an installed Visual
Studio/Windows SDK environment. Rust additionally needs an installed `rustc`
whose LLVM major/minor matches the pinned reader. Discovery of a compiler path
does not establish compatibility. These tools do not install missing compilers,
SDKs, packages or vendor products.

Keep a manifest in a dedicated owned project subdirectory. For example,
[the C fixture](../samples/multilang/native/c/project.json) uses:

```json
{
  "schema_version": 1,
  "name": "c-native-core",
  "language": "c",
  "sources": ["core.c"],
  "functions": ["native_transform"]
}
```

`sources` and C/C++ `include_dirs` are relative paths inside that directory.
Optional `defines` apply only to C/C++; `target` defaults to
`x86_64-pc-windows-msvc` and `artifact` to `shared_library`. Other native targets
or artifact types are blocked. `functions` names ordinary, unmangled public C-ABI
exports. Without `scope_policy`, it is also the explicit VM selection list.
With a C/C++ `scope_policy`, the reviewed policy selects the core and expands its
callers/helpers before optimization; the export list and internal VM list are
recorded separately. Unsupported VM lowering or unresolved scope review is a
build failure, not silently successful protection.

The current compiled fixtures cover integer functions. Native ABI contracts
accept `u32`, `i32`, `u64`, `i64` and `void` returns, with scalar integer
arguments; generic execution validation requires integer returns. This is not
support for managed objects, arbitrary pointers, callbacks, exceptions or
runtime-owned memory. The C/C++ driver disables exceptions/RTTI; the Rust path
uses one crate root and does not invoke Cargo or arbitrary build hooks.

```powershell
python -m antirea.defense_mcp languages
python -m antirea.defense_mcp source-plan --project samples/multilang/native/c/project.json --seed 1729
# Inspect plan inputs, blockers and tool hashes. Substitute returned values:
python -m antirea.defense_mcp source-build --plan-id <plan_id> --fingerprint <fingerprint>
# Separate explicit execution of the owned baseline and protected libraries:
python -m antirea.defense_mcp source-validate --plan-id <plan_id> --contract samples/multilang/native/contract.json --random-cases 8192 --timeout-seconds 120
# Generate source only; does not compile or execute any wrapper:
python -m antirea.defense_mcp bindings --contract samples/multilang/native/contract.json
```

The angle-bracket values are placeholders, not literal PowerShell syntax.
By default the CLI uses `.runs/protectors.local.json`; a custom configuration
is supplied before the subcommand with `--config <path>`. Its workspace root
defines the owned input boundary. Source plans, private build outputs,
validation records and binding bundles live under `.runs/source-protection/`.

| CLI command | MCP tool | Result/side effect |
|---|---|---|
| `languages` | `protection_languages` | Route inventory and tool discovery; no compiler execution |
| `source-plan` | `protection_source_plan` | Inspects inputs and writes a bounded project/tool/engine fingerprinted plan; JS/TS runs a trusted pinned parser, never target source; no target compilation |
| `source-build` | `protection_source_build` | Checks the fingerprint and unchanged inputs, runs native/.NET/JVM compilers or Python/JS AST frontends into a fresh directory; success is `artifact_created_unvalidated` |
| `source-validate` | `protection_source_validate` | Explicitly executes supported owned baseline/protected artifacts in bounded children; C#/JVM/Go/Swift also compare original runtime execution; mixed Python requires its separate application-sampling contract; not an OS sandbox |
| `source-integrate` | `protection_source_integrate` | Explicit [C#](csharp-applications.md), [Java/Kotlin](jvm-applications.md), [Go/Swift](go-swift-applications.md) or [Python/JS/TS](#script-application-integration) app execution around a reviewed source-build, with an application contract and local protected deployment bundle |
| `bindings` | `protection_bindings` | Generates native ABI wrappers; success is `bindings_generated_unvalidated` |

### Script application integration

The same explicit `source-integrate` command accepts a saved Python/JavaScript/
TypeScript source build and two files already present in its unchanged planned
project tree: `--integration-spec` and `--contract`. It reuses the protected
artifact; it does not overwrite the original source or silently run the app
during planning/building.

Owned examples provide `project.json`, `core-contract.json`, `integration.json`
and `app-contract.json`:
[Python package](../samples/multilang/python_application/),
[CommonJS JavaScript](../samples/multilang/javascript_application/) and
[multi-file TypeScript](../samples/multilang/typescript_cli_application/).
Use source-plan/build, source-validate with the core contract, then
source-integrate with the integration spec and app contract. The configuration
and source-plan fingerprint requirements above still apply.

The spec uses `schema_version: 1`, `kind: "script_application_integration"`,
`language`, `protected_source`, a different `entrypoint`, and an explicit
`application_files` list. The contract uses `kind: "script_application_samples"`
and cases containing only `label`, `args`, and `expect: {returncode, stdout}`.
At least one case must succeed and depend on the protected module; that first
successful case must fail in a separate missing-module copy. Three-arm
comparisons normalize line endings only; stderr is retained but not compared.

Python and mixed JS preserve the raw original source. Pure JS and all TS derive
their original runtime reference independently from original source using the
pinned CommonJS transpiler, never the producer baseline as application truth.
Pure-producer JS/TS require explicit exports for selected roots. Unselected runtime/data
files are copied unchanged, or independently transpiled from TS with fixed
options. The protected bundle contains only the explicit runtime inventory, with
the selected module replaced by the exact saved protected artifact.

Success is `script_application_samples_passed`, after independent raw receipt,
output, source/tool pin and bundle checks. It is restricted to owned Windows
Python/CommonJS CLI apps: no dependency installation, package hooks, arbitrary
project graphs, full TS type checking, runtime ESM/browser support or macOS
qualification. Missing-module checks prove dependency presence, not that every
VM function executes. Existing per-function script VM hardening is preserved;
no native Kagura layers or new resistance/performance claims are added.

`source-validate` compares baseline/protected behavior on generated scalar cases;
it does not know an arbitrary application's independent expected result. The
native 8,217-case fixture evidence above uses an additional fixture-specific expected
implementation. Keep those claims separate. Neither check establishes external
attack resistance. A changed project/toolchain requires a new source plan;
an attempted plan is not automatically rerun.

The built-in `auto-protect --provider antirea` route for a compiled EXE is
unsupported (`blocked`, `source_project_required`), as are its `antirea_engine`
and `kagura` aliases. Use the source workflow above. Commercial binary
protection remains a separate provider workflow, not a fallback that silently
protects an executable with the built-in source engine.

### Public forwarding boundaries

Native VM-definition coverage alone does not prove that a public caller still
uses protected code. The builder isolates reviewed scalar call/return wrappers
before interprocedural optimization and rejoins them after VM insertion. This
changes only the protection IR, not the source, baseline or original reference.
It records the original forwarding contract and checks the final codegen IR.

Coverage schema 2 stores hash-bound original/business/boundary/final IR evidence.
Before executing a native validation worker, the validator independently derives
the scope and forwarding relation using the locally pinned LLVM parser. It also
watches those inputs between workers. Go/Swift/.NET/JVM composed reports must
match their hash-bound `native/report.json`; they cannot substitute a top-level
success label for this native evidence. Builds without public forwarding
boundaries record `no_boundaries` explicitly. Historical schema 1 records remain
`legacy_unverified` for this gate, not retrospectively verified.

These checks concern the supported scalar graph, not all application control
flow, all-input functional equivalence or attack resistance. Current regression
and integration evidence is recorded in the private phase-5 results directory.

### Existing C/C++ compilation database (experimental)

The native source route can inspect an existing `compile_commands.json` and
preserve settings separately for each selected translation unit. This does not
run the database's original command string, a configure step, or project build
hooks. The builder authors compiler-only invocations with the pinned Clang,
Clang++ or clang-cl driver. Unknown options, response files, compiler wrappers
and plugins are rejected rather than silently removed.

For a manifest in a dedicated owned project directory:

```json
{
  "schema_version": 1,
  "name": "existing-native-core",
  "language": "cpp",
  "compile_commands": {
    "path": "compile_commands.json",
    "selections": [
      {"file": "helper.c"},
      {"file": "core.cpp"}
    ]
  },
  "functions": ["core"],
  "scope_policy": "scope.json"
}
```

Use the same `source-plan`, reviewed `source-build`, and `source-validate`
commands above. Do not also supply the older global `sources`, `include_dirs`
or `defines` fields: the database defines those settings per translation unit.
`selections[].file` is relative to the manifest directory. Ambiguous entries for
one source require the selected entry's `entry_sha256`, calculated from its
sorted-key compact JSON representation; choosing the first configuration is not
allowed. Optional `compile_commands.input_roots` supplies additional bounded,
owned workspace-relative input directories, not arbitrary external SDK paths.

Macro define/undefine and header-search order, language standards, original
optimization options, working directories and lexical path operands are
preserved. Canonical paths are used for ownership and hashing only: replacing
a relative operand with an absolute path can change `__FILE__` and
`__BASE_FILE__`. Options whose positional meaning cannot yet be preserved are
blocked, including semantic options after the source operand.

Installed LLVM/VS/SDK metadata determines trusted header roots. Plans bind
compact full-tree inventories; builds retain the full inventories in a private
sidecar and compare actual compiler dependency output against them. Unknown or
changed dependencies stop the build. This includes new shadowing headers, not
only modifications to an already-used header. Header inventory verification
adds planning/build time. Linker/runtime libraries are not yet fully hermetically
inventoried, so this is not a fully hermetic build claim.

Plans also pin reviewed environment selectors and the installed developer-shell
selection scripts/metadata. Builds explicitly select that Visual Studio
installation and retain the realized SDK search paths. Environment values used
for selection are hashed, not published as arbitrary environment contents.
These checks do not model every operating-system input. Raw LLVM from every
selected translation unit is parsed before original object generation; module
and function inline assembly are currently rejected because assembler file
inputs are not covered by the header dependency inventory.

Builds produce three separate DLLs: a direct-source original reference,
an unprotected LLVM baseline, and a protected candidate. Original-reference
objects and signature IR use the recorded source settings and never the
protection-adjusted IR. The protected route can retain selected functions with
`noinline`, remove incompatible `optnone`/inline hints, and promote internal
selected helpers to hidden external linkage; those changes are recorded and
are not applied to the original source/reference. Validation requires all
three arms to match on the same generated integer inputs and remain
deterministic, with matching owned artifacts, ABI and provenance records.
The validator binds the saved normalized plan to a private byte-exact copy of
the original compilation database, the complete selected translation-unit set,
and each original compile command's full ordered argument list. It checks the
sidecar/object/signature hashes before and after execution. This is consistency
checking of the owned build evidence, not cryptographic execution attestation.
Historical validation does not require the current database contents to remain
unchanged, but the original owned source/include paths must still exist.

The link contract remains a Windows x64 shared library with reviewed scalar
C-ABI exports, not the original application's full EXE/link/packaging contract.
Recorded exception/RTTI options do not imply Kagura supports every emitted
operation. Arbitrary C++ objects, mangled internal helper handling and app-wide
integration remain unfinished. See the private
phase-5 record (local-only record: `../results/2026-10-19/infrastructure/defense-loop/multilanguage-phase5/README.md`)
for actual test status; earlier checkpoints do not verify these new changes.

Opt in to the owned real-driver path-parity and mixed C/C++ integration tests
with `ANTIREA_RUN_COMPDB_PREPROCESSOR_TESTS=1` and
`ANTIREA_RUN_COMPILE_DB_E2E=1`. These tests build/execute owned fixtures and
retain private reports. They do not execute REA or publish a candidate.
`ANTIREA_RUN_COMPDB_IR_GATE_TESTS=1` separately enables actual LLVM-C parsing
checks for the assembly gate; those checks do not run an assembler or target.

### Reviewed surrounding-function scope

The [context fixture](../samples/multilang/native/context/project.json) adds
`"scope_policy": "protection-policy.json"`. Its policy declares `core_roots`,
`sensitive_functions`, reviewed `public_presentation` boundaries, `entry_points`
and a `max_functions` limit. The builder emits unoptimized source IR, links the
translation units, runs only `mem2reg`, then calls the scope analyzer. It does not
inline away helpers before deciding which functions need protection.

For this fixture, `context_mix`, `context_prepare`, `context_adjust` and
`context_score` receive VM coverage. `context_public` remains a simple reviewed
forwarder. Ambiguous indirect calls, unresolved functions or data relationships
requiring review stop the build. A review policy is not a proof that all possible
semantic clues are covered. Shared constants are not automatically encrypted.
Validation rejects a selected function missing from coverage, and checks all
public exports rather than requiring users to expose private internal helpers.

### Experimental C# source backend

Use [the C# manifest](../samples/multilang/dotnet/project.json) with
`language: "csharp"`, owned `.cs` sources, and `methods` entries containing a
declaring `type`, method `name` and native `export`. The installed .NET SDK's C#
compiler is invoked directly, without project build hooks, packages or analyzers.
A trusted metadata reader inspects the emitted IL without loading the target
assembly. Supported IL becomes C, then follows the existing LLVM/native-VM path.

Supported selected methods are public static scalar `int`, `uint`, `long` or
`ulong` methods with the accepted integer operations, locals and control flow.
Calls, fields, objects, arrays, generics, exception handlers, checked overflow,
division/remainder and static/module initializers are rejected. Width masking,
signed comparisons and arithmetic shifts are explicit in lowering. The current
CLR fixtures cover `u64(u32,u32)`, `i32(i32,i32)` and `i64(i64,i64)`; `u64` input
parameters were not exercised by that reference suite.

Source building alone does not rewrite an existing managed assembly's call sites.
The separate [C# application integration](csharp-applications.md) route rewrites
supported selected source bodies, preserves ordinary callers, compiles a managed
application and checks explicit CLI observations. It requires an integration spec
and app contract already present in the reviewed source snapshot. It is not
whole-assembly or general project support. `original.dll`, generated C, metadata
and IR are private build evidence, not files to ship with the protected library.
Both `dotnet_frontend.verify_build` and the shared source-validation workflow now
compare owned original CLR execution against native outputs. Source validation
requires native checks and original-runtime comparisons to pass for every export
and both DLLs. Matching baseline/protected lowering mistakes alone cannot pass
this gate. Before execution, the contract's return and ordered argument types
must exactly match original C#/JVM metadata, including signedness, not just bit
width. Caller-chosen parameter names may differ. These are sampled comparisons,
not a correctness proof.

### Experimental Java/Kotlin source backend

Use [Java](../samples/multilang/java/project.json) or
[Kotlin](../samples/multilang/kotlin/project.json) manifests with owned source files
and explicit `methods` entries (`class`, `name`, JVM `descriptor`, native `export`).
Java uses the installed JDK without annotation processors. Kotlin uses a local
portable compiler configured in `.tools/kotlin-toolchain.json`; its configuration
and compiler libraries are hashed. No project hooks, scripts or plugins are run.
Classfile metadata is parsed without loading the target class. Accepted bytecode
is lowered through C to the same native protection pipeline.

The supported subset is static `int`/`long` methods, locals, branches, switches,
width conversions, integer arithmetic/shifts and owned nonrecursive static
helpers. The helper closure is protected. Objects, arrays, fields, class
initialization, inheritance/interfaces, dynamic calls, exceptions,
synchronization, division/remainder and floating point are rejected. Historical
phase-3 artifacts shared a dispatcher. New multi-VM native builds can use four
independent generated dispatchers for four protected functions; inspect each
artifact's manifest and final coverage instead of inferring this from function count.
There is no arbitrary JAR rewrite or automatic call-site replacement. Original
classfiles, generated C/IR and reference runners remain private. The separate
[Java/Kotlin application integration](jvm-applications.md) route preserves ordinary
caller bytecode and replaces selected core classes with same-name JNI-backed
facades. It packages the protected DLL without the original core implementation.
Alternatively, explicit bindings still require the application owner to remove
the original core separately.

Original JVM comparison is mandatory in shared source validation, in addition
to native checks. Java and Kotlin were tested separately, not inferred from a
common backend. Kotlin 2.4.21 was downloaded from the
[official release](https://github.com/JetBrains/kotlin/releases/tag/v2.4.21),
size/SHA-256 verified before local extraction; no system PATH was changed.

### Experimental Go source backend

Use [the Go manifest](../samples/multilang/go/project.json) with owned `.go` files
and `functions` selectors containing `name` and native `export`. Inspection is
read-only; explicit build compiles a trusted helper using standard `go/parser`
and `go/types`, without executing target code. It lowers roots and their acyclic
owned helpers into width-masked C, then uses the existing native VM pipeline.

The current subset includes `int32`, `uint32`, `int64`, `uint64`, locals, branches,
accepted loops, conversions and supported integer/bit operations. Imports,
package state/init, objects, pointers, collections, generics, concurrency, runtime
division/remainder and potentially negative dynamic shifts are rejected; they
must not silently receive altered panic semantics. General Go project support
remains unfinished. Ordinary caller integration for a separated `package main`
core uses the explicit application route described below; the scalar frontend
alone does not replace application calls.

`.tools/go-toolchain.json` selects a portable compiler without changing system
PATH. Compiler executables and the trusted helper are pinned individually; a
compact sorted content digest also pins the distribution source/include tree.
Plan/build comparisons reject changes to either inventory. Build environment
disables automatic toolchain download, module lookup, Go environment files and
telemetry, and uses private caches. Reference validation compiles/runs the
unmodified owned Go functions separately from both generated native DLLs.

The fresh MCP record is
local Go E2E (local-only record: `../.runs/source-protection/source-20261019T151542Z-afd7b60f0489/language-e2e.json`).
Four exports each matched original Go on 8,192 unique random and 324 edge tuples,
for 68,128 original-versus-native comparisons. Native sampling also checks two
repeats. These do not prove whole-language semantics or resistance to analysis.

A later semantic audit found that emitting a Go loop as C11 `while(condition)`
could add a forward-progress assumption and eliminate a nonterminating loop.
Lowering now uses `for (;;)`, an explicit condition break, and explicit
continue/post labels. Actual Clang/Kagura IR preserves the backedge; owned Go,
baseline and protected executions match 42 terminating observations and each
remains nonreturning for the bounded one-second odd-input observation. That
timeout is not a general functional pass or a proof of infinite execution.
The fresh direct build/reference reports linked above include the repair;
earlier MCP records remain historical, unchanged evidence.

### Experimental Swift source backend

Use [the Swift manifest](../samples/multilang/swift/project.json) with one owned
`.swift` compilation unit and explicit `@_cdecl` export names in `functions`.
The configured portable Swift compiler emits real LLVM IR and a public Swift
interface. The latter provides exact signed scalar metadata; the pinned LLVM-C
parser checks integer widths, calls and the complete acyclic helper closure.
Only an eligible closed graph is normalized to the native C calling convention.
Calls and definitions change together; compiler-created trampolines/helpers are
selected too, not left as plaintext implementations outside VM coverage.

The current subset accepts selected UInt32/Int32/UInt64/Int64 functions and
supported integer operations. Wrapping arithmetic is supported. Checked-overflow
trap intrinsics, pointers, globals, objects, runtime calls, floating point,
recursion and indirect calls are rejected. The public interface parser accepts
ordinary single parameter names and explicit external/internal labels. This is
not a Swift runtime, SwiftPM adapter or arbitrary module/application protection.

The native builder protects all selected closure members and exports only the
requested C entry points. Final four-width evidence contains nine independent
VMs with all nine runtime FLA/SUB/CO and checksum calls retained. Separate
compilation of the unmodified owned Swift source produces the original-reference
DLL. Mandatory comparison against that original guards against shared mistakes
in normalized baseline/protected lowering. Private IR, source snapshots and the
original-reference DLL are not deployment artifacts.

`.tools/swift-toolchain.json` pins the portable compiler, SDK and runtime files.
SDK/runtime search paths are child-local; no persistent PATH or system SDK edit
is required. Real Swift caller binding tests use private copies of only missing
ucrt/WinSDK module maps, preserving already-provided vcruntime declarations.
Binding checks are separate from direct-source protection. Windows x64 passes
do not establish macOS/Mach-O/Apple Silicon, signing or packaging support.

### Go/Swift application connection

The public [Go/Swift source-integrate route](go-swift-applications.md) now
compiles ordinary app sources with same-name native facades instead of the
original separated scalar core. The original and protected compilations use
identical app-source bytes. Go uses Windows/amd64 standard-library bindings
without cgo; Swift preserves external argument labels from the pinned compiler
interface and statically links the common C bridge. No original core sources,
IR or baseline application are included in the deployment bundle.

Both paths authenticate the original producer and exact source/tool/contract
pins, compare stdout bytes and exit status, require missing/unset-core negative
controls, and verify the complete deployment allowlist. Windows Swift compiler
setup uses private pinned SDK module maps; it does not modify global SDKs.
This reuses existing native protection, not a new resistance mechanism.
Single-package/main-module console fixtures are qualified; Go modules, SwiftPM,
arbitrary build hooks, concurrent protected calls and macOS remain unverified.

### Experimental JavaScript/TypeScript source backend

Use [JavaScript](../samples/multilang/javascript/project.json) or
[TypeScript](../samples/multilang/typescript/project.json) manifests with one owned
module and explicit root `functions`. Inspection executes an installed, hash-pinned
TypeScript parser bundle, not target code. Build lowers roots and acyclic helpers
to custom encoded VM instructions. `protected.cjs` includes the interpreter;
there is no original-function `eval`, `Function` or AST execution fallback.

Supported scalar Number/BigInt/boolean functions include lexical locals, control
flow, arithmetic, accepted builtins and owned helper calls. Imports, objects,
arrays, classes, closures, recursion, async/generators and arbitrary libraries are
rejected. TS primitive annotations are syntax-checked/erased, not a full semantic
type check. This is a separate JS VM, not native Kagura. Encoded data checksums
do not authenticate the runtime; keys and decoded instructions are locally
available during execution.

The adopted format-2 backend uses function-local opcode/fetch/operand codecs,
instruction-position/opcode/key-derived operand feedback and per-instruction
decoding. It does not decode instructions during import or cache the decoded
whole program. Suspended helper frames can still retain their call instruction.
The import-time checksum binds encoded bytes and canonical codec/offset/slot
metadata, but is unauthenticated and does not cover runtime code. Number binary64
tags and decimal BigInt values remain separate from codec uint32 arithmetic.

New pure and mixed-module builds add a separate flattened dispatch function per
protected function, a function-ID dispatch table, seeded state IDs with
modular-add masking, and permuted opcode-handler groups. Fetch, operand and
operator helpers remain shared. This is generated JavaScript structure, not
native Kagura FLA/SUB/CO or proof of retention after JIT optimization. The
`runtime_hardening` profile is `per_function_flattened_dispatch_v1`; its
`external_resistance` remains `not_evaluated`.

Its fresh focused qualification passed 49 tests (24 new, 25 unchanged) and 82,114
original-versus-VM observations, independently audited before byte-identical
adoption. This covers the scalar fixtures, not ordinary applications, performance
acceptance or external resistance. The post-adoption repository suite is recorded
separately in the phase-12 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase12/README.md`).

Contracts use `kind: "javascript_scalar_samples"`; parameters declare `number`,
`bigint` or `boolean`. Numeric random bounds are integers; BigInt bounds are decimal
strings. Additional Number edges include NaN, infinities, negative zero and
fractions. Validation compares exact scalar tags/values and exception classes,
not messages or stack traces. Small finite domains are enumerated without padding:
two Boolean arguments have four possible inputs, not 8,192 distinct cases.
`baseline.cjs`, source snapshots and intermediate instructions remain private.

### Experimental Python source backend

The default pure route uses [the Python manifest](../samples/multilang/python/project.json)
with `language: "python"`, one owned `.py` source, selected root `functions` and
no `protection_mode` field. Reachable acyclic helpers are included automatically.
The whole source module must fit the documented
[pure integer/bool subset](../samples/multilang/python/README.md). The separate
[opt-in mixed-module route](python-mixed-modules.md) described below retains
ordinary unselected application code; it does not make the pure route general.
No target code executes during inspection/build, and this route needs neither
Kagura nor a native compiler. It emits a custom stack program with per-build
opcode numbers and encoded operands, plus a standalone Python VM runtime.
Original selected function bodies are not packaged for `exec`, `eval` or `marshal`.

The format-2 backend now uses function-local opcode maps and fetch parameters,
instruction-addressed records, and instruction-PC/opcode/key-derived operand
feedback. It decodes only the current instruction in each interpreter frame,
without a decoded whole-function/program cache. A suspended helper caller can
still retain its call instruction. New pure and mixed-module builds generate a
separate flattened Python dispatch function per protected function, a function-ID
dispatch table, XOR-masked seeded state IDs, and permuted opcode-handler groups.
Fetch, operand and operator helpers remain shared; these are not separate native
VMs. Import-time SHA-256 covers encoded bytes and canonical metadata, including
codecs and offsets; it does not authenticate runtime code.

The adopted format-2 candidate passed 53 focused tests (27 unchanged legacy,
26 new) and the three fixtures' 49,302 original-versus-VM observations. A separate
post-adoption repository run completed with 1,566 passed and 80 explicit opt-in
skips, no failures/errors. Skipped integration cases did not run. See the
phase-12 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase12/README.md`)
for pinned versions, raw evidence and limitations. These are functional and
mechanism checks, not performance acceptance or a new external attack evaluation.

Python's unbounded integers, negative floor division/modulo, bool values,
short-circuit conditions and supported loops/helper calls retain Python semantics.
This is not support for arbitrary imports, classes, dynamic objects or libraries.
`protected.py` is the deployment candidate; `baseline.py` and other build records
remain private. Decoded instructions and keys are locally available at runtime.

The [Python validation contract](../samples/multilang/python/contract.json) uses
`kind: "python_integer_samples"`, function/parameter names and inclusive integer
`minimum`/`maximum` sampling bounds. It is not a fixed-width native ABI contract:
returned arbitrary-precision integers are compared exactly, bool is distinct from
int, and raised exception classes are compared (not messages, traces or side
effects). A function producing only exceptions cannot pass. Root/export/helper
closure evidence is checked before either module executes. Native Kagura passes
and native hardening layers are explicitly not applied to this Python backend.

The current script runtime-hardening checkpoint is recorded in
phase 23 (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase23/README.md`).
Its fresh six public pure/mixed Python/JS/TS workflows retain both repeat arrays
for originals and protected artifacts and passed 90,303 input vectors
(361,212 observations). Counts differ by contract and finite domain; this does
not supersede historical artifact evidence or establish all-input equivalence.
Generated-source structure, functional agreement, performance observations and
external resistance are separate evidence stages.

### Optional Python mixed-module route

Use [the ordinary quote package](../samples/multilang/python_mixed/README.md) and
its exact six-field manifest with `protection_mode: "mixed_module"` to select
pure integer/bool roots inside one ordinary module. The frontend also protects
supported acyclic helpers in that module. Relative imports, UI/presentation
code, classes and other unselected functions retain their source/order; selected
functions keep their original callable names through VM wrappers.

This route returns backend `python_mixed_module_vm`. It shares format-2 Python
VM encoding with the pure route, not native Kagura passes. Selected global
values, objects, dynamic calls, defaults/decorators and other unsupported forms
are rejected rather than silently captured or copied as an unprotected fallback.
The [reference](python-mixed-modules.md) states the schema and exact boundaries.

Existing `source-plan` and `source-build` commands inspect and generate without
executing application code. Success remains `artifact_created_unvalidated`.
Keep the original package path/import names when replacing the selected module
in a fresh private deployment copy. No package assembler or installer is provided.
Do not reuse old bytecode caches as part of source-module replacement.

Mixed-module `source-validate` now requires the explicit
`python_mixed_module_application_samples` contract. It binds the original plan,
engine/toolchain and staged package siblings, then compares declared scalar
entrypoints in separate original/protected package-import processes. The existing
`python_integer_samples` contract still does not authorize package startup.
UI text, stdout, side effects, full semantics, performance and external protection
evaluation remain separate requirements. See the [reference](python-mixed-modules.md)
and the public sample contract; historical pure-module observations are not
evidence that an arbitrary mixed application passed.

The initial mixed-module adoption passed a separate 106-test qualification and
an independently audited ordinary-package differential: 8,217 unique inputs,
two repeats per original/protected arm, 16,434 comparisons. The post-adoption
repository suite then passed 1,646 tests with 80 explicit integration skips and
no failures/errors. All 56 new mixed tests passed, including a public quote
package test with 32,868 sampled calls plus UI error and CLI checks. The real
public CLI plan/build also generated the selected core/helper VM without
executing the application. These are bounded fixture observations, not generic
application execution authority, performance acceptance or external resistance.
See the phase-15 evidence (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase15/README.md`).

The subsequent explicit application-validator integration passed a fresh suite:
1,675 passed, 80 explicit integration skips, zero failures/errors. Independent
collection matched all 239 source/tool pins and 85 mixed-Python test IDs. The
public CLI plan/build/validate workflow compared 8,203 retained first-pass
original/protected output pairs in separate processes. This small calculation
fixture measured about 237x call-observation overhead after protection; no
performance acceptance or external-defense verdict follows. See the
phase-16 evidence (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase16/README.md`).

The same phase's supervised Opus 5.5 xhigh wave produced separate, unintegrated
candidates. Root independently audited C#'s 92 process receipts and 41 matching
app comparisons (38 unique inputs), including actual selected-method calls to
the native interop and missing-core failure controls. Rust's capture/coverage
adapter passed 31 new and 24 preserved tests, but only 14 of 30 source symbols
bind to original carrier members; missing symbols, COMDAT, archive parsing and
same-snapshot linking still block application substitution. The JS/TS candidate
fixes known binding errors by conservative rejection; root verified six such
cases and one supported CommonJS app in separate processes. These candidates
are not in the 1,675-pass production suite above. Public adoption, broader app
and platform qualification, performance and external effectiveness remain open.

### Optional JavaScript / TypeScript mixed modules

Phase17 connects `protection_mode: "mixed_module"` to the production source-plan
and source-build API/MCP tools. Selected scalar roots and their reachable owned
helpers enter the format-2 JavaScript VM; surrounding application code remains
ordinary code. JavaScript preserves unselected text; TypeScript is transpiled as
a whole CommonJS module, including runtime constructs such as enums/namespaces.
This is not merely type erasure, full type checking or native Kagura protection.

JavaScript now has an explicit `javascript_mixed_module_application_samples`
validation contract through the public service/MCP/CLI route. Phase19 adds the
separate `typescript_mixed_module_application_samples` route, using a fresh
pinned-compiler reference and a `.cjs` entry in place of the original `.ts` entry.
It rejects additional TS source files and runtime-name collisions; arbitrary TS
graphs and full type checking remain unfinished. The phase19 record tracks its
qualification separately from historical build-only receipts.
Building does not import or execute the app. Validation explicitly
runs owned application startup in separate bounded Node processes. Deployment
remains manual in the original package context. See
[supported boundaries and examples](javascript-mixed-modules.md).

The historical phase17 production suite passed **1,732 tests**, with **80 explicit
integration skips** and zero failures/errors. Root independently checked all 255
source/tool pins and 42 mixed-JS test IDs. Fresh JS/TS public builds remained
`artifact_created_unvalidated`. A reproduced CommonJS `require` reassignment bug
is now rejected, with failing-before/passing-after tests. Separate transform
audit evidence includes a fresh 3,060-case matching differential; it is sampled
correctness, not an external defense evaluation.

The same phase adopts a narrow Rust LLVM archive-name alignment fix, preserving
all protected-link gates. C#'s corrected private integration candidate has 41
matching sampled cases and 92 independently audited process receipts; it is not
yet a public app route. JavaScript's initial validator qualification was rejected
by root for missing integrity checks. After candidate corrections and a root-fixed
bounded test harness, 59 focused tests and 10,253 input vectors (two repetitions
per arm) passed. Root independently checked raw results, source/tool/stage pins
and process cleanup. This qualifies an owned CommonJS fixture snapshot only,
not a public ProjectService plan, TypeScript validation or all-input equivalence;
the validator remains private. Evidence-preservation and worker-scope violations
are explicitly recorded in the phase17 report rather than treated as compliant.
Generic Cargo protected BUILD, macOS, arbitrary applications, performance
acceptance and external resistance remain unfinished. Exact evidence and limits:
phase17 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase17/README.md`).

Phase18 adopts the JS validator, adds per-arm saved-plan/engine/runner integrity
checks and exact original-JS baseline binding. The first actual public CLI
plan/build/validate run and independent raw-receipt audit passed 16,418 input
vectors (two repetitions per arm), including a preserved caller of VM helpers.
This is finite scalar functional evidence, not a UI/side-effect, performance or
external-defense result. Phase18 tests and parallel candidates are tracked in the
phase18 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase18/README.md`);
the older 1,732-pass result is not proof for these newly adopted bytes.
The final phase18 CLI rerun also binds the pre-VM working-source hash. Its full
test run had 1,813 passes, 80 explicit skips and one test-only output-path error;
after correcting only that test path, all 16 tests in the affected file passed.
The raw failed full run and focused correction remain separate records. TS's
same-source private harness now matches 16,418 vectors; C#'s generic candidate
matches nine managed-app cases with reused native protection. Neither candidate
is publicly integrated, and the new Rust classifier does not qualify a protected
Cargo link. All four Orca worker terminals were released.

Phase19 publicly integrates the independent TS reference and explicit mixed-app
validation route. Its final source-frozen CLI run matches **16,418 input vectors**,
twice per arm; an independent auditor checks the original source, pinned compiler
reference, executable overlays, service-plan identity and six process receipts.
The fresh full suite runs **1,954 tests: 1,874 passes, 80 explicit opt-in skips,
zero failures/errors**. The 60 new TS tests all execute and pass. This supersedes
the phase18 build-only TS boundary, not its historical receipts or limitations.

C#'s phase19 private candidate now owns its transform and serializable plan and
has 45 focused tests plus seven matching managed-app cases. It reuses an existing
native artifact; public ProjectService adoption and fresh protected-native build
linkage remain open. Rust's worker declined pending direct human scope clarification;
no refused task was transferred or rephrased for another worker. All four actual
Orca Opus 5.5 xhigh terminals were released. Worker procedure deviations and root
corrections are recorded, not retroactively treated as compliant execution.
No performance or external defense result is inferred from functional counts.
See the phase19 checkpoint (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase19/README.md`).

Phase20 adopts the C# transform and integration engine into the public
`source-integrate` / `protection_source_integrate` route. A fresh, frozen public
workflow built three protected integer methods, matched original CLR on 8,516
inputs per method, rewrote their managed bodies, and passed ten original/protected
application cases. Relocating only the three deployment files passed the same ten
cases. The independent raw audit verified 75 cleaned processes, source/tool/report
pins and missing/unset-native controls. Integration reuses the artifact from that
fresh build; it does not rebuild native code itself. See the
phase20 qualification (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase20/public-csharp-qualification.md`).
The final frozen full suite separately passed **2,051 tests with 81 explicit
opt-in skips, zero failures/errors**, and 2,545 unchanged source/tool pins.
The independent auditor reconciled all 2,132 test records, including 178 new
C# identities (177 passes and the one named optional E2E skip). The fresh public
workflow was independently audited again after the suite. Rust remains pending
the direct human clarification; macOS, general applications, performance
acceptance and external resistance remain unfinished.

Phase21 adds the public [Java/Kotlin app route](jvm-applications.md): compile
ordinary callers against the original core, preserve their bytecode and replace
the core classes with exact JNI-backed forwarding facades. Fresh Java **and**
Kotlin builds each passed 51,096 original-JVM/native scalar comparisons, 11 app
cases and 11 relocated-bundle cases. Independent raw audits checked 75/76 clean
processes and 2,728 unchanged pins. The separate full suite passed **2,271 tests
with 82 explicit opt-in skips**, zero failures/errors/xfails and 2,726 unchanged
pins. The first SDK-capture failure and its bounded reproduction/fix are retained.
See phase21 (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase21/README.md`).
No whole-JAR, reflection-detection, macOS, performance or external-resistance
claim follows from those sampled results.

Phase22 adds the public [Go/Swift app route](go-swift-applications.md). Fresh
Go and Swift workflows passed **68,128 / 136,256** original-runtime/native
scalar comparisons, **17 / 15** application cases and **17 / 15** relocated
bundle cases. Independent read-only audits verified **92 / 88** cleaned
processes, **2 / 37** exact deployment files and **2,752** unchanged pins per
workflow. The Swift bundle includes its reviewed runtime DLLs.

Artifact-path serialization, private SDK module maps and Windows Swift stdout
newlines were diagnosed with retained actual failures and regression tests.
After the runtime audits, only one C# regression-test file changed: its previous
unsupported-Go sentinel was no longer valid once Go dispatch existed. An exact
test-only delta audit reconstructs the former test-file hash and checks that all
production/tool/sample pins remain unchanged. The corrected focused suite has
**377 passes and one explicit installed-toolchain opt-in skip** out of 378.
Final full discovery and its independent raw audit passed **2,506 tests with
82 explicit opt-in skips** out of 2,588, zero failures/errors/xfails, and
2,750 unchanged pins. The final delta audit also reconciles this later test
snapshot with the unchanged Go/Swift runtime implementation.
See the phase22 record (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase22/README.md`).
These are sampled functional results, not general project, macOS, performance,
concurrency or external-attack qualification. The overall goal remains open.

### Reproduce the owned integration checks

The ordinary suite skips the full MCP compiler/execution integration workflows
unless opted in. Its Python VM and bounded worker tests still execute owned code:

```powershell
$env:ANTIREA_RUN_SOURCE_E2E = "1"
$env:ANTIREA_RUN_EXTENDED_SOURCE_E2E = "1"
$env:ANTIREA_RUN_LANGUAGE_E2E = "1"
python -m unittest discover -s tests -q
```

The extended workflow covers actual MCP plan/build/validate for reviewed native
context, C# source and Python source, with 8,192 random samples plus separately
generated edges and two behavior repeats. Those generic edge counts differ from
the independent native/CLR/Python fixture suites above. Build/validation artifacts
are private append-only jobs under `.runs/source-protection/`; these checks do
not launch REA, publish candidates or change the external experiment's counts.

The additional opt-in workflow covers actual Java, Kotlin, JavaScript and
TypeScript MCP plan/build/validate. Set `ANTIREA_RUN_GO_SWIFT_E2E=1` as well to
include Go and Swift. Native-lowered language checks include original execution; script
baselines execute the owned original source (TS annotations erased). Set
`ANTIREA_BINDINGS_REAL=1` separately to compile/run native-core binding fixtures.
The TypeScript binding check uses the installed compiler API with strict semantic
diagnostics before emission, and verifies a deliberate BigInt-to-Number type error
is rejected without output. That binding test does not make the separate TS source
protection frontend a full semantic type checker.

Generated integration code also has explicit initialization failure checks.
The common C bridge publishes its handle and function pointers only after every
export resolves, releases an incomplete load, and rejects calls before success.
C# leaves unrelated P/Invoke names to the default resolver and permits a retry
after an initial load failure without registering its resolver twice. JNI converts
UTF-16 to standard UTF-8, rejecting interior NUL and unpaired surrogates rather
than passing JNI Modified UTF-8 to a standard UTF-8 loader. Actual Windows
C/C#/Java/Kotlin regression programs cover these paths, including BMP and
supplementary Unicode directory names. See the private
33-test integration checkpoint (local-only record: `../.runs/interop-fix-all-bindings-20261020.json`).
The common/C#/JVM integrations still require initialization before worker threads
and a single generated contract in the documented process/assembly boundary;
this does not implement arbitrary multi-contract loading or reload support.

To include the real Go parser and loop-semantics regression, additionally set
`ANTIREA_RUN_GO_PARSER_TESTS=1` and `ANTIREA_RUN_GO_LOOP_TESTS=1`. Protected binding
checks require explicit immutable build reports through
`ANTIREA_BINDINGS_GO_REPORT` / `ANTIREA_BINDINGS_SWIFT_REPORT`; the C-based
integration checks similarly require `ANTIREA_BINDINGS_BASELINE` and
`ANTIREA_BINDINGS_PROTECTED`. Compiler discovery or an ordinary passing unit
suite alone is not evidence these opt-in cases ran.

### Native VM performance checkpoint

The scalar-fetch generator now validates an entire 1/2/4/8-byte span once before
reading it, using overflow-safe checks. Byte-wise decoding/feedback and the
VM, fusion, FLA/SUB/CO and bytecode checksum remain. This removes repeated bounds
branches that amplified after runtime flattening.

One warmup and seven same-worker rotating measurement rounds (256 calls each)
showed context `121.32 → 47.66 ms` and C# fixture functions
`139.07 → 42.12`, `170.07 → 49.26`, `63.67 → 20.27 ms`: 2.55–3.45× faster than
the previous protected builds. These are small-function measurements including
ctypes overhead, excluding loading/startup. They remain about 195–573× slower
than the unprotected baselines, not a product SLA pass or an attack-resistance
result. C# performance comparison uses the fixed native baseline; original CLR
comparison is a separate gate. See local
context evidence (local-only record: `../.runs/native-context-span-v1-performance-final/performance.json`)
and C# evidence (local-only record: `../.runs/native-dotnet-span-v1-performance/performance.json`).

## Audited hardening capabilities

`HARDENING_LAYERS` is a request vocabulary, not an applied-feature checklist.
The earlier manifest-only header tag is now accompanied by a runtime check
covering the full encoded bytecode and its length. All three final native
artifacts retain the checksum helper and its dispatcher call. This is a
recoverable, non-cryptographic corruption check, not executable authentication.

The symbol-hash helper is still not an API resolver; anti-dump is not implemented.
New multi-function native builds support separate per-function VM codecs and
dispatchers with volatile indirect calls. The four-function context fixture
retains all four engines' FLA/SUB/CO and checksum calls and passes sampled
correctness checks. Historical single-engine artifacts remain single-engine;
top-level legacy `parameters`/`dispatcher_symbol` aliases describe only the first
engine in a multi-VM manifest. Decoders and pointer slots are locally recoverable,
not cryptographic independence. MBA checks and the synthetic
encoded constant pool are helper-only, not transformations of all application
operations or strings. Final optimized core IR removes the inert decoys.
The narrow anti-debug source component exists, but the current IR inspector did
not prove its retention in these artifacts. See the
[capability audit](hardening-capabilities.md) for exact states and evidence stages.

Kagura FLA/SUB/CO, selected-function VM wrappers/blobs, diversification and runtime
transformations have their own structural coverage fields. Do not infer their
presence from optional hardening names or infer resistance from their presence.

Do not silently remove a requested technique, but do not mark it applied merely
because its name appears in a settings list. Missing mechanisms and unverified
platform paths remain explicit unfinished requirements.

## Safety and reproducibility

- Own-source builds only; no received attacker programs or instructions.
- Fresh output directories, reviewed source manifests and input/tool hashes.
- No implicit package installation, arbitrary build-hook execution, remote push,
  or publication from a source build.
- Inspecting/compiling source and executing functional tests are separate
  operations. Generated artifacts are not sandboxed by the MCP bridge.
- `ponytail` was requested but its source is unavailable in the checked skill
  locations. No instructions have been invented for it.
