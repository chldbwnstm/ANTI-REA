# Kotlin ordinary-application integration sample

A separated pure-scalar core (`Core.kt`, `@file:JvmName("Core")`, accepted by
the ANTI-REA JVM frontend) plus an ordinary Kotlin application (`App.kt`) in one
project tree. The app is compiled against the original core metadata and keeps
calling the same binary method identities; after integration those roots are
substituted by native-backed same-name Java facades while the app bytecode is
unchanged. @Metadata/reflection and downstream Kotlin recompilation of the
bundle are NOT preserved or claimed.

| File | Role |
| --- | --- |
| `project.json` | Core project selectors: three public static roots (`scramble (II)I`, `blend (JJ)J`, `narrow (JI)I`). `step (II)I` is a private helper in the protected closure. |
| `Core.kt` | Pure scalar core source compiling to `sample.Core` (build evidence; never deployed). |
| `App.kt` | Ordinary application source compiling to `sample.AppKt`; exercises all three exports, argv/loops/IO/exit. |
| `native-contract.json` | Expected cdecl ABI contract (three `i32`/`i64` exports). |
| `integration.json` | `jvm_application_integration` spec: `application_sources`, `main_class` `sample.AppKt`. |
| `application-contract.json` | `jvm_application_samples`: exact `stdout` + `returncode` per case. |

Bounded iteration: `scramble` masks its loop count with `rounds and 7`, so for
EVERY int32 `rounds` (including INT_MAX and negatives) it does finite, terminating
work — required because root source-validate feeds full-width random/boundary
inputs to each root. This is a fixture-validation bound, not a defense
enhancement, and it is applied identically to the original and the lowered native.
The application only ever passes `rounds` in 1..4, where `(rounds and 7) == rounds`,
so the expected outputs are unaffected.

Exact-stdout provenance: identical integer algorithm to the Java sample, so the
numeric outputs match. They were computed from a pure reference model of the
documented Kotlin/Java integer semantics and MUST be confirmed by the root
harness's authentic original build/run. A Kotlin runtime jar may be required at
runtime from the pinned installed toolchain. stderr is recorded raw but not
compared. Case order is deliberate: `one-round` is first because it reaches the
protected roots and the root/engine harness uses the first exit-0 case as the
missing-native control; `zero-rounds` (which never reaches a protected root)
follows. No `.class` files are committed.
