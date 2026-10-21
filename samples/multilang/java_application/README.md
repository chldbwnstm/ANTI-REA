# Java ordinary-application integration sample

A separated pure-scalar core (`Core.java`, accepted by the ANTI-REA JVM
frontend) plus an ordinary application (`App.java`) in one project tree. The
app is compiled against the original core and keeps calling the same public
static roots; after integration those roots are substituted by native-backed
same-name Java facades while the app bytecode is unchanged.

| File | Role |
| --- | --- |
| `project.json` | Core project selectors: three public static roots (`scramble (II)I`, `blend (JJ)J`, `narrow (JI)I`). `step (II)I` is a private helper in the protected closure. |
| `Core.java` | Pure scalar core source (build evidence; never deployed). |
| `App.java` | Ordinary application source; exercises all three exports, argv/loops/IO/exit. |
| `native-contract.json` | Expected cdecl ABI contract (three `i32`/`i64` exports). |
| `integration.json` | `jvm_application_integration` spec: `application_sources`, `main_class` `sample.App`. |
| `application-contract.json` | `jvm_application_samples`: exact `stdout` + `returncode` per case. |

Bounded iteration: `scramble` masks its loop count with `rounds & 7`, so for
EVERY int32 `rounds` (including INT_MAX and negatives) it does finite, terminating
work — required because root source-validate feeds full-width random/boundary
inputs to each root. This is a fixture-validation bound, not a defense
enhancement, and it is applied identically to the original and the lowered native.
The application only ever passes `rounds` in 1..4, where `(rounds & 7) == rounds`,
so the expected outputs below are unaffected.

Exact-stdout provenance: the numeric case outputs were computed from a pure
reference model of the documented Java integer semantics (32/64-bit two's
complement wraparound, masked shifts). They are candidates and MUST be confirmed
by the root harness's authentic original build/run; if a value differs, the
sample reference is what needs fixing, not the protection. stderr (usage text,
uncaught-exception stack traces) is recorded raw but not compared; the
`non-integer-seed` case asserts only the uncaught-exception exit status and
empty stdout. Case order is deliberate: `one-round` is first because it reaches
the protected roots and the root/engine harness uses the first exit-0 case as the
missing-native control; `zero-rounds` (which never reaches a protected root)
follows. No `.class` files are committed.
