# Go ordinary-application integration fixture (phase22)

A minimal ordinary Go program whose protected build substitutes same-name
`package main` core facades for the original core, keeping the application source
byte-for-byte identical. It is a defender fixture only; it does not attack, and it
performs no builds by itself.

## Files

- `core.go` — the original owned core. Derived **unchanged** from
  `samples/multilang/go/core.go` except for the package clause
  (`protectedcore` -> `main`), so the four roots `Fold`, `Wide`, `Mix`, `Narrow`,
  the private helper `mixHelper` and the constant `blend` keep their exact
  algorithm. This is the source the Go frontend protects into the native core DLL,
  and it is **excluded** from the protected application compile.
- `main.go` — the ordinary application (`package main`). It dispatches
  `app <fold|wide|mix|narrow> operands...` to the four roots and prints the typed
  result with `fmt.Println`. Operands are parsed before any root is called, so a
  usage failure never loads the native core. It references only the four public
  roots — never `mixHelper` or `blend` — so the protected build (whose facade
  omits the helper and constant) still compiles; a reference to either would fail
  compilation, which is the intended fail-closed behaviour.
- `project.json` — the core source project consumed by the Go frontend to build
  the pinned protected native core (`Fold`/`Wide`/`Mix`/`Narrow` ->
  `go_fold`/`go_wide`/`go_mix`/`go_narrow`).
- `native-contract.json` — the native core cdecl ABI contract for all four
  exports (`go_fold` i32(i32,i32), `go_wide` i64(i64,u64), `go_mix` u64(u32,u32),
  `go_narrow` u32(i64,u32)), matching the existing Go ABI. `library_name` is
  `go_app_core`, matching the contract the frontend derives from `project.json`.
- `integration.json` — the fixed `native_application_integration` spec
  (`language` go, `application_sources` `["main.go"]`).
- `application-contract.json` — the fixed `native_application_samples` contract.
  The first success case (`fold-normal`) exercises a native root, so the engine's
  missing-core / unset-core negative controls prove the protected app depends on
  the loaded core. Cases cover all four exports, signed/unsigned edges, zero,
  multi-iteration and usage failures. `expect` carries only `returncode` and
  `stdout` (no stderr equivalence).

The root public focused runner expects exactly these fixture inputs in this
directory: `project.json`, `native-contract.json`, `integration.json`,
`application-contract.json`.

## Expected outputs

Expected `stdout` values were derived by an exact port of the Go fixed-width
integer semantics (two's-complement wrap, logical/arithmetic shifts, `&^`), not
by executing Go. Root re-qualifies every expectation against the real original
build before acceptance; these are not a self-certified pass.

## Boundaries

Package `main`, Windows/amd64, no cgo and no modules. Generation and these
fixtures are not compilation, behaviour or defense-strength evidence; the actual
fresh builds, >=8192-case original-runtime comparisons, application cases,
negative controls, copied-deployment rerun and independent audits are owned by
root and run only under its bounded runner.
