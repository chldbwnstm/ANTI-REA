# Swift ordinary-application integration fixture

An ordinary Swift executable (`main.swift`) plus the owned scalar core
(`core.swift`, byte-for-byte the same as `samples/multilang/swift/core.swift`)
living in the same project directory. It exercises the native-application
integration route for `language == "swift"`.

## Files

- `core.swift` — owned scalar core; four `@_cdecl` public roots. Unchanged from
  the existing Swift fixture (semantics and constants fixed).
- `project.json` — source-build project for the core (`swift_frontend`).
- `native-contract.json` — reference ABI the frontend derives from the core.
- `main.swift` — ordinary application; see below.
- `integration.json` — `native_application_integration` spec (app sources only).
- `application-contract.json` — `native_application_samples` cases.

## The application

`main.swift` takes `<op> <x> <y>` and calls one root per run so that every
selected export is covered and the missing/unset-core controls clearly fail:

| op           | root               | labels              | types        |
|--------------|--------------------|---------------------|--------------|
| `score`      | `swift_score`      | underscore (`_`)    | u64, u64→u64 |
| `signed`     | `swift_signed`     | underscore (`_`)    | i64, i64→i64 |
| `unsigned32` | `swift_unsigned32` | named (`x:`, `y:`)  | u32, u32→u32 |
| `signed32`   | `swift_signed32`   | named (`x:`, `y:`)  | i32, i32→i32 |

Both external-argument-label styles are used, so the protected build only
compiles if the generated facades preserve each root's external labels exactly.

Exit codes: `0` success; `2` usage error (wrong arity or unknown op, no stdout);
`1` operand parse error (non-integer or out-of-range for the op's scalar type,
no stdout).

## Two builds, one app source

- Original: `main.swift` + unchanged `core.swift`, one module.
- Protected: the SAME `main.swift` bytes + generated same-name facade
  declarations + the generated `NativeCore` bridge + the common C bridge. The
  original `core.swift` is never in the protected compiler inputs or deployment;
  each root forwards to the packaged protected native core loaded from the
  absolute local-drive path in `ANTIREA_NATIVE_CORE`.

## Expected outputs are candidates

The `expect.stdout` values are candidate references computed from the core's
wrapping-integer semantics. The Windows fixture uses literal CRLF stdout bytes,
as observed in both unchanged original and protected apps across all15 cases in
the bounded diagnostic `swift-newlines-20261020T103001Z-9d8e555d`. Numerical
values and source bodies were unchanged; the comparison engine does not normalize
line endings. This diagnostic reuses an existing build and is not a new public
workflow qualification. The root lane must
qualify them against the real compiled original before acceptance, and the
protected run must match the original across the full comparison set. Generation
of facades, native protection, packaging and external attack resistance are all
separate, separately-evaluated claims.
