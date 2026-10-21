# Validation status — 2026-10-22

This is a public summary of local maintainer qualification, not a published raw
evidence bundle or a claim that all programs in these languages are supported.
Private toolchain paths, raw logs, generated binaries, internal plans and incoming
external reports remain outside this repository. Historical local-only paths in
the development documents identify records; they are not download links.

## Functional qualification

The latest completed implementation qualification ran on Windows x64. Ordinary
regression recorded **2,891 passed tests and 82 deliberate opt-in skips**, with
zero failures/errors and 2,806 unchanged source/tool/runner pins. A separate
focused suite passed 202 tests. Opt-in skips are not counted as passes.

| Supported sample route | Observed result |
| --- | --- |
| Direct C, multi-source C++, single-crate no_std Rust | Each matched 8,200 sampled/boundary cases across independently source-compiled original, normalized baseline and protected DLLs |
| C# | Three methods compared with original CLR execution on 8,516 input vectors each; 10 app and 10 relocated-deployment cases |
| Java / Kotlin | Each: 51,096 scalar comparisons, 11 app and 11 relocated-deployment cases |
| Go | 68,128 scalar comparisons, 17 app and 17 relocated-deployment cases |
| Swift | 136,256 scalar comparisons, 15 app and 15 relocated-deployment cases |
| Python / JavaScript / TypeScript | Preceding increment: 4 / 15 / 13 app cases respectively across original, protected and copied-deployment arms; not newly rerun as actual apps after the native-only change |

Application qualification also checks failure when the protected core/module is
missing, producer/source/tool identity and saved execution evidence. Separate
read-only auditors checked the native/managed application records without
executing the applications themselves. Installed runtime dependencies remain
required where applicable.

The first Go integration hit a 900-second outer timeout. A reviewed continuation
reused that exact successful native build and completed integration in 954.977
seconds with an 1800-second outer allowance. Its per-child timeout and correctness
checks were unchanged. Both attempts were retained locally; the continuation is
not an additional fresh native build. The independent auditor checked 96 clean
process records and an EXE-plus-protected-DLL deployment without source or IR.

## Implementation and trust limits

Direct native validation now requires an independently source-compiled original;
agreement between two outputs of the same normalization path is insufficient.
Reference provenance binds the declared sources, compiler/link recipes, ABI
evidence and multi-source signature merge. Public validation binds these records
to the saved owned build. It is not cryptographic attestation against an operator
who controls all local files or a hostile-code sandbox.

These are experimental scalar-core and owned CLI sample routes, not arbitrary
packages, GUI applications or whole-language compatibility. macOS still needs
real-host qualification. General Cargo application protection/linking, arbitrary
project formats and runtime features remain incomplete.

Functional preservation does **not** establish resistance to REA, runtime analysis
or cloning. No new external attack evaluation was run for these artifacts.
Performance acceptance is also open: tiny native sample protected/baseline batch
ratios were roughly 458x (C), 469x (C++) and 310x (Rust) on a shared host. These
are small-function costs, not app startup times or an isolated performance SLA.

For commands, prerequisites and exact supported input contracts, see
[multi-language development](multilanguage-development.md). For requested versus
implemented hardening, see [hardening capabilities](hardening-capabilities.md).
