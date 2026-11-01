# Trusted Cargo unit recorder

`wrapper.rs` is a std-only Windows x64 `RUSTC_WRAPPER`. Its source was promoted from the private prototype, with an explicit pinned MSVC linker contract added. The promoted source has not yet been compiled or run at authoring handoff. Historical prototype results do not verify this new binary.

The trusted coordinator, not a project manifest, compiles and pins this source with the selected real rustc, runs its Rust tests and `--self-test`, and compares the latter with `antirea.rust_cargo_units.verify_wrapper_selftest`. It creates fresh policy/record/target directories and launches Cargo through bounded `run_logged` with the workspace STOP marker. It must retain the source/compiler/SDK/config/process evidence. There is no Cargo manifest, package dependency or project hook in this tool directory.

The policy has fourteen singleton fields: `schema`, `mode`, `backend`, `backend_sha256`, `backend_host`, `wrapper`, `wrapper_sha256`, `linker`, `linker_sha256`, `workspace`, `record_root`, `target_root`, `sysroot`, `stop`, followed by repeated `input_root` and `source` fields. Its compiled backend host and target are `x86_64-pc-windows-msvc`.

Every real crate invocation must have exactly one `-C linker=<exact policy path>` (compact spelling is also parsed). Probes may omit the linker; any supplied linker must be single and exact. Backend, wrapper and linker bytes are checked before/after the compiler. `start.json` records all three identities. Arbitrary link arguments, custom codegen backends, response files, native `-l` arguments, binary/test/proc-macro/build-script units remain unsupported and are rejected.

The explicitly pinned installed linker may have OS-maintained hardlink aliases; its content hash is still mandatory. Backend/wrapper binaries, owned sources and policy/record files retain the no-hardlink rule. Cargo output aliases use the separate full in-target alias accounting check, not the SDK exception.

Original compiler arguments, environment name/value spelling, working directory and Cargo standard streams are forwarded unchanged. Only derivative crate recipes add LLVM IR output and explicitly replace the three recorded codegen controls: no-prepopulate-passes, embed-bitcode=no and codegen-units=1. Cargo planning uses `--jobs 1` in both arms so independent crates do not race the existing target-tree stability checks. These controls are not a promise of semantic equivalence for every Cargo profile.

Records retain exact compiler arguments, package identities, input hashes and two raw diagnostic environment values (`PATH`, `CARGO_MAKEFLAGS`) only. Other environment values are hashed, not dumped. All records, IR and policy files are private defender evidence; the two diagnostic values and argv can still contain sensitive paths or cfg data. Never publish them as attacker-facing artifacts.

The recorder checks owned source/extern paths, scoped hardlink aliases and STOP, but only waits/kills its direct compiler child. The coordinator's owned Job must verify descendant cleanup. This is not an OS sandbox, a complete compiler-read trace, a link-closure proof or a protection verdict. It never launches the generated application.
