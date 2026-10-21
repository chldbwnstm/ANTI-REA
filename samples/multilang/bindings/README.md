# Public native-core FFI fixture

`fixture.c` is a public, non-security ABI test. It joins two `uint32_t` values
into one `uint64_t` and exposes signed/unsigned identity functions plus a void
function. It is not the ledger algorithm, a secret-bearing sample, or proof of
protection strength.

`contract.json` is a schema-1 example accepted by
`antirea.bindings.generate_bindings(contract, new_output_directory)`. The bundle
contains separate C, C++, Rust, Swift, Go, C#, Java, Kotlin, Python, JavaScript
and TypeScript bindings. JavaScript/TypeScript use a dependency-free Node-API
addon; Java/Kotlin use a JNI adapter. Both adapters call the same native ABI.

Normal unit tests generate source only. To additionally compile and execute this
owned fixture with installed toolchains (no installations or network packages):

```powershell
$env:ANTIREA_BINDINGS_REAL = '1'
$env:ANTIREA_BINDINGS_EVIDENCE = 'C:/absolute/private/bindings-validation.json'
python -m unittest discover -s tests -p test_bindings.py -v
```

Unavailable compilers/development headers are recorded as unavailable and
skipped, never treated as successful validation. The Windows test uses the
existing `.tools/kagura-toolchain.json` developer environment. Node-API headers
and `node.lib` must already exist in the local cache for the installed Node
version. C# restore uses an empty package-source configuration.

The additional protected integration test accepts explicitly supplied trusted
local artifacts with ABI `uint64_t native_transform(uint32_t, uint32_t)`:

```powershell
$env:ANTIREA_BINDINGS_BASELINE = 'C:/absolute/private/baseline.dll'
$env:ANTIREA_BINDINGS_PROTECTED = 'C:/absolute/private/protected.dll'
```

That test compares eight boundary/sample calls from Python, Node, Java and C#
against the baseline and records artifact hashes before/after. It is a binding
smoke test, not the independent large-suite native equivalence/performance gate,
not a protection-coverage test, and not an attack or resistance measurement.
Never point it at incoming reports or downloaded executable code.

Generated FFI wrappers do not transform or protect original-language application
source. The sensitive implementation must actually live in the separately built
and protected native library. The remaining application and FFI interface stay
visible. Initialization is single-threaded and one-time per bridge/contract;
the library remains loaded until process exit.
