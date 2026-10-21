# C++ namespace and overload integration fixture

Owned three-translation-unit source for the C++ protection-only symbol mapper.
`wide.cpp` and `narrow.cpp` define real `core::mix` overloads, `wide.cpp` also
defines `core::finish`, and `narrow.cpp` contains a static `core::tweak` helper.
The public C ABI function calls those C++ implementations; the helpers are not
rewritten to `extern "C"` merely to satisfy the protection backend.

The opt-in test generates an actual compilation database with separate GNU O0,
GNU O2 and clang-cl O2 settings in a fresh private `.runs` directory. A fourth
case defines `ANTIREA_PUBLIC_FORWARDER` and reviews `public_forward` as a public
boundary: it must still call the mapped, protected `core::finish` helper after
optimization and linking. The default scope discovers the helper closure from
`public_score`, without guessed compiler-mangled selectors.

Run after the native mapper and independent validator are integrated:

```powershell
$env:ANTIREA_RUN_CPP_PROJECT_E2E = "1"
python -m unittest discover -s tests -p test_cpp_project_build.py -v
```

The tests require original-source, unprotected LLVM and protected native DLLs,
with 8,192 random inputs plus boundaries and two repeats for every export.
They also check source/protected symbol bijection, all three VM evidence stages,
public exports, schema-2 independent verification and process cleanup. Build
and target execution occur only when explicitly opted in; the fixture is not
received attacker code. Test presence is not a passing execution result.

This is not arbitrary C++ application compatibility: objects, exceptions, RTTI,
templates/COMDAT, callbacks and arbitrary final application links remain separate
work. No resistance to REA or performance acceptance is inferred from this fixture.
