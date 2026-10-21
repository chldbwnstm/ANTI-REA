# Experimental direct Python source protection

These owned fixtures exercise a **direct Python source-function VM backend**.
They do not call a protected native DLL and are distinct from FFI bindings.
`project.json` selects `integer_score`; its owned helper is included automatically.

The compiler parses a single pure module and lowers supported AST nodes to custom
stack instructions. A generated Python interpreter executes a per-build encoded
program with randomized opcode numbers. It does not `exec`/`eval`/`marshal` the
original function bodies. Python's unbounded integer arithmetic and bool values
are retained; errors such as negative shifts, division by zero and unbound locals
retain their exception class (not exact traceback/message).

Supported: int/bool literals and module constants; ordinary positional/keyword
public parameters; local assignments; integer arithmetic `+ - * // % << >> & | ^`;
unary operators; short-circuit `and`/`or`; chained comparisons; conditional
expressions; if, while, for over unshadowed range, break, continue and loop else;
acyclic owned helper calls; abs/int/bool and multiargument min/max. Internal helper
calls use positional arguments only. Implicit/explicit None returns are preserved
but are not accepted by the integer-sampling validator as successful outputs.

Rejected before output: imports, module execution, collections/attributes,
classes/closures, decorators/defaults, variadics, recursive calls, exceptions
handlers, async/generators, float/division/power and arbitrary library calls.
The complete single module must fit the subset, including unselected functions.
Inputs are exact Python ints/bools, not custom numeric objects or subclasses.

Generate privately (no source execution):

```powershell
python -m antirea.python_frontend inspect --project samples/multilang/python/project.json
python -m antirea.python_frontend build --project samples/multilang/python/project.json --workspace . --output-dir .runs/python-example --seed 1729
```

Output contains private `baseline.py`, `coverage.json`, `report.json` and the
standalone `protected.py`. Only the latter is a potential deployment artifact;
do not publish the whole private output directory. Build status is
`artifact_created_unvalidated`; tests/validation must explicitly execute owned
baseline and protected code in a separate step.

The import-time checksum covers encoded data, not runtime code. Its key/checksum
are locally available, so it is not authentication or a claim of tamper resistance.
Decoded instructions exist in memory. No Kagura LLVM passes, native VM, anti-debug,
anti-dump, IAT protection or external attack resistance are claimed for this route.
Performance is not accepted merely because samples match. No runtime step/memory
limit is silently added; use bounded validation subprocesses for untrusted inputs.
