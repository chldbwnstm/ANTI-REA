# Swift scalar source fixture

This is owned, non-security arithmetic source for the experimental Windows Swift
source route. Both exported roots and their real Swift helper implementations
must be inside the protected LLVM graph. A protected C wrapper around an
unprotected Swift implementation does not satisfy that requirement.

The fixture intentionally uses Swift wrapping operators (`&+`, `&-`, `&*`,
`&<<`, `&>>`). Compiler output containing checked-overflow/trap intrinsics,
runtime calls, object/pointer/aggregate operations or recursive helpers is
rejected before a protected artifact is claimed. This does not mean ordinary
checked Swift arithmetic was silently changed into wrapping arithmetic.

`project.json` selects four scalar C-ABI exports covering `UInt32`, `Int32`,
`UInt64` and `Int64`. Both ordinary public argument labels (`x:`) and explicit
external/internal labels (`_ x:`) are represented. `contract.json` records exact
signedness and widths; compiler-produced interface and LLVM ABI metadata must
agree. Separate explicit validation compares the original Swift-driver DLL with
the normalized baseline and protected DLL, including boundary inputs and two
behavior repetitions. Compilation itself does not run any target code.

The original source, interfaces, original/reference DLL, LLVM IR and cases are
private build evidence. This is not whole-Swift, macOS, GUI, runtime-object or
attack-resistance support. Toolchain availability and actual validation status
must be read from the run's report rather than inferred from this fixture.
