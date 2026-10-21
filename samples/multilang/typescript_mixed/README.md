# Owned mixed TypeScript fixture

`project.json` opts into experimental selected-body replacement. `score` and its
`blend` helper are virtualized after whole-module CommonJS transpilation.
`LABEL`, `describe` and the module export machinery remain unprotected.

TypeScript transpilation is not full type-checking or generic application
support. Plan/build never execute the application, and public mixed validation
is not yet integrated. See [supported scope](../../../docs/javascript-mixed-modules.md).
