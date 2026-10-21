# TypeScript source fixture

This fixture uses actual primitive TypeScript annotations and exported functions.
The installed TypeScript compiler creates the private ordinary JavaScript
baseline; a separate AST-to-custom-VM lowering protects the selected functions.
Type erasure alone is not counted as protection.

See [the shared subset, validation and deployment boundaries](../javascript/README.md).
`bigintScore` and `bigintErrors` exercise arbitrary-width BigInt behavior;
`booleanGate` has an exhaustive four-input Boolean domain. The contract uses
decimal strings for BigInt bounds so JSON does not truncate them to Number.
