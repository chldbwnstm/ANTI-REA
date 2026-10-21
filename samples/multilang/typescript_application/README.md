# Owned TypeScript application fixture

The whole TS entry is compiled to CommonJS. Only `score` and its reachable
`blend` helper are virtualized; enum, namespace, JS sibling import and UI text
remain ordinary application code. `digitSum` is a preserved scalar caller of
the protected helper. The contract samples those scalar outputs, not UI text.

Plan/build do not run the application. The explicit TypeScript application
validation contract authorizes its startup in bounded separate Node processes.
The validator independently compiles the planned original and requires byte
equality with the unprotected build reference. Staging removes `app.ts` and
adds `app.cjs` in the same package; it never leaves an original-source fallback.
This is not general TS project resolution, type checking, an OS sandbox,
performance acceptance or reverse-engineering resistance evidence.
