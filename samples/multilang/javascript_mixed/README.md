# Owned mixed CommonJS fixture

`project.json` opts into experimental selected-body replacement. `checksum` and
its `mix` / `rotate` helper closure are virtualized; ordinary imports, UI functions
and exports remain unprotected. `digitSum` calls a protected helper, and module
startup calls `checksum` before its textual definition through `preview`.

Plan/build never execute this module. Public mixed validation is not yet
integrated. Preserve `labels.js` and the original module location when explicitly
testing deployment. Do not distribute baseline/source/private build reports as
protected artifacts. See [supported scope](../../../docs/javascript-mixed-modules.md).
