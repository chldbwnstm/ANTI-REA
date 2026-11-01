"use strict";
// Independent pinned TypeScript transpile-reference helper.
//
// This child performs ONE job: whole-module CommonJS transpilation of an owned
// TypeScript source string, byte-identically to the mixed compiler's TS path in
// tools/javascript_frontend/compile_mixed.cjs, so the parent
// (antirea.typescript_reference) can cross-check the mixed build's baseline
// without reusing the mixed compiler's own VM-lowering code. It is deliberately
// minimal and performs NO import rewriting, NO module evaluation/require of the
// source, NO type checking, and emits NO generated VM runtime. It is a type
// erasure + runtime-construct (enum/namespace/import) emission ONLY, exactly
// what `ts.transpileModule` produces under the pinned compiler options below.
//
// Protocol: argv[2] is the absolute path of the pinned TypeScript compiler
// bundle; the request is a JSON object {source, language} read from stdin. The
// source is the parent-normalized (UTF-8 BOM already stripped once) owned module
// text; the child never reads the source file, never touches the filesystem, and
// requires nothing but the pinned bundle and Node builtins. The child writes the
// reference bytes and strict metadata to stdout as base64 + lengths; the parent
// computes every hash itself, bounds the sizes, and writes the reference file.
const fs = require("node:fs");

const MAX_SOURCE_BYTES = 512 * 1024;   // mirrors compile_mixed.cjs 512 KiB cap

function build(ts, request) {
  if (request === null || typeof request !== "object" || Array.isArray(request))
    throw Error("reference request must be a JSON object");
  const original = request.source;
  if (typeof original !== "string") throw Error("reference request source must be a string");
  if (Buffer.byteLength(original, "utf8") > MAX_SOURCE_BYTES) throw Error("Source exceeds 512 KiB");
  if (request.language !== "typescript") throw Error("TypeScript reference supports language=typescript only");

  // A leading shebang is held out of the transpiler and re-attached to the
  // emitted output, byte-for-byte as tools/javascript_frontend/compile_mixed.cjs
  // does, so directive/shebang semantics survive. It never reaches transpileModule.
  let shebang = "", rest = original;
  if (rest.startsWith("#!")) {
    const nl = rest.indexOf("\n");
    shebang = nl === -1 ? rest : rest.slice(0, nl + 1);
    rest = nl === -1 ? "" : rest.slice(nl + 1);
  }

  // The exact pinned mixed compile options (compile_mixed.cjs TS path). Reusing
  // these verbatim is what makes the emitted output byte-identical to the mixed
  // builder's baseline working source.
  const out = ts.transpileModule(rest, {fileName: "owned.ts", reportDiagnostics: true,
    compilerOptions: {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, sourceMap: false,
      removeComments: false, alwaysStrict: false, isolatedModules: true, esModuleInterop: true}});
  const errors = (out.diagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
  if (errors.length) throw Error("TypeScript cannot be safely transpiled for mixed protection: "
    + ts.flattenDiagnosticMessageText(errors[0].messageText, " "));

  const working = out.outputText;
  const reference = shebang + working;
  const workingBuf = Buffer.from(working, "utf8");
  const referenceBuf = Buffer.from(reference, "utf8");
  const shebangBuf = Buffer.from(shebang, "utf8");
  return {status: "ok", compiler_version: ts.version, language: "typescript", transpiled: true,
    source_executed: false, type_checking: "not_performed_whole_module_transpile_only",
    shebang_present: shebang.length > 0, shebang_bytes: shebangBuf.length,
    shebang_b64: shebangBuf.toString("base64"),
    working_b64: workingBuf.toString("base64"), working_bytes: workingBuf.length,
    reference_b64: referenceBuf.toString("base64"), reference_bytes: referenceBuf.length};
}

try {
  const ts = require(process.argv[2]);
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  process.stdout.write(JSON.stringify(build(ts, request)));
} catch (error) {
  process.stdout.write(JSON.stringify({status: "rejected", error: String(error && error.message || error)}));
  process.exitCode = 2;
}
