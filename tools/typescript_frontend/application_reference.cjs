"use strict";
// Independent pinned TypeScript/JavaScript application transpile-reference helper
// (phase24 script application integration, JAVASCRIPT lane).
//
// This trusted child performs ONE job for the JavaScript adapter
// (antirea.script_javascript_application): whole-module CommonJS transpilation of
// one or more OWNED ordinary application source strings (the surrounding app
// entrypoint and its unselected sibling modules, and -- for the pure producer
// route -- the exported original core). It uses the SAME pinned compiler options
// for every file and for both runtime arms, so a given source transpiles to
// identical bytes wherever it is placed.
//
// It is deliberately minimal and performs NO import rewriting, NO module
// evaluation/require of the owned source, NO type checking, NO VM lowering and
// NO original-source fallback. It is a type-erasure + runtime-construct
// (enum/namespace/import) emission ONLY -- exactly what `ts.transpileModule`
// produces under the pinned options below. It additionally parses each source
// with the pinned compiler's AST (never a regex) to report, per file:
//   * the string-literal module specifiers of every `import`/`export ... from`/
//     `import x = require(...)`/`require(...)`/dynamic `import(...)` so the parent
//     can reject explicit `.ts`/`.tsx`/`.mts`/`.cts`/`.d.ts`/`.mjs` RUNTIME
//     specifiers instead of leaking an un-runnable original source into a bundle;
//   * the top-level exported binding names so the parent can require that every
//     selected pure root is actually exported (fail closed on a missing export).
//
// Protocol: argv[2] is the absolute path of the pinned TypeScript compiler
// bundle. The request is a JSON object read from stdin:
//
//   {"language": "typescript"|"javascript",
//    "files": [{"key": "<relative/path>", "source": "<module text>"}, ...]}
//
// Each `source` is the parent-normalized (UTF-8 BOM already stripped once) owned
// module text; this child never reads the filesystem (except the pinned bundle),
// never evaluates the source, and requires nothing but the pinned bundle and Node
// builtins. It writes the transpiled bytes (base64) and strict per-file metadata
// to stdout; the PARENT computes every hash itself, bounds the sizes, and writes
// the runtime files. A transpile diagnostic error fails the whole request (fail
// closed), never a partial/degraded emit.

const MAX_FILES = 128;                  // mirrors the engine application_files bound
const MAX_SOURCE_BYTES = 512 * 1024;    // mirrors compile_mixed.cjs 512 KiB per-source cap
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_OUTPUT_BYTES = 32 * 1024 * 1024;

// The single pinned, standard option set. `module: CommonJS` targets ordinary
// CommonJS Node; `isolatedModules` keeps every file a self-contained single-file
// transpile (no cross-file type resolution); `esModuleInterop` makes ordinary
// `import { x } from "./dep.js"` / default imports resolve against a plain
// `module.exports` object (the producer's protected/baseline core export shape).
function pinnedOptions(ts) {
  return {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, sourceMap: false,
    inlineSourceMap: false, removeComments: false, alwaysStrict: false,
    isolatedModules: true, esModuleInterop: true};
}

// A leading shebang is held out of the transpiler and re-attached to the emitted
// output byte-for-byte (as tools/javascript_frontend/compile_mixed.cjs does), so
// a `#!` directive survives without ever reaching transpileModule.
function splitShebang(text) {
  if (!text.startsWith("#!")) return {shebang: "", rest: text};
  const nl = text.indexOf("\n");
  if (nl === -1) return {shebang: text, rest: ""};
  return {shebang: text.slice(0, nl + 1), rest: text.slice(nl + 1)};
}

function nodeModifiers(ts, node) {
  if (typeof ts.canHaveModifiers === "function" && typeof ts.getModifiers === "function") {
    return (ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined) || [];
  }
  return node.modifiers || [];
}

function hasModifier(ts, node, kind) {
  return nodeModifiers(ts, node).some(m => m.kind === kind);
}

// Collect every string-literal module specifier reachable in the source AST.
function collectSpecifiers(ts, sourceFile) {
  const specs = [];
  const add = expr => {
    if (expr && ts.isStringLiteralLike(expr)) specs.push(expr.text);
  };
  const visit = node => {
    if (ts.isImportDeclaration(node)) {
      add(node.moduleSpecifier);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      add(node.moduleSpecifier);
    } else if (ts.isImportEqualsDeclaration(node)
               && ts.isExternalModuleReference(node.moduleReference)) {
      add(node.moduleReference.expression);
    } else if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const isRequire = ts.isIdentifier(callee) && callee.text === "require";
      const isDynamicImport = callee.kind === ts.SyntaxKind.ImportKeyword;
      if ((isRequire || isDynamicImport) && node.arguments.length >= 1) {
        add(node.arguments[0]);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return specs;
}

// Collect top-level exported binding names (fail-closed export evidence).
function collectExportedNames(ts, sourceFile) {
  const names = new Set();
  for (const node of sourceFile.statements) {
    const exported = hasModifier(ts, node, ts.SyntaxKind.ExportKeyword);
    const isDefault = hasModifier(ts, node, ts.SyntaxKind.DefaultKeyword);
    if (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)
        || ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node)
        || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) {
      if (exported && isDefault) names.add("default");
      else if (exported && node.name && ts.isIdentifier(node.name)) names.add(node.name.text);
    } else if (ts.isVariableStatement(node) && exported) {
      for (const decl of node.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) names.add(decl.name.text);
      }
    } else if (ts.isExportDeclaration(node) && node.exportClause) {
      if (ts.isNamedExports(node.exportClause)) {
        for (const element of node.exportClause.elements) names.add(element.name.text);
      } else if (ts.isNamespaceExport(node.exportClause)) {
        names.add(node.exportClause.name.text);
      }
    } else if (ts.isExportAssignment(node)) {
      names.add(node.isExportEquals ? "export=" : "default");
    }
  }
  return [...names];
}

function transpileOne(ts, options, language, key, source) {
  if (typeof key !== "string" || !key) throw Error("each file needs a string key");
  if (typeof source !== "string") throw Error("file " + key + " source must be a string");
  if (Buffer.byteLength(source, "utf8") > MAX_SOURCE_BYTES) throw Error("file " + key + " exceeds 512 KiB");
  const fileName = language === "javascript" ? "owned.js" : "owned.ts";
  const scriptKind = language === "javascript" ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const {shebang, rest} = splitShebang(source);

  const sourceFile = ts.createSourceFile(fileName, rest, ts.ScriptTarget.ES2022, true, scriptKind);
  const specifiers = collectSpecifiers(ts, sourceFile);
  const exportedNames = collectExportedNames(ts, sourceFile);

  const out = ts.transpileModule(rest, {fileName: fileName, reportDiagnostics: true,
    compilerOptions: Object.assign({allowJs: language === "javascript"}, options)});
  const errors = (out.diagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
  if (errors.length) {
    throw Error("file " + key + " cannot be safely transpiled to CommonJS: "
      + ts.flattenDiagnosticMessageText(errors[0].messageText, " "));
  }
  const working = out.outputText;
  const output = shebang + working;
  const shebangBuf = Buffer.from(shebang, "utf8");
  const workingBuf = Buffer.from(working, "utf8");
  const outputBuf = Buffer.from(output, "utf8");
  if (outputBuf.length > MAX_OUTPUT_BYTES) throw Error("file " + key + " transpiled output exceeds the size bound");
  return {key: key, shebang_present: shebang.length > 0, shebang_bytes: shebangBuf.length,
    shebang_b64: shebangBuf.toString("base64"),
    working_bytes: workingBuf.length, working_b64: workingBuf.toString("base64"),
    output_bytes: outputBuf.length, output_b64: outputBuf.toString("base64"),
    require_specifiers: specifiers, exported_names: exportedNames};
}

function build(ts, request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw Error("reference request must be a JSON object");
  }
  const language = request.language;
  if (language !== "typescript" && language !== "javascript") {
    throw Error("application reference supports language typescript or javascript only");
  }
  const files = request.files;
  if (!Array.isArray(files) || files.length < 1 || files.length > MAX_FILES) {
    throw Error("request.files must list 1.." + MAX_FILES + " owned source files");
  }
  const options = pinnedOptions(ts);
  const results = [];
  const seen = new Set();
  let total = 0;
  for (const file of files) {
    if (file === null || typeof file !== "object") throw Error("each file entry must be an object");
    if (seen.has(file.key)) throw Error("duplicate file key: " + file.key);
    seen.add(file.key);
    const row = transpileOne(ts, options, language, file.key, file.source);
    total += row.output_bytes;
    if (total > MAX_TOTAL_OUTPUT_BYTES) throw Error("total transpiled output exceeds the bound");
    results.push(row);
  }
  // Report the literal options as evidence (enum values resolved to their names).
  const optionEvidence = {target: "ES2022", module: "CommonJS", sourceMap: false,
    inlineSourceMap: false, removeComments: false, alwaysStrict: false,
    isolatedModules: true, esModuleInterop: true, allowJs: language === "javascript"};
  return {status: "ok", compiler_version: ts.version, language: language,
    source_executed: false, type_checking: "not_performed_whole_module_transpile_only",
    pinned_compiler_options: optionEvidence, results: results};
}

try {
  const ts = require(process.argv[2]);
  const request = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
  const reply = build(ts, request);
  reply.loaded_files = Object.keys(require.cache);
  process.stdout.write(JSON.stringify(reply));
} catch (error) {
  process.stdout.write(JSON.stringify({status: "rejected",
    error: String(error && error.message || error).slice(0, 4096)}));
  process.exitCode = 2;
}
