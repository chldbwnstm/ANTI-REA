"use strict";
// Trusted mixed-module compiler/transpiler helper. Parse/transpile the whole
// owned module; NEVER import or evaluate it. Only the selected top-level scalar
// functions and their reachable owned helper closure are lowered to VM IR; every
// other statement is reported as a byte span to preserve verbatim. TypeScript is
// transpiled whole-module via isolatedModules and then handled exactly like the
// resulting CommonJS JavaScript: type annotations are erased, while
// runtime-bearing constructs (enums, namespaces with runtime members, decorators,
// parameter properties) are emitted as ordinary runtime JavaScript. Unselected
// code is therefore preserved as that transpiled runtime form -- not dropped and
// not reinterpreted. Only TypeScript that isolatedModules cannot transpile is
// rejected; the selected scalar subset cannot itself use those constructs.
const fs = require("node:fs");
const ts = require(process.argv[2]);
const request = JSON.parse(fs.readFileSync(0, "utf8"));

function compile(request) {
  const original = request.source;
  if (typeof original !== "string" || Buffer.byteLength(original) > 524288) throw Error("Source exceeds 512 KiB");
  if (!["javascript", "typescript"].includes(request.language)) throw Error("Unsupported language");

  // A leading shebang is held out of the parser and re-attached by the caller so
  // directive/shebang semantics survive. It never participates in byte spans.
  let shebang = "", rest = original;
  if (rest.startsWith("#!")) {
    const nl = rest.indexOf("\n");
    shebang = nl === -1 ? rest : rest.slice(0, nl + 1);
    rest = nl === -1 ? "" : rest.slice(nl + 1);
  }

  let working = rest, transpiled = false;
  if (request.language === "typescript") {
    const out = ts.transpileModule(rest, {fileName: "owned.ts", reportDiagnostics: true,
      compilerOptions: {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, sourceMap: false,
        removeComments: false, alwaysStrict: false, isolatedModules: true, esModuleInterop: true}});
    const errors = (out.diagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
    if (errors.length) throw Error("TypeScript cannot be safely transpiled for mixed protection: "
      + ts.flattenDiagnosticMessageText(errors[0].messageText, " "));
    working = out.outputText;
    transpiled = true;
  }

  const file = ts.createSourceFile("owned.js", working, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  if (file.parseDiagnostics && file.parseDiagnostics.length)
    throw Error(ts.flattenDiagnosticMessageText(file.parseDiagnostics[0].messageText, " "));

  let nodes = 0;
  (function count(node) { if (++nodes > 20000) throw Error("Module exceeds 20000 AST nodes"); ts.forEachChild(node, count); })(file);

  function lineOf(node) { return file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1; }
  function fail(node, text) { throw Error("line " + lineOf(node) + ": " + text); }

  const reserved = new Set(["module", "exports", "require", "arguments", "eval", "undefined", "NaN", "Infinity",
    "yield", "await", "implements", "interface", "package", "private", "protected", "public", "static", "let"]);
  function identifierStrict(node) {
    if (!ts.isIdentifier(node) || !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(node.text)
      || node.text.startsWith("_ar_") || node.text.startsWith("_arm_") || reserved.has(node.text))
      fail(node, "Unsupported/reserved identifier");
    return node.text;
  }

  // Whole-module reservation: no identifier anywhere may collide with the
  // injected _ar_/_arm_ generated-runtime namespace, selected or not.
  (function scanReserved(node) {
    if (ts.isIdentifier(node) && (node.text.startsWith("_ar_") || node.text.startsWith("_arm_")))
      fail(node, "The _ar_/_arm_ generated-runtime identifier prefix is reserved");
    ts.forEachChild(node, scanReserved);
  })(file);

  // Register every top-level function declaration by name; do not validate or
  // reject unselected functions. Duplicates make a name ineligible for selection.
  const topFunctions = new Map(), dupNames = new Set();
  for (const node of file.statements) {
    if (ts.isFunctionDeclaration(node) && node.name && node.body && ts.isIdentifier(node.name)
        && /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(node.name.text)
        && !node.name.text.startsWith("_ar_") && !node.name.text.startsWith("_arm_") && !reserved.has(node.name.text)) {
      const name = node.name.text;
      if (topFunctions.has(name)) dupNames.add(name); else topFunctions.set(name, {node});
    }
  }

  function parseParams(node) {
    const names = []; let error = null;
    if (node.modifiers && node.modifiers.length) error = "A selected/helper function cannot carry modifiers (export/async/default/declare)";
    if (!error && (node.asteriskToken || (node.typeParameters && node.typeParameters.length) || node.parameters.length > 16))
      error = "Generators/generics or >16 parameters unsupported";
    for (const p of node.parameters) {
      if (p.initializer || p.dotDotDotToken || p.questionToken || (p.modifiers && p.modifiers.length)) {
        error = error || "Defaults/rest/optional/decorated parameters unsupported"; names.push(null); continue;
      }
      if (p.type) error = error || "Only primitive annotations are supported";
      if (ts.isIdentifier(p.name) && /^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(p.name.text)
          && !p.name.text.startsWith("_ar_") && !p.name.text.startsWith("_arm_") && !reserved.has(p.name.text)) {
        names.push(p.name.text);
      } else { error = error || "Unsupported/destructured parameter"; names.push(null); }
    }
    const real = names.filter(n => n !== null);
    if (!error && new Set(real).size !== real.length) error = "Duplicate parameters";
    return {names, error};
  }
  for (const [name, record] of topFunctions) { const p = parseParams(record.node); record.parameters = p.names; record.paramError = p.error; }

  const binary = new Set(["+", "-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "|", "^",
    "==", "!=", "===", "!==", "<", "<=", ">", ">="]);
  const primitiveBuiltins = new Set(["Number", "BigInt", "Boolean"]);
  const mathBuiltins = new Set(["abs", "min", "max", "floor", "ceil", "trunc", "round", "sign", "imul", "fround"]);
  const numberBuiltins = new Set(["isFinite", "isNaN", "isInteger", "isSafeInteger"]);

  // Compiler copied from tools/javascript_frontend/compile.cjs. The only mixed
  // change: the module-constant table is intentionally empty, so a selected body
  // that reads any module-global value (even an apparent literal const) is
  // rejected rather than having that value silently frozen into the VM program.
  const constants = new Map();

  // Names bound at module top level, in any binding form. A selected/helper body
  // that reads one of these is reading a module-global value and must be rejected
  // (the module-constant table is intentionally empty), even when the name
  // coincides with a runtime intrinsic (undefined/NaN/Infinity) or a captured
  // builtin receiver/callee (Math/Number/BigInt/Boolean): a module binding that
  // shadows the intrinsic/builtin must NOT be silently resolved to the global.
  const moduleBindings = new Set();
  function collectBindingName(name) {
    if (!name) return;
    if (ts.isIdentifier(name)) moduleBindings.add(name.text);
    else if (ts.isArrayBindingPattern(name) || ts.isObjectBindingPattern(name))
      for (const el of name.elements) if (!ts.isOmittedExpression(el)) collectBindingName(el.name);
  }
  for (const statement of file.statements) {
    if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)
        || ts.isEnumDeclaration(statement) || ts.isModuleDeclaration(statement))
        && statement.name && ts.isIdentifier(statement.name)) moduleBindings.add(statement.name.text);
    else if (ts.isVariableStatement(statement))
      for (const d of statement.declarationList.declarations) collectBindingName(d.name);
    else if (ts.isImportEqualsDeclaration(statement) && statement.name) moduleBindings.add(statement.name.text);
    else if (ts.isImportDeclaration(statement) && statement.importClause) {
      const clause = statement.importClause;
      if (clause.name) moduleBindings.add(clause.name.text);
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) moduleBindings.add(clause.namedBindings.name.text);
        else for (const spec of clause.namedBindings.elements) moduleBindings.add(spec.name.text);
      }
    }
  }
  // The file.statements pass above only sees immediate top-level statements. Two
  // more binding forms reach this module's top scope from inside nested blocks and
  // must be collected too, so a selected body's free name or the injected runtime
  // never resolves to the real global while the module actually shadows it:
  //   * `var` is function-scoped: a var declared in any nested block (if/for/try/
  //     switch/label/bare block), but NOT inside a nested function, is hoisted to
  //     this module's top scope.
  //   * A block-level function *declaration* can create an OUTER (module-scope)
  //     binding under sloppy-mode Annex B (B.3.3). Strictness is not tracked here,
  //     so its name is collected conservatively (over-collecting in a strict module
  //     only yields a conservative rejection, which is acceptable).
  // The walk stops at the boundary of any nested function's own scope: a function
  // expression / arrow / method / accessor / constructor introduces a new scope
  // whose inner declarations do not reach this module scope. A function
  // declaration contributes its own name to this scope but its body is a new
  // scope, so its name is taken without descending into it.
  (function hoistedScope(node) {
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)
        || ts.isConstructorDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) return;
    if (ts.isFunctionDeclaration(node)) {
      if (node.name && ts.isIdentifier(node.name)) collectBindingName(node.name);
      return;
    }
    if (ts.isVariableDeclarationList(node) && !(node.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const)))
      for (const declaration of node.declarations) collectBindingName(declaration.name);
    ts.forEachChild(node, hoistedScope);
  })(file);

  // Free global names the INJECTED runtime itself depends on at module scope
  // (runtime.mixed.cjs.in). If the module binds any of these at its top scope the
  // hoisted runtime factory would resolve the module's shadow instead of the real
  // global and break -- regardless of whether selected code uses the name. The
  // format-2 runtime is fixed, so conservatively reject rather than rewrite it.
  const runtimeFreeNames = new Set(["require", "Math", "Number", "BigInt", "Boolean", "JSON",
    "Symbol", "Array", "Object", "Error", "ReferenceError", "TypeError", "Set", "undefined"]);
  for (const name of moduleBindings)
    if (runtimeFreeNames.has(name))
      throw Error("Module-level binding '" + name + "' shadows a global the injected runtime depends on; "
        + "such shadowing is unsupported and rejected rather than silently breaking the VM");

  class Compiler {
    constructor(info) {
      this.info = info; this.code = []; this.slots = []; this.scopes = [new Map()]; this.calls = new Set(); this.loops = [];
      for (const name of info.parameters) this.bind(name, "parameter", info.node);
    }
    emit(op, ...args) { this.code.push([op, ...args]); return this.code.length - 1; }
    patch(index, value, operand = 1) { this.code[index][operand] = value; }
    bind(name, kind, node) {
      const scope = this.scopes[this.scopes.length - 1];
      if (scope.has(name)) fail(node, "Duplicate lexical binding " + name);
      const slot = this.slots.length; this.slots.push(kind); scope.set(name, slot); return slot;
    }
    local(name) {
      for (let i = this.scopes.length - 1; i >= 0; --i) if (this.scopes[i].has(name)) return this.scopes[i].get(name);
      return null;
    }
    target(node) {
      const name = identifierStrict(node), slot = this.local(name);
      if (slot === null) fail(node, "Mutation of globals/functions is unsupported");
      return slot;
    }
    prepareDeclarations(list, slots) {
      if (!(list.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const))) fail(list, "var is unsupported; use lexical let/const");
      const kind = list.flags & ts.NodeFlags.Const ? "const" : "let";
      for (const declaration of list.declarations) {
        if (declaration.type) fail(declaration, "Only primitive annotations are supported");
        if (declaration.exclamationToken || (kind === "const" && !declaration.initializer)) fail(declaration, "Definite assignment assertion or uninitialized const unsupported");
        slots.push(this.bind(identifierStrict(declaration.name), kind, declaration));
      }
    }
    block(node, root = false) {
      if (!root) this.scopes.push(new Map());
      const slots = [];
      for (const statement of node.statements) if (ts.isVariableStatement(statement)) {
        if (statement.modifiers && statement.modifiers.length) fail(statement, "Unsupported modifiers on a local declaration");
        this.prepareDeclarations(statement.declarationList, slots);
      }
      if (slots.length) this.emit("reset", slots);
      for (const statement of node.statements) this.statement(statement);
      if (!root) this.scopes.pop();
    }
    declarations(list) {
      for (const declaration of list.declarations) {
        if (declaration.initializer) this.expr(declaration.initializer); else this.emit("const", ["undefined"]);
        this.emit("init", this.local(identifierStrict(declaration.name)));
      }
    }
    expr(node) {
      if (ts.isParenthesizedExpression(node)) return this.expr(node.expression);
      if (ts.isNumericLiteral(node) || ts.isBigIntLiteral(node) || [ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword, ts.SyntaxKind.NullKeyword].includes(node.kind)) {
        this.emit("const", tag(literal(node))); return;
      }
      if (ts.isIdentifier(node)) {
        const name = node.text, slot = this.local(name);
        if (slot !== null) this.emit("load", slot);
        else if (constants.has(name)) this.emit("const", constants.get(name));
        else if (["undefined", "NaN", "Infinity"].includes(name) && !topFunctions.has(name) && !moduleBindings.has(name)) this.emit("const", tag(literal(node)));
        else fail(node, "Unknown scalar value " + name);
        return;
      }
      if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
        const op = ts.tokenToString(node.operator);
        if (["++", "--"].includes(op)) this.emit("update", this.target(node.operand), op, ts.isPrefixUnaryExpression(node));
        else if (["+", "-", "!", "~"].includes(op)) { this.expr(node.operand); this.emit("unary", op); }
        else fail(node, "Unsupported unary operator");
        return;
      }
      if (ts.isBinaryExpression(node)) {
        const op = ts.tokenToString(node.operatorToken.kind);
        if (["&&", "||", "??"].includes(op)) {
          this.expr(node.left); this.emit("dup");
          const branch = this.emit(op === "&&" ? "false" : op === "||" ? "true" : "nonnull", null);
          this.emit("pop"); this.expr(node.right); this.patch(branch, this.code.length); return;
        }
        if (["=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^="].includes(op)) {
          const slot = this.target(node.left);
          if (op !== "=") this.emit("load", slot);
          this.expr(node.right);
          if (op !== "=") this.emit("binary", op.slice(0, -1));
          this.emit("set", slot); return;
        }
        if (!binary.has(op)) fail(node, "Unsupported binary operator " + op);
        this.expr(node.left); this.expr(node.right); this.emit("binary", op); return;
      }
      if (ts.isConditionalExpression(node)) {
        this.expr(node.condition); const branch = this.emit("false", null);
        this.expr(node.whenTrue); const end = this.emit("jump", null);
        this.patch(branch, this.code.length); this.expr(node.whenFalse); this.patch(end, this.code.length); return;
      }
      if (ts.isCallExpression(node)) {
        if (node.questionDotToken || (node.typeArguments && node.typeArguments.length) || node.arguments.length > 16) fail(node, "Optional/generic/>16-argument calls unsupported");
        let name, builtin = false;
        if (ts.isIdentifier(node.expression)) {
          name = node.expression.text;
          if (this.local(name) !== null || constants.has(name)) fail(node, "Call target shadowed by local/constant");
          if (topFunctions.has(name)) {
            if (node.arguments.length !== topFunctions.get(name).parameters.length) fail(node, "Owned helper call arity mismatch");
            this.calls.add(name);
          } else if (primitiveBuiltins.has(name) && node.arguments.length === 1 && !moduleBindings.has(name)) builtin = true;
          else fail(node, "Unsupported call " + name + " (not an owned scalar helper or supported builtin)");
        } else if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
          const base = node.expression.expression.text, property = node.expression.name.text;
          if (this.local(base) !== null || constants.has(base) || topFunctions.has(base) || moduleBindings.has(base) || node.expression.questionDotToken) fail(node, "Builtin receiver is shadowed/optional");
          if (!(base === "Math" && mathBuiltins.has(property)) && !(base === "Number" && numberBuiltins.has(property))
            && !(base === "BigInt" && ["asIntN", "asUintN"].includes(property))) fail(node, "Unsupported property call");
          name = base + "." + property; builtin = true;
        } else fail(node, "Only owned helper or fixed primitive/Math calls supported");
        for (const argument of node.arguments) this.expr(argument);
        this.emit(builtin ? "builtin" : "call", name, node.arguments.length); return;
      }
      fail(node, "Unsupported expression " + ts.SyntaxKind[node.kind]);
    }
    statement(node) {
      if (ts.isBlock(node)) return this.block(node);
      if (ts.isVariableStatement(node)) {
        if (!ts.isBlock(node.parent) || node.declarationList.declarations.some(d => !ts.isIdentifier(d.name) || !this.scopes[this.scopes.length - 1].has(d.name.text)))
          fail(node, "Lexical declarations require a containing block");
        this.declarations(node.declarationList); return;
      }
      if (ts.isReturnStatement(node)) {
        if (node.expression) this.expr(node.expression); else this.emit("const", ["undefined"]);
        this.emit("return"); return;
      }
      if (ts.isExpressionStatement(node)) {
        if (ts.isStringLiteral(node.expression) && node.expression.text === "use strict") return;
        this.expr(node.expression); this.emit("pop"); return;
      }
      if (ts.isIfStatement(node)) {
        this.expr(node.expression); const branch = this.emit("false", null);
        this.statement(node.thenStatement); const end = this.emit("jump", null);
        this.patch(branch, this.code.length); if (node.elseStatement) this.statement(node.elseStatement);
        this.patch(end, this.code.length); return;
      }
      if (ts.isForStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) {
        this.scopes.push(new Map());
        if (ts.isForStatement(node) && node.initializer) {
          if (ts.isVariableDeclarationList(node.initializer)) {
            const slots = []; this.prepareDeclarations(node.initializer, slots); this.emit("reset", slots); this.declarations(node.initializer);
          } else { this.expr(node.initializer); this.emit("pop"); }
        }
        const start = this.code.length;
        let exit = null;
        if (!ts.isDoStatement(node)) {
          const condition = ts.isForStatement(node) ? node.condition : node.expression;
          if (condition) { this.expr(condition); exit = this.emit("false", null); }
        }
        const loop = {breaks: [], continues: []}; this.loops.push(loop);
        this.statement(node.statement); this.loops.pop();
        const continuation = this.code.length;
        for (const index of loop.continues) this.patch(index, continuation);
        if (ts.isForStatement(node) && node.incrementor) { this.expr(node.incrementor); this.emit("pop"); }
        if (ts.isDoStatement(node)) { this.expr(node.expression); this.emit("true", start); }
        else this.emit("jump", start);
        if (exit !== null) this.patch(exit, this.code.length);
        for (const index of loop.breaks) this.patch(index, this.code.length);
        this.scopes.pop(); return;
      }
      if (ts.isBreakStatement(node) || ts.isContinueStatement(node)) {
        if (node.label || !this.loops.length) fail(node, "Labels or break/continue outside loop unsupported");
        this.loops[this.loops.length - 1][ts.isBreakStatement(node) ? "breaks" : "continues"].push(this.emit("jump", null)); return;
      }
      if (ts.isEmptyStatement(node)) return;
      fail(node, "Unsupported statement " + ts.SyntaxKind[node.kind]);
    }
    compile() {
      this.block(this.info.node.body, true); this.emit("const", ["undefined"]); this.emit("return");
      return {parameters: this.info.parameters, slots: this.slots, code: this.code, helpers: [...this.calls].sort()};
    }
  }
  function tag(value) {
    if (typeof value === "bigint") return ["bigint", value.toString()];
    if (typeof value === "number") { const b = Buffer.alloc(8); b.writeDoubleBE(value); return ["number", b.toString("hex")]; }
    if (typeof value === "boolean") return ["boolean", value];
    if (value === null) return ["null"];
    if (value === undefined) return ["undefined"];
    throw Error("Unsupported constant");
  }
  function literal(node) {
    if (ts.isParenthesizedExpression(node)) return literal(node.expression);
    if (ts.isNumericLiteral(node)) return Number(node.text.replaceAll("_", ""));
    if (ts.isBigIntLiteral(node)) return BigInt(node.text.replaceAll("_", "").slice(0, -1));
    if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (node.kind === ts.SyntaxKind.NullKeyword) return null;
    if (ts.isIdentifier(node) && ["undefined", "NaN", "Infinity"].includes(node.text)) return ({undefined, NaN, Infinity})[node.text];
    if (ts.isPrefixUnaryExpression(node) && [ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken].includes(node.operator)) {
      const value = literal(node.operand);
      return node.operator === ts.SyntaxKind.PlusToken ? +value : -value;
    }
    fail(node, "Scalar literal required");
  }

  const selected = request.functions;
  if (topFunctions.size > 128 || !Array.isArray(selected) || selected.length < 1 || selected.length > 64
      || new Set(selected).size !== selected.length)
    throw Error("Select 1..64 unique owned function names (at most 128 module functions)");
  for (const name of selected) {
    if (typeof name !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(name)) throw Error("Invalid selected function name");
    if (!topFunctions.has(name)) throw Error("Selected top-level function not found: " + name);
  }

  const compiled = new Map(), active = new Set();
  function include(name) {
    if (active.has(name)) throw Error("Recursive helper cycles unsupported");
    if (compiled.has(name)) return;
    const info = topFunctions.get(name);
    if (!info) fail(file, "Selected/helper is not an owned top-level function: " + name);
    if (dupNames.has(name)) fail(info.node, "Protected function must have exactly one top-level definition: " + name);
    if (info.paramError) fail(info.node, info.paramError);
    active.add(name);
    let result;
    try { result = new Compiler(info).compile(); }
    catch (exc) { throw Error(String(exc.message) + "; mixed selected code cannot freeze module-global values or reach unselected code"); }
    for (const child of result.helpers) include(child);
    active.delete(name);
    compiled.set(name, result);
  }
  for (const name of selected) include(name);
  const closure = [...compiled.keys()].sort();
  if (closure.length > 128) throw Error("At most 128 protected functions are supported");

  // Reject any binding/write occurrence of a protected name other than its one
  // top-level function declaration, anywhere in the module (conservative: a reuse
  // as a local or nested declaration in unselected code is rejected too). This
  // forbids rebinding/redeclaration/import/deletion that would make the selected
  // name ambiguous instead of silently freezing one interpretation.
  const closureSet = new Set(closure);
  const ownDecl = new Map(closure.map(name => [name, topFunctions.get(name).node.name]));
  function flag(id) {
    if (!ts.isIdentifier(id) || !closureSet.has(id.text)) return;
    if (ownDecl.get(id.text) === id) return;
    fail(id, "Protected function name '" + id.text + "' cannot be rebound/redeclared/imported/deleted/shadowed");
  }
  function writeTarget(id) {
    // CommonJS supplies require as a writable MODULE-WRAPPER parameter, so a
    // bare assignment has no declaration for moduleBindings to collect. The
    // lazy VM factory closes over this binding. Reject writes conservatively
    // even in nested scopes (including harmless writes to a local shadow),
    // rather than letting ordinary startup replace the VM's builtin loader.
    if (ts.isIdentifier(id) && id.text === "require")
      fail(id, "CommonJS require binding cannot be assigned in a mixed module");
    flag(id);
  }
  function bindingTargets(expr) {
    if (!expr) return;
    if (ts.isParenthesizedExpression(expr)) return bindingTargets(expr.expression);
    if (ts.isIdentifier(expr)) { writeTarget(expr); return; }
    if (ts.isArrayLiteralExpression(expr)) { for (const el of expr.elements) { if (ts.isSpreadElement(el)) bindingTargets(el.expression); else if (!ts.isOmittedExpression(el)) bindingTargets(el); } return; }
    if (ts.isObjectLiteralExpression(expr)) { for (const p of expr.properties) {
      if (ts.isShorthandPropertyAssignment(p)) writeTarget(p.name);
      else if (ts.isPropertyAssignment(p)) bindingTargets(p.initializer);
      else if (ts.isSpreadAssignment(p)) bindingTargets(p.expression);
    } return; }
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) return bindingTargets(expr.left);
    // PropertyAccess/ElementAccess assign a property, not the identifier binding.
  }
  function bindingName(name) {
    if (!name) return;
    if (ts.isIdentifier(name)) { flag(name); return; }
    if (ts.isArrayBindingPattern(name) || ts.isObjectBindingPattern(name))
      for (const el of name.elements) if (!ts.isOmittedExpression(el)) bindingName(el.name);
  }
  (function scanBindings(node) {
    if (ts.isFunctionDeclaration(node) && node.name) {
      if (!(closureSet.has(node.name.text) && ownDecl.get(node.name.text) === node.name)) flag(node.name);
    } else if (ts.isFunctionExpression(node) && node.name) flag(node.name);
    else if ((ts.isClassDeclaration(node) || ts.isClassExpression(node)) && node.name) flag(node.name);
    else if ((ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) && node.name && ts.isIdentifier(node.name)) flag(node.name);
    else if (ts.isVariableDeclaration(node)) bindingName(node.name);
    else if (ts.isParameter(node)) bindingName(node.name);
    else if (ts.isBindingElement(node)) { /* handled via bindingName recursion */ }
    else if (ts.isImportClause(node) && node.name) flag(node.name);
    else if (ts.isNamespaceImport(node)) flag(node.name);
    else if (ts.isImportSpecifier(node)) flag(node.name);
    else if (ts.isCatchClause(node) && node.variableDeclaration) bindingName(node.variableDeclaration.name);
    else if (ts.isBinaryExpression(node) && [ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken, ts.SyntaxKind.MinusEqualsToken,
        ts.SyntaxKind.AsteriskEqualsToken, ts.SyntaxKind.SlashEqualsToken, ts.SyntaxKind.PercentEqualsToken, ts.SyntaxKind.AsteriskAsteriskEqualsToken,
        ts.SyntaxKind.LessThanLessThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanEqualsToken, ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken,
        ts.SyntaxKind.AmpersandEqualsToken, ts.SyntaxKind.BarEqualsToken, ts.SyntaxKind.CaretEqualsToken,
        ts.SyntaxKind.AmpersandAmpersandEqualsToken, ts.SyntaxKind.BarBarEqualsToken, ts.SyntaxKind.QuestionQuestionEqualsToken].includes(node.operatorToken.kind)) {
      bindingTargets(node.left);
    }
    else if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
        && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(node.operator)) bindingTargets(node.operand);
    else if (ts.isDeleteExpression(node) && ts.isIdentifier(node.expression)) flag(node.expression);
    // `for (x of ...)` / `for (x in ...)` with a non-declaration head assigns to an
    // existing binding; its target (identifier or array/object destructuring
    // pattern) is a rebinding occurrence just like `x = ...`. A declaration head
    // (`for (const x of ...)`) is a fresh binding handled by the VariableDeclaration
    // branch during descent, so only non-declaration heads are inspected here.
    else if ((ts.isForInStatement(node) || ts.isForOfStatement(node)) && !ts.isVariableDeclarationList(node.initializer)) bindingTargets(node.initializer);
    // Dynamic binding contexts a static scan cannot verify: a `with` block or a
    // direct `eval(...)` could rebind a protected/module name invisibly. Rather
    // than risk a silent semantic change, the whole module is conservatively
    // rejected (ordinary lexical shadowing is already rejected above).
    else if (ts.isWithStatement(node)) fail(node, "with statements introduce a dynamic scope that can rebind protected/module names and are unsupported");
    else if (ts.isCallExpression(node)) {
      // Direct eval -- including a parenthesized callee like `(eval)(...)`, which
      // is still direct eval and can rebind a module-scoped name -- is rejected.
      // Parentheses are stripped; a comma/other expression (e.g. indirect
      // `(0, eval)(...)`, which runs in global scope and cannot reach module
      // bindings) is deliberately NOT matched here.
      let callee = node.expression;
      while (ts.isParenthesizedExpression(callee)) callee = callee.expression;
      if (ts.isIdentifier(callee) && callee.text === "eval")
        fail(node, "Direct eval (including a parenthesized callee) can dynamically rebind protected/module names and is unsupported");
    }
    ts.forEachChild(node, scanBindings);
  })(file);

  // Byte spans (UTF-8) of each closure member's declaration in `working`, plus
  // the directive-prologue end so the runtime injects after it.
  const encoder = new TextEncoder();
  function byteOffset(pos) { return encoder.encode(working.slice(0, pos)).length; }
  const spans = closure.map(name => {
    const node = topFunctions.get(name).node;
    return {name, byte_start: byteOffset(node.getStart(file)), byte_end: byteOffset(node.getEnd()),
            parameters: topFunctions.get(name).parameters};
  });
  let prologueEnd = 0;
  for (const node of file.statements) {
    if (ts.isExpressionStatement(node) && ts.isStringLiteral(node.expression)) prologueEnd = byteOffset(node.getEnd());
    else break;
  }

  const functions = {};
  for (const name of closure) functions[name] = compiled.get(name);
  const unprotected = [...topFunctions.keys()].filter(name => !closureSet.has(name)).sort();

  return {schema_version: 1, compiler_version: ts.version, language: request.language, source_executed: false,
    type_checking: "not_performed_syntax_subset_only", transpiled, shebang, working_source: working,
    working_source_bytes: encoder.encode(working).length, prologue_end: prologueEnd,
    functions, exported_functions: selected, helper_closure: closure,
    unprotected_top_level_functions: unprotected, spans};
}

try { const result = compile(request); result.loaded_files = Object.keys(require.cache); process.stdout.write(JSON.stringify({status: "ok", result})); }
catch (error) { process.stdout.write(JSON.stringify({status: "rejected", error: String(error.message)})); process.exitCode = 2; }
