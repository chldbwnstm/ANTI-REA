"use strict";
// Trusted compiler helper. Parse/transpile input; NEVER import or evaluate it.
const fs = require("node:fs");
const ts = require(process.argv[2]);
const request = JSON.parse(fs.readFileSync(0, "utf8"));

function compile(request) {
  const source = request.source;
  if (typeof source !== "string" || Buffer.byteLength(source) > 524288) throw Error("Source exceeds 512 KiB");
  if (!["javascript", "typescript"].includes(request.language)) throw Error("Unsupported language");
  const file = ts.createSourceFile(request.language === "typescript" ? "owned.ts" : "owned.js", source,
    ts.ScriptTarget.ES2022, true, request.language === "typescript" ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  function fail(node, text) {
    const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;
    throw Error(`line ${line}: ${text}`);
  }
  if (file.parseDiagnostics.length) throw Error(ts.flattenDiagnosticMessageText(file.parseDiagnostics[0].messageText, " "));
  let nodes = 0;
  function count(node) { if (++nodes > 20000) throw Error("Source exceeds 20000 AST nodes"); ts.forEachChild(node, count); }
  count(file);
  const reserved = new Set(["module", "exports", "require", "arguments", "eval", "undefined", "NaN", "Infinity",
    "yield", "await", "implements", "interface", "package", "private", "protected", "public", "static", "let"]);
  function identifier(node) {
    if (!ts.isIdentifier(node) || !/^[A-Za-z_$][A-Za-z0-9_$]{0,127}$/.test(node.text)
      || node.text.startsWith("_ar_") || reserved.has(node.text)) fail(node, "Unsupported/reserved identifier");
    return node.text;
  }
  function annotation(node) {
    if (!node) return;
    if (request.language !== "typescript" || ![ts.SyntaxKind.NumberKeyword, ts.SyntaxKind.BigIntKeyword,
      ts.SyntaxKind.BooleanKeyword, ts.SyntaxKind.VoidKeyword].includes(node.kind)) fail(node, "Only primitive TS annotations are supported");
  }
  function modifiers(node, allowExport) {
    if (node.modifiers && node.modifiers.some(m => !allowExport || m.kind !== ts.SyntaxKind.ExportKeyword))
      fail(node, "Only an optional export modifier is supported; no decorators/async/default/declare");
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
    if (ts.isIdentifier(node) && ["undefined", "NaN", "Infinity"].includes(node.text))
      return ({undefined, NaN, Infinity})[node.text];
    if (ts.isPrefixUnaryExpression(node) && [ts.SyntaxKind.PlusToken, ts.SyntaxKind.MinusToken].includes(node.operator)) {
      const value = literal(node.operand);
      return node.operator === ts.SyntaxKind.PlusToken ? +value : -value;
    }
    fail(node, "Module constants must be primitive literals, not executable expressions");
  }
  const functions = new Map(), constants = new Map();
  for (const node of file.statements) {
    if (ts.isExpressionStatement(node) && ts.isStringLiteral(node.expression) && node.expression.text === "use strict") continue;
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      modifiers(node, true);
      const name = identifier(node.name);
      if (functions.has(name) || constants.has(name)) fail(node, "Duplicate module name");
      if (node.asteriskToken || node.typeParameters?.length || node.parameters.length > 16) fail(node, "Generators/generics or >16 parameters unsupported");
      const parameters = node.parameters.map(p => {
        if (p.initializer || p.dotDotDotToken || p.questionToken || p.modifiers?.length) fail(p, "Defaults/rest/optional/decorated parameters unsupported");
        annotation(p.type); return identifier(p.name);
      });
      if (new Set(parameters).size !== parameters.length) fail(node, "Duplicate parameters");
      annotation(node.type);
      functions.set(name, {node, parameters});
    } else if (ts.isVariableStatement(node)) {
      modifiers(node, false);
      if (!(node.declarationList.flags & ts.NodeFlags.Const)) fail(node, "Only literal const declarations are allowed at module level");
      for (const declaration of node.declarationList.declarations) {
        const name = identifier(declaration.name); annotation(declaration.type);
        if (!declaration.initializer || functions.has(name) || constants.has(name)) fail(node, "Duplicate/missing module constant");
        constants.set(name, tag(literal(declaration.initializer)));
      }
    } else fail(node, `Unsupported module statement ${ts.SyntaxKind[node.kind]}; no imports/classes/module execution`);
  }
  if (functions.size > 128 || !Array.isArray(request.functions) || request.functions.length < 1 || request.functions.length > 64
      || new Set(request.functions).size !== request.functions.length || request.functions.some(n => !functions.has(n)))
    throw Error("Select 1..64 unique owned function names (at most 128 module functions)");
  const binary = new Set(["+", "-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "|", "^",
    "==", "!=", "===", "!==", "<", "<=", ">", ">="]);
  const primitiveBuiltins = new Set(["Number", "BigInt", "Boolean"]);
  const mathBuiltins = new Set(["abs", "min", "max", "floor", "ceil", "trunc", "round", "sign", "imul", "fround"]);
  const numberBuiltins = new Set(["isFinite", "isNaN", "isInteger", "isSafeInteger"]);

  class Compiler {
    constructor(info) {
      this.info = info; this.code = []; this.slots = []; this.scopes = [new Map()]; this.calls = new Set(); this.loops = [];
      for (const name of info.parameters) this.bind(name, "parameter", info.node);
    }
    emit(op, ...args) { this.code.push([op, ...args]); return this.code.length - 1; }
    patch(index, value, operand = 1) { this.code[index][operand] = value; }
    bind(name, kind, node) {
      const scope = this.scopes[this.scopes.length - 1];
      if (scope.has(name)) fail(node, `Duplicate lexical binding ${name}`);
      const slot = this.slots.length; this.slots.push(kind); scope.set(name, slot); return slot;
    }
    local(name) {
      for (let i = this.scopes.length - 1; i >= 0; --i) if (this.scopes[i].has(name)) return this.scopes[i].get(name);
      return null;
    }
    target(node) {
      const name = identifier(node), slot = this.local(name);
      if (slot === null) fail(node, "Mutation of globals/functions is unsupported");
      return slot;
    }
    prepareDeclarations(list, slots) {
      if (!(list.flags & (ts.NodeFlags.Let | ts.NodeFlags.Const))) fail(list, "var is unsupported; use lexical let/const");
      const kind = list.flags & ts.NodeFlags.Const ? "const" : "let";
      for (const declaration of list.declarations) {
        annotation(declaration.type);
        if (declaration.exclamationToken || (kind === "const" && !declaration.initializer)) fail(declaration, "Definite assignment assertion or uninitialized const unsupported");
        slots.push(this.bind(identifier(declaration.name), kind, declaration));
      }
    }
    block(node, root = false) {
      if (!root) this.scopes.push(new Map());
      const slots = [];
      for (const statement of node.statements) if (ts.isVariableStatement(statement)) {
        modifiers(statement, false); this.prepareDeclarations(statement.declarationList, slots);
      }
      if (slots.length) this.emit("reset", slots);
      for (const statement of node.statements) this.statement(statement);
      if (!root) this.scopes.pop();
    }
    declarations(list) {
      for (const declaration of list.declarations) {
        if (declaration.initializer) this.expr(declaration.initializer); else this.emit("const", ["undefined"]);
        this.emit("init", this.local(identifier(declaration.name)));
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
        else if (["undefined", "NaN", "Infinity"].includes(name) && !functions.has(name)) this.emit("const", tag(literal(node)));
        else fail(node, `Unknown scalar value ${name}`);
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
        if (!binary.has(op)) fail(node, `Unsupported binary operator ${op}`);
        this.expr(node.left); this.expr(node.right); this.emit("binary", op); return;
      }
      if (ts.isConditionalExpression(node)) {
        this.expr(node.condition); const branch = this.emit("false", null);
        this.expr(node.whenTrue); const end = this.emit("jump", null);
        this.patch(branch, this.code.length); this.expr(node.whenFalse); this.patch(end, this.code.length); return;
      }
      if (ts.isCallExpression(node)) {
        if (node.questionDotToken || node.typeArguments?.length || node.arguments.length > 16) fail(node, "Optional/generic/>16-argument calls unsupported");
        let name, builtin = false;
        if (ts.isIdentifier(node.expression)) {
          name = node.expression.text;
          if (this.local(name) !== null || constants.has(name)) fail(node, "Call target shadowed by local/constant");
          if (functions.has(name)) {
            if (node.arguments.length !== functions.get(name).parameters.length) fail(node, "Owned helper call arity mismatch");
            this.calls.add(name);
          } else if (primitiveBuiltins.has(name) && node.arguments.length === 1) builtin = true;
          else fail(node, `Unsupported call ${name}`);
        } else if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
          const base = node.expression.expression.text, property = node.expression.name.text;
          if (this.local(base) !== null || constants.has(base) || functions.has(base) || node.expression.questionDotToken) fail(node, "Builtin receiver is shadowed/optional");
          if (!(base === "Math" && mathBuiltins.has(property)) && !(base === "Number" && numberBuiltins.has(property))
            && !(base === "BigInt" && ["asIntN", "asUintN"].includes(property))) fail(node, "Unsupported property call");
          name = base + "." + property; builtin = true;
        } else fail(node, "Only owned helper or fixed primitive/Math calls supported");
        for (const argument of node.arguments) this.expr(argument);
        this.emit(builtin ? "builtin" : "call", name, node.arguments.length); return;
      }
      fail(node, `Unsupported expression ${ts.SyntaxKind[node.kind]}`);
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
      fail(node, `Unsupported statement ${ts.SyntaxKind[node.kind]}`);
    }
    compile() {
      this.block(this.info.node.body, true); this.emit("const", ["undefined"]); this.emit("return");
      return {parameters: this.info.parameters, slots: this.slots, code: this.code, helpers: [...this.calls].sort()};
    }
  }
  const compiled = new Map();
  for (const [name, info] of functions) compiled.set(name, new Compiler(info).compile());
  const active = new Set(), done = new Set();
  function visit(name) {
    if (active.has(name)) throw Error("Recursive helper cycles unsupported");
    if (done.has(name)) return;
    active.add(name); for (const child of compiled.get(name).helpers) visit(child); active.delete(name); done.add(name);
  }
  for (const name of functions.keys()) visit(name);
  const closure = new Set();
  function include(name) { if (!closure.has(name)) { closure.add(name); for (const child of compiled.get(name).helpers) include(child); } }
  request.functions.forEach(include);
  const selected = Object.fromEntries([...closure].sort().map(name => [name, compiled.get(name)]));
  let baseline = null;
  if (request.action === "build") {
    // Remove only explicit export modifiers through the AST, then reparse the
    // printed ordinary module for transpilation. This avoids emitted CommonJS
    // Object.defineProperty glue being shadowed by an owned function Object.
    // Function bodies remain original ASTs; this baseline is NOT VM protection.
    const baselineFile = ts.factory.updateSourceFile(file, file.statements.map(node =>
      ts.isFunctionDeclaration(node) ? ts.factory.updateFunctionDeclaration(node,
        node.modifiers?.filter(modifier => modifier.kind !== ts.SyntaxKind.ExportKeyword),
        node.asteriskToken, node.name, node.typeParameters, node.parameters, node.type, node.body) : node));
    const baselineSource = ts.createPrinter().printFile(baselineFile);
    const transpiled = ts.transpileModule(baselineSource, {fileName: file.fileName, reportDiagnostics: true,
      compilerOptions: {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, sourceMap: false,
        removeComments: false, alwaysStrict: true, isolatedModules: true}});
    const errors = (transpiled.diagnostics || []).filter(item => item.category === ts.DiagnosticCategory.Error);
    if (errors.length) throw Error(ts.flattenDiagnosticMessageText(errors[0].messageText, " "));
    baseline = transpiled.outputText + "\nmodule.exports = {" + request.functions.join(",") + "};\n";
  }
  return {schema_version: 1, compiler_version: ts.version, source_executed: false,
    type_checking: "not_performed_syntax_subset_only", functions: selected, exported_functions: request.functions,
    helper_closure: [...closure].sort(), baseline};
}

try { const result = compile(request); result.loaded_files = Object.keys(require.cache); process.stdout.write(JSON.stringify({status: "ok", result})); }
catch (error) { process.stdout.write(JSON.stringify({status: "rejected", error: String(error.message)})); process.exitCode = 2; }
