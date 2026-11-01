// Trusted metadata helper. Parses/typechecks source; never executes target code.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"
)

type node map[string]interface{}
type encoder struct {
	info *types.Info
	ids map[types.Object]string
	locals []node
	calls map[string]bool
	count int
}

func fail(format string, args ...interface{}) { panic(fmt.Sprintf(format, args...)) }
func typeName(t types.Type, untyped bool) string {
	b, ok := t.(*types.Basic)
	if !ok { fail("unsupported type %v", t) }
	switch b.Kind() {
	case types.Int32: return "int32"
	case types.Uint32: return "uint32"
	case types.Int64: return "int64"
	case types.Uint64: return "uint64"
	case types.Bool: return "bool"
	case types.UntypedBool: return "bool"
	case types.UntypedInt, types.UntypedRune:
		if untyped { return b.Name() }
	}
	fail("unsupported type %v: use explicit fixed-width integers", t)
	return ""
}
func (e *encoder) variable(obj types.Object) string {
	if v, ok := e.ids[obj]; ok { return v }
	if obj == nil { fail("missing typed variable") }
	if _, ok := obj.(*types.Var); !ok { fail("not a variable: %s", obj.Name()) }
	if len(e.ids) >= 1024 { fail("too many local variables") }
	id := fmt.Sprintf("v%d", len(e.ids)); e.ids[obj] = id
	e.locals = append(e.locals, node{"id":id, "name":obj.Name(), "type":typeName(obj.Type(), false)})
	return id
}
func (e *encoder) expr(x ast.Expr) node {
	e.count++; if e.count > 100000 { fail("expression budget exceeded") }
	tv, ok := e.info.Types[x]; if !ok { fail("missing typed expression %T", x) }
	typ := typeName(tv.Type, true)
	if tv.Value != nil {
		if tv.Value.Kind() == constant.Bool { return node{"kind":"constant", "type":"bool", "value":constant.BoolVal(tv.Value)} }
		if tv.Value.Kind() != constant.Int { fail("unsupported constant") }
		return node{"kind":"constant", "type":typ, "value":tv.Value.ExactString()}
	}
	switch x := x.(type) {
	case *ast.ParenExpr: return e.expr(x.X)
	case *ast.Ident:
		obj := e.info.Uses[x]
		return node{"kind":"variable", "type":typ, "id":e.variable(obj)}
	case *ast.UnaryExpr:
		if x.Op != token.ADD && x.Op != token.SUB && x.Op != token.XOR && x.Op != token.NOT { fail("unsupported unary operator %s", x.Op) }
		return node{"kind":"unary", "type":typ, "op":x.Op.String(), "value":e.expr(x.X)}
	case *ast.BinaryExpr:
		if x.Op == token.QUO || x.Op == token.REM { fail("division/remainder require panic semantics and are unsupported") }
		return node{"kind":"binary", "type":typ, "op":x.Op.String(), "left":e.expr(x.X), "right":e.expr(x.Y)}
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() { fail("variadic calls unsupported") }
		if e.info.Types[x.Fun].IsType() {
			if len(x.Args) != 1 || typ == "bool" { fail("unsupported conversion") }
			return node{"kind":"convert", "type":typ, "value":e.expr(x.Args[0])}
		}
		id, ok := x.Fun.(*ast.Ident); if !ok { fail("only direct owned function calls supported") }
		f, ok := e.info.Uses[id].(*types.Func); if !ok || f.Pkg() == nil { fail("builtin/external calls unsupported") }
		args := []node{}; for _, a := range x.Args { args = append(args, e.expr(a)) }
		e.calls[f.Name()] = true
		return node{"kind":"call", "type":typ, "name":f.Name(), "args":args}
	}
	fail("unsupported expression %T", x); return nil
}
func (e *encoder) stmt(s ast.Stmt) node {
	if s == nil { return node{"kind":"empty"} }
	switch s := s.(type) {
	case *ast.EmptyStmt: return node{"kind":"empty"}
	case *ast.BlockStmt:
		body := []node{}; for _, child := range s.List { body = append(body, e.stmt(child)) }
		return node{"kind":"block", "body":body}
	case *ast.ReturnStmt:
		if len(s.Results) != 1 { fail("exactly one explicit return expression required") }
		return node{"kind":"return", "value":e.expr(s.Results[0])}
	case *ast.AssignStmt:
		if len(s.Lhs) != 1 || len(s.Rhs) != 1 { fail("multiple assignment unsupported") }
		id, ok := s.Lhs[0].(*ast.Ident); if !ok || id.Name == "_" { fail("only local identifier assignment supported") }
		obj := e.info.Defs[id]; if obj == nil { obj = e.info.Uses[id] }
		v := e.variable(obj)
		if s.Tok == token.QUO_ASSIGN || s.Tok == token.REM_ASSIGN { fail("division/remainder assignment unsupported") }
		return node{"kind":"assign", "id":v, "type":typeName(obj.Type(), false), "op":s.Tok.String(), "value":e.expr(s.Rhs[0])}
	case *ast.IncDecStmt:
		id, ok := s.X.(*ast.Ident); if !ok { fail("only local increment supported") }
		obj := e.info.Uses[id]
		return node{"kind":"incdec", "id":e.variable(obj), "type":typeName(obj.Type(), false), "op":s.Tok.String()}
	case *ast.IfStmt:
		return node{"kind":"if", "init":e.stmt(s.Init), "condition":e.expr(s.Cond), "then":e.stmt(s.Body), "else":e.stmt(s.Else)}
	case *ast.ForStmt:
		var cond interface{}; if s.Cond != nil { cond = e.expr(s.Cond) }
		return node{"kind":"for", "init":e.stmt(s.Init), "condition":cond, "post":e.stmt(s.Post), "body":e.stmt(s.Body)}
	case *ast.BranchStmt:
		if s.Label != nil || s.Tok != token.BREAK && s.Tok != token.CONTINUE { fail("only unlabeled loop break/continue supported") }
		return node{"kind":s.Tok.String()}
	case *ast.DeclStmt:
		g, ok := s.Decl.(*ast.GenDecl); if !ok || g.Tok != token.VAR && g.Tok != token.CONST { fail("unsupported local declaration") }
		body := []node{}
		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			if g.Tok == token.CONST { continue }
			if len(v.Names) != 1 || len(v.Values) > 1 { fail("multiple variable declaration unsupported") }
			obj := e.info.Defs[v.Names[0]]; typ := typeName(obj.Type(), false)
			var value node
			if len(v.Values) == 1 { value = e.expr(v.Values[0]) } else if typ == "bool" { value=node{"kind":"constant","type":"bool","value":false} } else { value=node{"kind":"constant","type":typ,"value":"0"} }
			body = append(body, node{"kind":"assign", "op":"=", "type":typ, "id":e.variable(obj), "value":value})
		}
		return node{"kind":"block", "body":body}
	case *ast.ExprStmt: return node{"kind":"expression", "value":e.expr(s.X)}
	}
	fail("unsupported statement %T", s); return nil
}
func analyze(paths []string) node {
	fset := token.NewFileSet(); files := []*ast.File{}
	for _, path := range paths {
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.AllErrors)
		if err != nil { fail("parse: %v", err) }
		if len(f.Imports) != 0 { fail("imports are unsupported; no external package resolution") }
		for _, group := range f.Comments { for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:") || strings.HasPrefix(c.Text,"//line ") || strings.HasPrefix(c.Text,"// +build") { fail("compiler/build directives unsupported") }
		} }
		files = append(files, f)
	}
	info := &types.Info{Types:map[ast.Expr]types.TypeAndValue{}, Defs:map[*ast.Ident]types.Object{}, Uses:map[*ast.Ident]types.Object{}}
	conf := types.Config{Sizes:types.SizesFor("gc", "amd64")}
	pkg, err := conf.Check("antirea_owned", fset, files, info); if err != nil { fail("typecheck: %v", err) }
	methods := []node{}
	for _, file := range files { for _, d := range file.Decls {
		f, ok := d.(*ast.FuncDecl)
		if !ok { g, ok := d.(*ast.GenDecl); if !ok || g.Tok != token.CONST { fail("package state/types are unsupported") }; continue }
		if f.Name.Name == "init" || f.Name.Name == "main" || f.Recv != nil || f.Type.TypeParams != nil || f.Body == nil { fail("initializers/main/methods/generics/bodyless functions unsupported") }
		sig := info.Defs[f.Name].Type().(*types.Signature)
		if sig.Variadic() || sig.Params().Len()>8 || sig.Results().Len()!=1 || sig.Results().At(0).Name()!="" { fail("requires <=8 scalar arguments and one unnamed scalar return") }
		result := typeName(sig.Results().At(0).Type(), false); if result=="bool" { fail("boolean return ABI unsupported") }
		e := &encoder{info:info,ids:map[types.Object]string{},calls:map[string]bool{},locals:[]node{}}
		params := []node{}
		for i:=0;i<sig.Params().Len();i++ {
			v:=sig.Params().At(i); typ:=typeName(v.Type(),false); if typ=="bool" || v.Name()=="" || v.Name()=="_" { fail("requires named fixed-width integer arguments") }
			params=append(params,node{"id":e.variable(v),"name":v.Name(),"type":typ})
		}
		body:=e.stmt(f.Body); calls:=[]string{}; for name:= range e.calls { calls=append(calls,name) }; sort.Strings(calls)
		methods=append(methods,node{"name":f.Name.Name,"parameters":params,"return_type":result,"locals":e.locals,"calls":calls,"body":body})
	} }
	if len(methods)>64 || len(methods)==0 { fail("expected 1..64 owned functions") }
	return node{"schema_version":1,"package":pkg.Name(),"methods":methods,"target_executed":false}
}
func main() {
	defer func(){ if r:=recover();r!=nil { fmt.Fprintln(os.Stderr,r); os.Exit(2) } }()
	if len(os.Args)<2 || len(os.Args)>33 { fail("expected 1..32 explicit source paths") }
	if err:=json.NewEncoder(os.Stdout).Encode(analyze(os.Args[1:]));err!=nil { fail("json: %v",err) }
}
