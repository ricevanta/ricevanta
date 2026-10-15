// Command gotestdecls prints the tests, fuzz targets, benchmarks and runnable
// examples that go test derives from each named test file. It parses files with
// go/parser and go/doc using the rules of cmd/go's test loader, so comments and
// literals cannot hide a declaration or an example's output comment.
//
// Each output line is "kind<TAB>name<TAB>path", where kind is test, fuzz,
// benchmark or example; examples without an output comment are compiled but
// not run, so they are not printed.
package main

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

func main() {
	files := token.NewFileSet()
	for _, path := range os.Args[1:] {
		f, err := parser.ParseFile(files, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			name := fn.Name.Name
			kind := ""
			switch {
			case name == "TestMain":
				// TestMain(*testing.T) is an ordinary test; otherwise it is the main entry point.
				if isTestFunc(fn, "T") {
					kind = "test"
				}
			case isTest(name, "Test"):
				kind = "test"
			case isTest(name, "Benchmark"):
				kind = "benchmark"
			case isTest(name, "Fuzz"):
				kind = "fuzz"
			}
			if kind != "" {
				fmt.Printf("%s\t%s\t%s\n", kind, name, path)
			}
		}
		for _, e := range doc.Examples(f) {
			if e.Output == "" && !e.EmptyOutput {
				continue
			}
			fmt.Printf("example\tExample%s\t%s\n", e.Name, path)
		}
	}
}

// isTest and isTestFunc match cmd/go/internal/load.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}

func isTestFunc(fn *ast.FuncDecl, arg string) bool {
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 || fn.Type.Params.List == nil ||
		len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	ptr, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	if name, ok := ptr.X.(*ast.Ident); ok && name.Name == arg {
		return true
	}
	sel, ok := ptr.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == arg
}
