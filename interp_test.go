package scanguard

// Constructs that compile and pass every test here but misbehave under the
// Yaegi interpreter Traefik runs this plugin with. Each was hit for real; the
// tests keep them from coming back. docs/development.md has the list.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Yaegi v0.16.1 evaluates only the FIRST expression of a multi-expression case
// in a tagless switch: `switch { case a, b: }` behaves as `case a:`. That made a
// Redis replica decode a published revert ("null") as a rule set of schema
// version 0, refuse it, and keep enforcing the reverted rules. Tagged switches
// (`switch x { case 1, 2: }`) are not affected.
func TestNoMultiExpressionCasesInTaglessSwitches(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag != nil {
				return true
			}
			for _, stmt := range sw.Body.List {
				if cc, ok := stmt.(*ast.CaseClause); ok && len(cc.List) > 1 {
					t.Errorf("%s: a tagless switch case lists %d expressions; Yaegi evaluates only the first. Use separate cases or ifs.",
						fset.Position(cc.Pos()), len(cc.List))
				}
			}
			return true
		})
	}
}
