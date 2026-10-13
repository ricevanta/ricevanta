package loader

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"go.yaml.in/yaml/v3"
)

func TestDecodeVerifiedYAML(t *testing.T) {
	want := map[string]any{"kind": "Extension", "items": []any{true, false, json.Number("18446744073709551615"), "12", map[string]any{}}}
	for _, source := range []string{"kind: Extension\nitems: [true, false, 18446744073709551615, '12', {}]\n", `{"kind":"Extension","items":[true,false,18446744073709551615,"12",{}]}`} {
		for _, start := range []string{"", "---\n"} {
			for _, end := range []string{"", "\n...\n# tail\n"} {
				got, err := decodeVerifiedYAML([]byte(start + source + end))
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("%#v, %v", got, err)
				}
				assertConvertedTypes(t, got)
			}
		}
	}
	for _, source := range []string{"", "# comment\n", "---\n...\n", "a: b\n---\n", "a: b\n...\nx: y\n", "a: b\n[", "\xef\xbb\xbfa: b", "a: \xff", "[]", "a: &x b", "a: *x", "%YAML 1.1\n---\na: b"} {
		assertYAMLError(t, source, ErrYAML)
	}
}
func assertConvertedTypes(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for _, c := range x {
			assertConvertedTypes(t, c)
		}
	case []any:
		for _, c := range x {
			assertConvertedTypes(t, c)
		}
	case string, bool, json.Number:
	default:
		t.Fatalf("output type %T", v)
	}
}
func assertYAMLError(t *testing.T, source string, want error) {
	t.Helper()
	got, err := decodeVerifiedYAML([]byte(source))
	if got != nil || !errors.Is(err, want) {
		t.Fatalf("non-nil document=%t, error=%v; want %v", got != nil, err, want)
	}
	if err.Error() != want.Error() {
		t.Fatalf("error detail: %v", err)
	}
}
func TestScalarProfile(t *testing.T) {
	for _, v := range []string{"0", "1", "9223372036854775808", "18446744073709551615"} {
		got, err := decodeVerifiedYAML([]byte("a: " + v))
		if err != nil || got["a"] != json.Number(v) {
			t.Fatalf("%s: %#v, %v", v, got, err)
		}
	}
	for _, v := range []string{"yes", "no", "on", "off", "'123'", `"123"`, "'true'"} {
		got, err := decodeVerifiedYAML([]byte("a: " + v))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got["a"].(string); !ok {
			t.Fatalf("%s: %T", v, got["a"])
		}
	}
	for _, v := range []string{"null", "~", "", "True", "FALSE", "-1", "+1", "01", "1_000", "0x10", "0o10", "1.0", ".inf", ".nan", "1e2", "18446744073709551616", "123456789012345678901", "2001-01-01"} {
		assertYAMLError(t, "a: "+v, ErrYAML)
	}
	for _, tag := range []string{"!", "!!str", "!!bool", "!!int", "!!null", "!!binary", "!!timestamp", "!!float", "!!map", "!!seq", "!<tag:yaml.org,2002:str>"} {
		assertYAMLError(t, "a: "+tag+" value", ErrExplicitTag)
	}
	for _, source := range []string{"true: x", "1: x", "? [a, b]\n: x", "'<<': x", `"\u003c\u003c": x`, "<<: x"} {
		assertYAMLError(t, source, ErrYAML)
	}
	got, err := decodeVerifiedYAML([]byte("a: |\n  ! & * --- ... #\nb: 'can''t'\n"))
	if err != nil || got["a"] != "! & * --- ... #\n" || got["b"] != "can't" {
		t.Fatalf("%#v, %v", got, err)
	}
}
func TestDuplicateKeys(t *testing.T) {
	for _, source := range []string{`{kind: a, "k\u0069nd": b}`, `outer: {kind: a, "k\u0069nd": b}`, `outer: [{kind: a, "k\u0069nd": b}]`, "a: x\na: y"} {
		assertYAMLError(t, source, ErrDuplicateKey)
	}
	if _, err := decodeVerifiedYAML([]byte("a: {kind: x}\nb: {kind: y}")); err != nil {
		t.Fatal(err)
	}
}
func TestYAMLPrecedence(t *testing.T) {
	for _, source := range []string{"a: x\na: y\nb: null", "b: null\na: x\na: y", "a: null\nb: ! x", "a: x\na: y\nb: ["} {
		want := ErrYAML
		if strings.Contains(source, "! x") {
			want = ErrExplicitTag
		}
		assertYAMLError(t, source, want)
	}
	assertYAMLError(t, "a: null\nb: "+strings.Repeat("[", 17)+"0"+strings.Repeat("]", 17), ErrYAMLLimit)
}

// The overlay alters only a temporary compilation of production source.
// The ordinary production build has no injectable dependency or counter.
func TestDecodeVerifiedYAMLCallCounts(t *testing.T) {
	dir := t.TempDir()
	replacements := map[string]string{}
	for _, name := range []string{"yaml.go", "tree.go"} {
		original, err := filepath.Abs(name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, original, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		type replacement struct {
			start, end int
			name       string
		}
		var edits []replacement
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			target := ""
			if s, ok := call.Fun.(*ast.SelectorExpr); ok {
				if p, ok := s.X.(*ast.Ident); ok && p.Name == "yamltokens" && s.Sel.Name == "DecodeAccounted" {
					target = "countedYAMLDecode"
				}
			}
			if f, ok := call.Fun.(*ast.Ident); ok && f.Name == "yamlValue" {
				target = "countedYAMLValue"
			}
			if target != "" {
				edits = append(edits, replacement{positions.Position(call.Fun.Pos()).Offset, positions.Position(call.Fun.End()).Offset, target})
			}
			return true
		})
		want := 1
		if name == "tree.go" {
			want = 2
		}
		if len(edits) != want {
			t.Fatalf("%s instrumentation sites %d, want %d", name, len(edits), want)
		}
		slices.SortFunc(edits, func(a, b replacement) int { return b.start - a.start })
		for _, e := range edits {
			data = append(append(append([]byte{}, data[:e.start]...), []byte(e.name)...), data[e.end:]...)
		}
		substitute := filepath.Join(dir, name)
		if err := os.WriteFile(substitute, data, 0600); err != nil {
			t.Fatal(err)
		}
		replacements[original] = substitute
	}
	data, err := json.Marshal(map[string]any{"Replace": replacements})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlay, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-count=1", "-overlay", overlay, ".", "-run", "^TestDecodeVerifiedYAMLInstrumented$")
	cmd.Env = append(os.Environ(), "GOPROXY=off", "RICEVANTA_YAML_INSTRUMENTED=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("instrumented test: %v\n%s", err, output)
	}
}

var yamlDecodeCalls, yamlContainers int

func countedYAMLDecode(payload []byte) (*yaml.Node, *yamltokens.Budget, error) {
	yamlDecodeCalls++
	return yamltokens.DecodeAccounted(payload)
}
func countedYAMLValue(n *yaml.Node, b *yamltokens.Budget) (any, error) {
	v, err := yamlValue(n, b)
	if err == nil && (n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode) {
		yamlContainers++
	}
	return v, err
}
func TestDecodeVerifiedYAMLInstrumented(t *testing.T) {
	if os.Getenv("RICEVANTA_YAML_INSTRUMENTED") != "1" {
		t.Skip("requires test-only source overlay")
	}
	for _, c := range []struct {
		source     string
		err        error
		containers int
	}{{"a: [1, true, {}]", nil, 3}, {"a: null", ErrYAML, 0}, {"a: ! x", ErrExplicitTag, 0}, {"a: [", ErrYAML, 0}, {"a: x\na: y", ErrDuplicateKey, 0}, {mappingSource(897), ErrYAMLLimit, 0}, {"a: [" + mappingSource(897) + "]", ErrYAMLLimit, 0}} {
		yamlDecodeCalls, yamlContainers = 0, 0
		document, err := decodeVerifiedYAML([]byte(c.source))
		if !errors.Is(err, c.err) || (err != nil && document != nil) {
			t.Fatalf("error %v, want %v", err, c.err)
		}
		if yamlDecodeCalls != 1 || yamlContainers != c.containers {
			t.Fatalf("decoder calls %d containers %d, want 1/%d", yamlDecodeCalls, yamlContainers, c.containers)
		}
	}
}
