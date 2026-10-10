package celdecl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

const assetDir = "../../../../schemas/cel/v1/"

func canonical(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(assetDir + "variables.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkParse(t testing.TB, b []byte, want error) {
	t.Helper()
	d, err := Parse(b)
	if want == nil {
		if err != nil || d == nil {
			t.Fatalf("Parse: document=%v error=%v", d, err)
		}
		return
	}
	if d != nil || !errors.Is(err, want) {
		t.Fatalf("Parse: document=%v error=%v, want %v", d, err, want)
	}
	for _, other := range []error{ErrRead, ErrSize, ErrJSON, ErrDuplicateKey, ErrShape, ErrVersion, ErrProfile, ErrOCSF, ErrName, ErrType, ErrLimit, ErrDomain, ErrReference, ErrCycle, ErrCatalogue, ErrDocument} {
		if other != want && errors.Is(err, other) {
			t.Fatalf("also matches %v", other)
		}
	}
}

func altered(t testing.TB, edit func(map[string]any)) []byte {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(canonical(t), &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func dict(v any) map[string]any                             { return v.(map[string]any) }
func variable(v map[string]any, name string) map[string]any { return dict(dict(v["variables"])[name]) }

func TestParseJSON(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("x"), []byte("{} {}"), []byte("{}!"), append([]byte{239, 187, 191}, canonical(t)...), []byte{'"', 255, '"'}, []byte(`"\ud800"`), []byte(`"\udc00"`), []byte(`"\ud800x"`), []byte(`"\ud800\u0041"`)} {
		checkParse(t, b, ErrJSON)
	}
	checkParse(t, canonical(t), nil)
	for _, s := range []string{`"\ud83d\ude00"`, `"😀"`, `"escaped { } \\ \""`} {
		checkParse(t, []byte(s), ErrShape)
	}
}
func TestParseDuplicateKeys(t *testing.T) {
	for _, b := range []string{`{"x":1,"x":2}`, `{"name":1,"na\u006de":2}`, `{"x":{"a":1,"a":2}}`, `{"x":[{"type":{"kind":"int","kind":"bool"}}]}`} {
		checkParse(t, []byte(b), ErrDuplicateKey)
	}
	for _, path := range []string{"root", "object", "field", "type"} {
		b := canonical(t)
		switch path {
		case "root":
			b = bytes.Replace(b, []byte(`"format_version": 1`), []byte(`"format_version": 1, "format_version": 2`), 1)
		case "object":
			b = bytes.Replace(b, []byte(`"doc": "Managed device projection."`), []byte(`"doc": "Managed device projection.", "doc": "x"`), 1)
		case "field":
			b = bytes.Replace(b, []byte(`"presence": "required"`), []byte(`"presence": "required", "presence": "optional"`), 1)
		case "type":
			b = bytes.Replace(b, []byte(`"kind": "string"`), []byte(`"kind": "string", "kind": "int"`), 1)
		}
		checkParse(t, b, ErrDuplicateKey)
	}
}
func TestParseNumbers(t *testing.T) {
	for _, n := range []string{"-0", "-1", "1.0", "1e0", "1E+0", "01", "+1"} {
		checkParse(t, bytes.Replace(canonical(t), []byte(`"format_version": 1`), []byte(`"format_version": `+n), 1), ErrJSON)
		checkParse(t, []byte(`{"ignored":`+n+`}`), ErrJSON)
	}
}
func TestParseShape(t *testing.T) {
	for _, b := range []string{`null`, `[]`, `0`, `true`, `{}`} {
		checkParse(t, []byte(b), ErrShape)
	}
	for _, key := range []string{"format_version", "profile", "declaration_version", "ocsf_version", "objects", "variables", "domains"} {
		t.Run(key+"/absent", func(t *testing.T) { checkParse(t, altered(t, func(v map[string]any) { delete(v, key) }), ErrShape) })
		t.Run(key+"/null", func(t *testing.T) { checkParse(t, altered(t, func(v map[string]any) { v[key] = nil }), ErrShape) })
		t.Run(key+"/case", func(t *testing.T) {
			checkParse(t, altered(t, func(v map[string]any) { v[strings.ToUpper(key)] = v[key]; delete(v, key) }), ErrShape)
		})
	}
	for _, edit := range []func(map[string]any){
		func(v map[string]any) { v["objects"] = map[string]any{} },
		func(v map[string]any) { v["variables"] = map[string]any{} },
		func(v map[string]any) { dict(dict(v["objects"])["device"])["fields"] = map[string]any{} },
		func(v map[string]any) { dict(dict(v["objects"])["device"])["doc"] = "bad\n" },
		func(v map[string]any) { variable(v, "now")["doc"] = "bad\x7f" },
		func(v map[string]any) { variable(v, "now")["presence"] = "unknown" },
		func(v map[string]any) { variable(v, "now")["values"] = []any{"x", "x"} },
		func(v map[string]any) { variable(v, "now")["values"] = []any{1} },
		func(v map[string]any) { variable(v, "now")["values"] = nil },
		func(v map[string]any) { variable(v, "now")["extra"] = true },
		func(v map[string]any) { delete(variable(v, "now"), "type") },
	} {
		checkParse(t, altered(t, edit), ErrShape)
	}
}
func arrayTokens(n int) []byte { return []byte("[" + strings.Repeat("0,", n-3) + "0]") }
func TestParseWireBounds(t *testing.T) {
	b := canonical(t)
	checkParse(t, append(b, bytes.Repeat([]byte(" "), MaxBytes-len(b))...), nil)
	checkParse(t, bytes.Repeat([]byte("!"), MaxBytes+1), ErrSize)
	for _, depth := range []int{64, 65} {
		want := ErrShape
		if depth == 65 {
			want = ErrSize
		}
		checkParse(t, []byte(strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth)), want)
	}
	checkParse(t, arrayTokens(32768), ErrShape)
	checkParse(t, arrayTokens(32769), ErrSize)
	checkParse(t, bytes.Replace(arrayTokens(32768), []byte("0"), []byte(`"{\\\"}"`), 1), ErrShape)
	checkParse(t, bytes.Replace(arrayTokens(32769), []byte("0"), []byte(`"{\\\"}"`), 1), ErrSize)
	checkParse(t, []byte("["+strings.Repeat(`"{\\\"}",`, 32766)+`"x"]`), ErrSize)
}
func TestParseLexicalPrecedence(t *testing.T) {
	checkParse(t, []byte(`{"x":1,"x":2} !`), ErrJSON)
	checkParse(t, []byte(`{"format_version":2,"format_version":3}`), ErrDuplicateKey)
	checkParse(t, altered(t, func(v map[string]any) { v["extra"] = true; v["format_version"] = 2 }), ErrShape)
	checkParse(t, []byte("!"+strings.Repeat("[", 65)), ErrJSON)
	checkParse(t, []byte(strings.Repeat("[", 65)+"!"), ErrSize)
}

func fixtureCases(t testing.TB) []struct {
	File        string
	SchemaValid bool `json:"schema_valid"`
	Error       *string
} {
	t.Helper()
	b, err := os.ReadFile(assetDir + "fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema string
		Cases  []struct {
			File        string
			SchemaValid bool `json:"schema_valid"`
			Error       *string
		}
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "declarations.schema.json" || len(manifest.Cases) != 48 {
		t.Fatal("unexpected fixture manifest")
	}
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		if seen[c.File] {
			t.Fatal("duplicate fixture", c.File)
		}
		seen[c.File] = true
	}
	files, err := os.ReadDir(assetDir + "fixtures")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") && !seen["fixtures/"+f.Name()] {
			t.Fatal("unlisted fixture", f.Name())
		}
	}
	return manifest.Cases
}
func fixtureSentinels() map[string]error {
	return map[string]error{"ErrRead": ErrRead, "ErrSize": ErrSize, "ErrJSON": ErrJSON, "ErrDuplicateKey": ErrDuplicateKey, "ErrShape": ErrShape, "ErrVersion": ErrVersion, "ErrProfile": ErrProfile, "ErrOCSF": ErrOCSF, "ErrName": ErrName, "ErrType": ErrType, "ErrLimit": ErrLimit, "ErrDomain": ErrDomain, "ErrReference": ErrReference, "ErrCycle": ErrCycle, "ErrCatalogue": ErrCatalogue, "ErrDocument": ErrDocument}
}
func TestFixtures(t *testing.T) {
	count := 0
	for _, c := range fixtureCases(t) {
		t.Run(c.File, func(t *testing.T) {
			b, err := os.ReadFile(assetDir + c.File)
			if err != nil {
				t.Fatal(err)
			}
			var want error
			if c.Error != nil {
				var ok bool
				want, ok = fixtureSentinels()[*c.Error]
				if !ok {
					t.Fatal("unknown fixture error")
				}
			}
			checkParse(t, b, want)
			count++
		})
	}
	if count != 48 {
		t.Fatalf("executed %d fixtures", count)
	}
}
func TestVersionPrecedence(t *testing.T) {
	for _, c := range []struct {
		edit func(map[string]any)
		want error
	}{
		{func(v map[string]any) { v["format_version"] = 0; dict(v["profile"])["id"] = "wrong" }, ErrVersion},
		{func(v map[string]any) { v["declaration_version"] = 2; dict(v["profile"])["version"] = 2 }, ErrVersion},
		{func(v map[string]any) { dict(v["profile"])["id"] = "wrong"; v["ocsf_version"] = "wrong" }, ErrProfile},
		{func(v map[string]any) { dict(v["profile"])["version"] = 0; v["ocsf_version"] = "wrong" }, ErrProfile},
		{func(v map[string]any) {
			v["ocsf_version"] = "wrong"
			dict(v["variables"])["bad.name"] = variable(v, "now")
		}, ErrOCSF},
	} {
		checkParse(t, altered(t, c.edit), c.want)
	}
	b := bytes.Replace(canonical(t), []byte(`"format_version": 1`), []byte(`"format_version": `+strings.Repeat("9", 100)), 1)
	checkParse(t, b, ErrVersion)
}
func TestTypeGrammar(t *testing.T) {
	for _, kind := range []string{"uint", "bytes", "dyn", "any", "message", "enum", "wrapper", "optional", "nullable", "opaque", "union", "Bool", ""} {
		t.Run(kind, func(t *testing.T) {
			checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = map[string]any{"kind": kind} }), ErrType)
		})
	}
	for _, typ := range []any{nil, "int", 1, []any{}, map[string]any{},
		map[string]any{"Kind": "int"}, map[string]any{"kind": "int", "name": "device"},
		map[string]any{"kind": "string"}, map[string]any{"kind": "string", "max_length": nil}, map[string]any{"kind": "string", "max_length": "1"},
		map[string]any{"kind": "list", "max_items": 1}, map[string]any{"kind": "list", "element": nil, "max_items": 1},
		map[string]any{"kind": "map", "key": "int", "value": map[string]any{"kind": "int"}, "max_entries": 1},
		map[string]any{"kind": "map", "key": "string", "value": map[string]any{"kind": "int"}},
		map[string]any{"kind": "object"}, map[string]any{"kind": "object", "name": nil},
	} {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = typ }), ErrType)
	}
	for _, kind := range []string{"bool", "int", "double", "null", "duration", "json"} {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = map[string]any{"kind": kind} }), ErrCatalogue)
	}
	checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["values"] = []any{"a"} }), ErrType)
	for _, p := range []string{"network", "exact"} {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["presence"] = p }), ErrType)
	}
	for _, name := range []string{"Bad", "bad.name", "a\n", strings.Repeat("a", 65), ""} {
		checkParse(t, altered(t, func(v map[string]any) { dict(v["variables"])[name] = variable(v, "now") }), ErrName)
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "device")["type"] = map[string]any{"kind": "object", "name": name} }), ErrName)
	}
}
func TestDeclarationLimits(t *testing.T) {
	for _, n := range []int{64, 65} {
		want := ErrCatalogue
		if n == 65 {
			want = ErrLimit
		}
		for _, kind := range []string{"objects", "fields", "variables"} {
			t.Run(kind+string(rune(n)), func(t *testing.T) {
				checkParse(t, altered(t, func(v map[string]any) {
					var target map[string]any
					var entry any
					switch kind {
					case "objects":
						target = dict(v["objects"])
						entry = map[string]any{"doc": "x", "fields": map[string]any{"x": variable(v, "now")}}
					case "fields":
						target = dict(dict(dict(v["objects"])["device"])["fields"])
						entry = variable(v, "now")
					case "variables":
						target = dict(v["variables"])
						entry = variable(v, "now")
					}
					for i := 0; len(target) < n; i++ {
						target[fmt.Sprintf("extra_%02d", i)] = entry
					}
				}), want)
			})
		}
	}
	for _, n := range []int{0, 1024, 1025} {
		want := ErrCatalogue
		if n != 1024 {
			want = ErrLimit
		}
		for _, key := range []string{"entry", "object"} {
			checkParse(t, altered(t, func(v map[string]any) {
				if key == "entry" {
					variable(v, "now")["doc"] = strings.Repeat("😀", n)
				} else {
					dict(dict(v["objects"])["device"])["doc"] = strings.Repeat("😀", n)
				}
			}), want)
		}
	}
	for _, n := range []int{0, 32, 33} {
		want := ErrCatalogue
		if n != 32 {
			want = ErrLimit
		}
		checkParse(t, altered(t, func(v map[string]any) {
			e := variable(v, "now")
			e["type"] = map[string]any{"kind": "string", "max_length": 64}
			a := []any{}
			for i := 0; i < n; i++ {
				a = append(a, fmt.Sprintf("v%02d", i))
			}
			e["values"] = a
		}), want)
	}
	for _, n := range []int{0, 64, 65} {
		want := ErrCatalogue
		if n != 64 {
			want = ErrLimit
		}
		checkParse(t, altered(t, func(v map[string]any) {
			e := variable(v, "now")
			e["type"] = map[string]any{"kind": "string", "max_length": 64}
			e["values"] = []any{strings.Repeat("😀", n)}
		}), want)
	}
	for _, c := range []struct {
		kind, key string
		max       int
	}{{"string", "max_length", 32768}, {"list", "max_items", 10000}, {"map", "max_entries", 1024}} {
		for _, n := range []int{0, 1, c.max, c.max + 1} {
			want := ErrCatalogue
			if n == 0 || n > c.max {
				want = ErrLimit
			}
			checkParse(t, altered(t, func(v map[string]any) {
				typ := map[string]any{"kind": c.kind, c.key: n}
				if c.kind == "list" {
					typ["element"] = map[string]any{"kind": "int"}
				}
				if c.kind == "map" {
					typ["key"] = "string"
					typ["value"] = map[string]any{"kind": "int"}
				}
				variable(v, "now")["type"] = typ
			}), want)
		}
	}
	for _, depth := range []int{16, 17} {
		want := ErrCatalogue
		if depth == 17 {
			want = ErrLimit
		}
		checkParse(t, altered(t, func(v map[string]any) {
			typ := map[string]any{"kind": "int"}
			for i := 1; i < depth; i++ {
				typ = map[string]any{"kind": "list", "max_items": 1, "element": typ}
			}
			variable(v, "now")["type"] = typ
		}), want)
	}
	b := bytes.Replace(canonical(t), []byte(`"max_length": 4096`), []byte(`"max_length": `+strings.Repeat("9", 100)), 1)
	checkParse(t, b, ErrLimit)
}
func TestDomainContexts(t *testing.T) {
	for _, edit := range []func(map[string]any){
		func(v map[string]any) { delete(dict(v["domains"]), "edr") }, func(v map[string]any) { dict(v["domains"])["extra"] = dict(v["domains"])["edr"] },
		func(v map[string]any) { dict(v["domains"])["edr"] = nil }, func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = nil },
		func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = []any{} },
		func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = []any{"Bad"} },
		func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = []any{1} },
		func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = []any{"device", "device"} },
		func(v map[string]any) { dict(dict(v["domains"])["edr"])["condition"] = []any{"user", "now"} },
		func(v map[string]any) {
			a := []any{}
			for i := 0; i < 65; i++ {
				a = append(a, fmt.Sprintf("v%02d", i))
			}
			dict(dict(v["domains"])["edr"])["condition"] = a
		},
	} {
		checkParse(t, altered(t, edit), ErrDomain)
	}
	checkParse(t, altered(t, func(v map[string]any) {
		a := []any{}
		for i := 0; i < 64; i++ {
			name := fmt.Sprintf("v%02d", i)
			a = append(a, name)
			dict(v["variables"])[name] = variable(v, "now")
		}
		for k := range dict(v["variables"]) {
			if !strings.HasPrefix(k, "v") {
				delete(dict(v["variables"]), k)
			}
		}
		for _, contexts := range dict(v["domains"]) {
			for k := range dict(contexts) {
				dict(contexts)[k] = a
			}
		}
	}), ErrCatalogue)
}
func cycleEdit(v map[string]any) {
	dict(dict(dict(v["objects"])["device"])["fields"])["self"] = map[string]any{"doc": "x", "presence": "required", "type": map[string]any{"kind": "object", "name": "device"}}
}
func missingEdit(v map[string]any) {
	variable(v, "device")["type"] = map[string]any{"kind": "object", "name": "missing"}
}
func TestReferencesAndCycles(t *testing.T) {
	checkParse(t, altered(t, missingEdit), ErrReference)
	checkParse(t, altered(t, cycleEdit), ErrCycle)
	for _, kind := range []string{"list", "map", "object"} {
		checkParse(t, altered(t, func(v map[string]any) {
			typ := map[string]any{"kind": "object", "name": "unused"}
			if kind == "list" {
				typ = map[string]any{"kind": "list", "element": typ, "max_items": 1}
			}
			if kind == "map" {
				typ = map[string]any{"kind": "map", "key": "string", "value": typ, "max_entries": 1}
			}
			dict(v["objects"])["unused"] = map[string]any{"doc": "x", "fields": map[string]any{"self": map[string]any{"doc": "x", "presence": "required", "type": typ}}}
		}), ErrCycle)
	}
}
func TestSemanticPrecedence(t *testing.T) {
	cases := []struct {
		first, second func(map[string]any)
		want          error
	}{
		{func(v map[string]any) { dict(v["variables"])["bad.name"] = variable(v, "now") }, func(v map[string]any) { variable(v, "now")["type"] = nil }, ErrName},
		{func(v map[string]any) { variable(v, "now")["type"] = nil }, func(v map[string]any) { dict(variable(v, "rows")["type"])["max_items"] = 10001 }, ErrType},
		{func(v map[string]any) { dict(variable(v, "rows")["type"])["max_items"] = 10001 }, func(v map[string]any) { delete(dict(v["domains"]), "edr") }, ErrLimit},
		{func(v map[string]any) { delete(dict(v["domains"]), "edr") }, missingEdit, ErrDomain},
		{missingEdit, cycleEdit, ErrReference},
		{cycleEdit, func(v map[string]any) { variable(v, "now")["doc"] = "changed" }, ErrCycle},
	}
	for _, c := range cases {
		b := altered(t, func(v map[string]any) { c.first(v); c.second(v) })
		checkParse(t, b, c.want)
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		checkParse(t, reverseJSON(t, v), c.want)
	}
}
func reverseJSON(t testing.TB, v any) []byte {
	t.Helper()
	if m, ok := v.(map[string]any); ok {
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		parts := []string{}
		for _, k := range keys {
			b, _ := json.Marshal(k)
			parts = append(parts, string(b)+":"+string(reverseJSON(t, m[k])))
		}
		return []byte("{" + strings.Join(parts, ",") + "}")
	}
	if a, ok := v.([]any); ok {
		parts := []string{}
		for _, x := range a {
			parts = append(parts, string(reverseJSON(t, x)))
		}
		return []byte("[" + strings.Join(parts, ",") + "]")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestCatalogueIdentity(t *testing.T) {
	for _, edit := range []func(map[string]any){
		func(v map[string]any) { variable(v, "now")["doc"] = "changed" },
		func(v map[string]any) {
			dict(dict(dict(dict(v["objects"])["certificate"])["fields"])["serial"])["presence"] = "optional"
		},
		func(v map[string]any) {
			dict(dict(v["domains"])["edr"])["condition"] = []any{"certificate", "device", "event", "now", "user"}
		},
		func(v map[string]any) {
			dict(dict(dict(dict(v["objects"])["device"])["fields"])["uid"])["type"] = map[string]any{"kind": "string", "max_length": 4095}
		},
	} {
		checkParse(t, altered(t, edit), ErrCatalogue)
	}
	for _, doc := range []string{`"\ud83d\ude00"`, `"😀"`} {
		b := bytes.Replace(canonical(t), []byte(`"Managed device projection."`), []byte(doc), 1)
		checkParse(t, b, ErrCatalogue)
	}
	checkParse(t, bytes.Replace(canonical(t), []byte(`"device"`), []byte(`"devi\u0063e"`), -1), nil)
}

func TestTypeGrammarSubtrees(t *testing.T) {
	for _, name := range []string{"Bad", "bad.name", "a\n", strings.Repeat("a", 65), ""} {
		checkParse(t, altered(t, func(v map[string]any) { dict(v["objects"])[name] = dict(v["objects"])["device"] }), ErrName)
		checkParse(t, altered(t, func(v map[string]any) { dict(dict(dict(v["objects"])["device"])["fields"])[name] = variable(v, "now") }), ErrName)
	}
	for _, typ := range []any{
		map[string]any{"kind": "map", "key": "string", "max_entries": 1},
		map[string]any{"kind": "map", "key": "string", "value": nil, "max_entries": 1},
		map[string]any{"kind": "list", "element": "int", "max_items": 1},
		map[string]any{"kind": "object", "name": "device", "extra": true},
		map[string]any{"kind": "string", "max_length": 1, "max_items": 1},
	} {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = typ }), ErrType)
	}
	checkParse(t, altered(t, func(v map[string]any) {
		e := variable(v, "now")
		e["type"] = map[string]any{"kind": "int"}
		e["values"] = []any{"a"}
	}), ErrType)
}
func TestParseShapeMembers(t *testing.T) {
	for _, location := range []string{"profile", "object", "entry"} {
		for _, mode := range []string{"extra", "case", "missing", "null"} {
			checkParse(t, altered(t, func(v map[string]any) {
				var target map[string]any
				var key string
				switch location {
				case "profile":
					target = dict(v["profile"])
					key = "id"
				case "object":
					target = dict(dict(v["objects"])["device"])
					key = "fields"
				case "entry":
					target = variable(v, "now")
					key = "doc"
				}
				switch mode {
				case "extra":
					target["extra"] = true
				case "case":
					target[strings.ToUpper(key)] = target[key]
					delete(target, key)
				case "missing":
					delete(target, key)
				case "null":
					target[key] = nil
				}
			}), ErrShape)
		}
	}
	for r := rune(0); r <= 31; r++ {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["doc"] = "x" + string(r) }), ErrShape)
	}
}

// The padded multi-root input must not rescan its whitespace suffix per token.
func TestTrailingScanBudget(t *testing.T) {
	data := []byte(strings.Repeat("0 ", 32768))
	data = append(data, bytes.Repeat([]byte(" "), MaxBytes-len(data))...)
	start := time.Now()
	checkParse(t, data, ErrJSON)
	elapsed := time.Since(start)
	t.Logf("padded multi-root parse: %s", elapsed)
	// The linear parser takes milliseconds; allow scheduler and race overhead.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("trailing scan took %s, budget 500ms", elapsed)
	}
}

func TestReferenceNamesStayInTypes(t *testing.T) {
	bad := map[string]any{"kind": "object", "name": "Bad"}
	cases := map[string]any{
		"name":       map[string]any{"kind": "object", "name": bad},
		"max_length": map[string]any{"kind": "string", "max_length": bad},
		"extra":      map[string]any{"kind": "timestamp", "extra": bad},
	}
	for name, typ := range cases {
		t.Run(name, func(t *testing.T) {
			checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = typ }), ErrType)
		})
	}
	for _, typ := range []any{
		bad,
		map[string]any{"kind": "list", "element": bad, "max_items": 1},
		map[string]any{"kind": "map", "key": "string", "value": bad, "max_entries": 1},
	} {
		checkParse(t, altered(t, func(v map[string]any) { variable(v, "now")["type"] = typ }), ErrName)
	}
}
