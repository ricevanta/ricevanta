package resourcevalidate

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func baseline(os, kind string, settings map[string]any) map[string]any {
	s := map[string]any{"os": os, "items": []any{map[string]any{"id": "item", "kind": kind, "settings": settings, "required": true, "severity": "high"}}}
	if kind != "check.query" && kind != "check.collector" {
		s["allowedGroups"] = []any{"fleet"}
	}
	return map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "Baseline", "metadata": map[string]any{"name": "test"}, "spec": s}
}
func queryBaseline() map[string]any {
	return baseline("linux", "check.query", map[string]any{"query": "select 1", "expect": "true"})
}
func item(m map[string]any) map[string]any {
	return m["spec"].(map[string]any)["items"].([]any)[0].(map[string]any)
}
func clone(t testing.TB, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func accept(t testing.TB, m map[string]any) {
	t.Helper()
	r, err := Validate(m)
	if err != nil || !reflect.DeepEqual(r, expectedResult(m)) {
		t.Fatalf("Validate %+v, %v", r, err)
	}
}

type hostileMarshaler struct{ called *bool }

func (h hostileMarshaler) MarshalJSON() ([]byte, error) { *h.called = true; panic("must not marshal") }
func TestValidateInputDomain(t *testing.T) {
	checkError(t, nil, ErrEnvelope, "", "envelope")
	called := false
	values := []any{int(0), json.Number("1"), struct{}{}, hostileMarshaler{&called}, []string{}, (*string)(nil), map[string]any(nil), []any(nil), math.NaN(), math.Inf(1), math.Inf(-1), float64(9007199254740992), string([]byte{255}), map[string]any{string([]byte{255}): nil}}
	for i, v := range values {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			m := queryBaseline()
			m["a"] = v
			path := "/a"
			if i == len(values)-1 {
				path += "/" + string([]byte{255})
			}
			checkError(t, m, ErrInput, path, "input")
		})
	}
	if called {
		t.Fatal("custom marshaler ran")
	}
	for _, v := range []any{float64(0), math.Copysign(0, -1)} {
		m := queryBaseline()
		item(m)["grace"] = v
		accept(t, m)
	}
	for _, v := range []any{true, 0.5} {
		m := queryBaseline()
		item(m)["grace"] = v
		checkError(t, m, ErrSchema, "/spec/items/0/grace", "schema")
	}
	shared := map[string]any{"x": float64(1.5), "y": float64(-9007199254740991)}
	m := baseline("linux", "check.collector", map[string]any{"ref": "ext/test/check", "expect": "true", "input": map[string]any{"a": shared, "b": shared}})
	accept(t, m)
	cyclic := map[string]any{}
	cyclic["cycle"] = cyclic
	m = queryBaseline()
	m["a"] = cyclic
	_, err := Validate(m)
	if e, ok := err.(*Error); !ok || e.Cause != ErrLimit || e.Rule != "budget" {
		t.Fatalf("cycle: %v", err)
	}
	a := make([]any, 1)
	a[0] = a
	m["a"] = a
	_, err = Validate(m)
	if e, ok := err.(*Error); !ok || e.Cause != ErrLimit {
		t.Fatalf("slice cycle: %v", err)
	}
}
func TestValidateErrorPrecedence(t *testing.T) {
	m := baseline("windows", "windows.registry", map[string]any{"hive": "HKLM", "view": float64(64), "key": "SOFTWARE\\Policies", "name": "", "type": "binary", "value": "YR=="})
	first := item(m)
	second := clone(t, m)["spec"].(map[string]any)["items"].([]any)[0]
	m["spec"].(map[string]any)["items"] = []any{first, second}
	checkError(t, m, ErrSemantic, "/spec/items/1/id", "unique")
	first["settings"].(map[string]any)["unknown"] = true
	checkError(t, m, ErrSchema, "/spec/items/0/settings/unknown", "schema")
	m["apiVersion"] = "wrong"
	checkError(t, m, ErrEnvelope, "/apiVersion", "envelope")
	m["a"] = strings.Repeat("a", 1048576)
	checkError(t, m, ErrLimit, "", "bytes")
	m["a"] = math.NaN()
	checkError(t, m, ErrInput, "/a", "input")
}
func TestValidateClassification(t *testing.T) {
	for _, c := range fixtureRecords(t) {
		if !c.Accepted {
			continue
		}
		m := readFixture(t, c.File)
		accept(t, m)
	}
	m := baseline("linux", "linux.polkit", map[string]any{"rules": "polkit.addRule(function() { return polkit.Result.YES; });"})
	item(m)["required"] = false
	accept(t, m)
	item(m)["protected"] = false
	checkError(t, m, ErrSchema, "/spec/items/0/protected", "schema")
}
func TestValidateNoMutation(t *testing.T) {
	for _, c := range fixtureRecords(t) {
		m := readFixture(t, c.File)
		before := clone(t, m)
		Validate(m)
		if !reflect.DeepEqual(m, before) {
			t.Fatalf("mutated %s", c.File)
		}
	}
}
func TestValidateNoAliases(t *testing.T) {
	m := baseline("linux", "software", map[string]any{"package": "test", "ensure": "present"})
	r, err := Validate(m)
	if err != nil {
		t.Fatal(err)
	}
	r.ApplyItemIDs[0] = "changed"
	if item(m)["id"] != "item" {
		t.Fatal("result aliases input")
	}
	r2, err := Validate(m)
	if err != nil || r2.ApplyItemIDs[0] != "item" {
		t.Fatal("retained result slice")
	}
	item(m)["id"] = "new"
	if r2.ApplyItemIDs[0] != "item" {
		t.Fatal("input aliases result")
	}
}
func TestValidateConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			m := queryBaseline()
			for range 25 {
				accept(t, m)
			}
		})
	}
	wg.Wait()
}
func TestErrorRedaction(t *testing.T) {
	m := queryBaseline()
	item(m)["settings"].(map[string]any)["query"] = "secret\x00bytes"
	checkError(t, m, ErrSchema, "/spec/items/0/settings/query", "schema")
}

func TestVersionScalars(t *testing.T) {
	excluded := map[rune]bool{}
	for r := rune(0); r <= 0x20; r++ {
		excluded[r] = true
	}
	for r := rune(0x2000); r <= 0x200a; r++ {
		excluded[r] = true
	}
	for _, r := range []rune{0x7f, 0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff} {
		excluded[r] = true
	}
	probes := map[rune]bool{0x1f600: true}
	for r := range excluded {
		probes[r] = true
		if r > 0 {
			probes[r-1] = true
		}
		probes[r+1] = true
	}
	for r := range probes {
		for _, s := range []string{"1" + string(r), "1" + string(r) + "0"} {
			m := queryBaseline()
			m["spec"].(map[string]any)["minOsVersion"] = s
			if excluded[r] {
				checkError(t, m, ErrSchema, "/spec/minOsVersion", "schema")
			} else {
				accept(t, m)
			}
		}
	}
	for _, ch := range []string{"a", "😀"} {
		for _, n := range []int{0, 1, 128, 129} {
			m := queryBaseline()
			m["spec"].(map[string]any)["minOsVersion"] = strings.Repeat(ch, n)
			if n == 1 || n == 128 {
				accept(t, m)
			} else {
				checkError(t, m, ErrSchema, "/spec/minOsVersion", "schema")
			}
		}
	}
	settings := []any{"spec", "items", 0, "settings"}
	cases := []struct {
		file string
		path []any
	}{
		{"mdm-os-update-macos-populated.json", []any{"spec", "minOsVersion"}},
		{"mdm-os-update-macos-populated.json", append(append([]any{}, settings...), "targetVersion")},
		{"mdm-os-update-macos-populated.json", append(append([]any{}, settings...), "targetBuild")},
		{"mdm-os-update-windows-populated.json", append(append([]any{}, settings...), "productVersion")},
		{"mdm-os-update-windows-populated.json", append(append([]any{}, settings...), "targetRelease")},
	}
	for _, file := range []string{"mdm-package-macos-pkg-blob-developer-id-bundle.json", "mdm-package-windows-msix-blob-msix-msix.json", "mdm-package-windows-exe-blob-authenticode-uninstall.json", "mdm-package-linux-deb-blob-none-package.json"} {
		cases = append(cases, struct {
			file string
			path []any
		}{file, []any{"spec", "version"}}, struct {
			file string
			path []any
		}{file, []any{"spec", "detection", "version"}})
	}
	for _, c := range cases {
		for r := range probes {
			m := readFixture(t, "valid/"+c.file)
			var parent any = m
			for _, k := range c.path[:len(c.path)-1] {
				switch x := k.(type) {
				case string:
					parent = parent.(map[string]any)[x]
				case int:
					parent = parent.([]any)[x]
				}
			}
			s := "1" + string(r) + "0"
			parent.(map[string]any)[c.path[len(c.path)-1].(string)] = s
			if !excluded[r] && m["kind"] == "SoftwarePackage" {
				spec := m["spec"].(map[string]any)
				spec["version"] = s
				spec["detection"].(map[string]any)["version"] = s
			}
			if excluded[r] {
				checkError(t, m, ErrSchema, location(c.path).pointer(), "schema")
			} else {
				accept(t, m)
			}
		}
	}
}
func TestCSPNamespaces(t *testing.T) {
	for _, scope := range []string{"Device", "User"} {
		for _, format := range []struct {
			kind  string
			value any
		}{{"int", float64(1)}, {"bool", true}, {"chr", ""}, {"xml", "<x/>"}, {"b64", "YQ=="}} {
			for _, probe := range []struct{ suffix, rule string }{{"Test/Setting", ""}, {"./Test", "target"}, {"../Test", "target"}, {"Test/.", "target"}, {"Test/..", "target"}, {"", "schema"}, {"Test//Setting", "schema"}, {"Test/", "schema"}, {"%2e/Test", "schema"}, {"Test?q=1", "schema"}, {"Test#x", "schema"}} {
				m := baseline("windows", "windows.csp", map[string]any{"locUri": "./" + scope + "/Vendor/MSFT/" + probe.suffix, "format": format.kind, "value": format.value})
				if probe.rule == "" {
					accept(t, m)
				} else {
					cause := ErrSchema
					if probe.rule == "target" {
						cause = ErrSemantic
					}
					checkError(t, m, cause, "/spec/items/0/settings/locUri", probe.rule)
				}
			}
		}
	}
}

func TestBaselineConditionalErrorOrder(t *testing.T) {
	for _, v := range []any{nil, true, "items", float64(1), []any{nil}, []any{true}} {
		m := queryBaseline()
		m["spec"].(map[string]any)["items"] = v
		checkError(t, m, ErrSchema, "/spec/allowedGroups", "schema")
	}
	m := queryBaseline()
	delete(m["spec"].(map[string]any), "items")
	checkError(t, m, ErrSchema, "/spec/allowedGroups", "schema")
	m = queryBaseline()
	spec := m["spec"].(map[string]any)
	spec["items"] = []any{}
	spec["allowedGroups"] = []any{"fleet"}
	checkError(t, m, ErrSchema, "/spec/allowedGroups", "schema")
	m = queryBaseline()
	spec = m["spec"].(map[string]any)
	spec["items"] = []any{}
	checkError(t, m, ErrSchema, "/spec/items", "schema")
	m = queryBaseline()
	delete(item(m), "kind")
	checkError(t, m, ErrSchema, "/spec/items/0/kind", "schema")
	m = queryBaseline()
	item(m)["kind"] = "apple.unknown"
	item(m)["authority"] = "agent"
	checkError(t, m, ErrSchema, "/spec/items/0/kind", "schema")
}
func TestBaselineUnknownKindAuthority(t *testing.T) {
	m := queryBaseline()
	item(m)["kind"] = "apple.unknown"
	item(m)["authority"] = "agent"
	checkError(t, m, ErrSchema, "/spec/items/0/kind", "schema")
}
