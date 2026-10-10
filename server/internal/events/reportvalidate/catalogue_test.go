package reportvalidate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func canonical(t testing.TB, p string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	b, e := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../", p))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestBuiltin(t *testing.T) {
	c, e := Builtin()
	if e != nil || c.Revision() != 1 {
		t.Fatalf("builtin: %v", e)
	}
	again, e := Builtin()
	if e != nil || c != again {
		t.Fatal("initialization")
	}
}
func TestBuiltinDrift(t *testing.T) {
	c, e := Builtin()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(c.JSON(), canonical(t, "schemas/report/v1alpha1/catalogue.json")) {
		t.Fatal("catalogue drift")
	}
}
func TestCatalogueDetachedJSON(t *testing.T) {
	c, _ := Builtin()
	b := c.JSON()
	b[0] = '!'
	if c.JSON()[0] != '{' {
		t.Fatal("alias")
	}
	var zero Catalogue
	if zero.Revision() != 0 || zero.JSON() != nil {
		t.Fatal("zero")
	}
}
func TestPermissionBindings(t *testing.T) {
	c, e := Builtin()
	if e != nil {
		t.Fatal(e)
	}
	var p struct{ Permissions []map[string]any }
	if e = json.Unmarshal(canonical(t, "schemas/permissions/v1/catalogue.json"), &p); e != nil {
		t.Fatal(e)
	}
	by := map[string]map[string]any{}
	for _, x := range p.Permissions {
		by[x["name"].(string)] = x
	}
	for _, s := range c.sources {
		for _, r := range append([]ConditionalRead{{Permission: s.requirement.Permission, Scope: s.requirement.Scope}}, s.requirement.ConditionalReads...) {
			x := by[r.Permission]
			if x["owner"] != s.owner || x["scope"] != r.Scope || x["grant"] != "role" || x["status"] != "active" {
				t.Fatalf("binding %s", r.Permission)
			}
		}
	}
}
func TestCatalogueIntegrity(t *testing.T) {
	for _, raw := range []string{`{}`, `{"revision":1,"revision":2}`, string(catalogueJSON) + `{}`, "\xff"} {
		_, e := loadCatalogue(raw)
		if !errors.Is(e, ErrCatalogue) {
			t.Fatal("accepted invalid catalogue")
		}
	}
	var d map[string]any
	if e := json.Unmarshal([]byte(catalogueJSON), &d); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"owner", "read_permission", "scope", "footprint", "time_field", "conditional_reads", "unknown"} {
		var x map[string]any
		json.Unmarshal([]byte(catalogueJSON), &x)
		s := x["sources"].([]any)[0].(map[string]any)
		s[key] = "invalid"
		b, _ := json.Marshal(x)
		if _, e := loadCatalogue(string(b)); !errors.Is(e, ErrCatalogue) {
			t.Fatalf("accepted mutation %s", key)
		}
	}
}

func TestCatalogueHostileMutations(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { s := d["sources"].([]any); s[0], s[1] = s[1], s[0] },
		func(d map[string]any) { s := d["sources"].([]any); d["sources"] = s[:len(s)-1] },
		func(d map[string]any) {
			for _, s := range d["sources"].([]any) {
				m := s.(map[string]any)
				if m["id"] == "pki.certificates" {
					m["conditional_reads"] = []any{}
				}
			}
		},
		func(d map[string]any) {
			f := d["sources"].([]any)[0].(map[string]any)["fields"].([]any)
			f[0], f[1] = f[1], f[0]
		},
		func(d map[string]any) {
			f := d["sources"].([]any)[0].(map[string]any)["fields"].([]any)[1].(map[string]any)
			f["type"] = "string"
		},
		func(d map[string]any) {
			f := d["sources"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
			f["filterable"] = false
		},
		func(d map[string]any) {
			f := d["sources"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
			f["operators"] = []any{"eq", "eq"}
		},
		func(d map[string]any) {
			f := d["sources"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
			f["values"] = []any{"x"}
		},
		func(d map[string]any) { delete(d, "revision") },
	} {
		var d map[string]any
		if e := json.Unmarshal([]byte(catalogueJSON), &d); e != nil {
			t.Fatal(e)
		}
		mutate(d)
		raw, e := json.Marshal(d)
		if e != nil {
			t.Fatal(e)
		}
		c, e := loadCatalogue(string(raw))
		if c != nil {
			t.Fatal("partial catalogue")
		}
		assertError(t, e, ErrCatalogue, "", "catalogue")
	}
}

func TestPrivateLoaderBounds(t *testing.T) {
	for _, n := range []int{1048576, 1048577} {
		raw := catalogueJSON + strings.Repeat(" ", n-len(catalogueJSON))
		c, e := loadCatalogue(raw)
		if n == 1048576 {
			if e != nil || c == nil {
				t.Fatal(e)
			}
		} else {
			if c != nil {
				t.Fatal("partial catalogue")
			}
			assertError(t, e, ErrCatalogue, "", "catalogue")
		}
	}
	for _, n := range []int{16, 17} {
		raw := strings.Repeat("[", n) + "null" + strings.Repeat("]", n)
		_, e := decodeCatalogue(raw)
		if (e == nil) != (n == 16) {
			t.Fatalf("depth %d: %v", n, e)
		}
	}
	for _, n := range []int{32767, 32768} {
		raw := "[" + strings.Repeat("null,", n-1) + "null]"
		_, e := decodeCatalogue(raw)
		if (e == nil) != (n == 32767) {
			t.Fatalf("nodes %d: %v", n+1, e)
		}
	}
}
