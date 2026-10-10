package manifest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	m "github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

type corpusCase struct {
	Name        string
	Error       string
	SchemaValid bool `json:"schema_valid"`
	Options     struct {
		Allow bool   `json:"allow_reserved_id"`
		Max   uint64 `json:"max_total_file_bytes"`
	}
	Manifest map[string]any
}

func cases(t *testing.T) []corpusCase {
	t.Helper()
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct{ Cases []corpusCase }
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&c); e != nil {
		t.Fatal(e)
	}
	return c.Cases
}
func base(t *testing.T) map[string]any { return cases(t)[0].Manifest }
func check(t *testing.T, v any, o m.Options, want error) {
	t.Helper()
	got := m.Validate(v, o)
	if want == nil {
		if got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	} else if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
func localCases(t *testing.T, want string, sentinel error) {
	t.Helper()
	for _, c := range cases(t) {
		if c.Error == want {
			t.Run(c.Name, func(t *testing.T) {
				check(t, c.Manifest, m.Options{AllowReservedID: c.Options.Allow, MaxTotalFileBytes: c.Options.Max}, sentinel)
			})
		}
	}
}
func TestOptions(t *testing.T) {
	check(t, nil, m.Options{MaxTotalFileBytes: math.MaxUint64}, m.ErrOptions)
	check(t, base(t), m.Options{}, nil)
}
func TestTreeTypes(t *testing.T) {
	type text string
	type obj map[string]any
	type arr []any
	for _, v := range []any{nil, map[string]any(nil), []any(nil), 1, float64(1), math.NaN(), math.Inf(1), text("x"), obj{}, arr{}, "\xff", json.Number("01"), json.Number("-0"), json.Number("1.0"), json.Number("1e0"), json.Number("+1"), json.Number("18446744073709551616"), json.Number(strings.Repeat("1", 1000000))} {
		check(t, v, m.Options{}, m.ErrTree)
	}
	for _, s := range []string{"0", "1", "18446744073709551615"} {
		check(t, json.Number(s), m.Options{}, m.ErrShape)
	}
}
func TestTreeBudgets(t *testing.T) {
	for _, n := range []int{65535, 65536, 65537} {
		v := make([]any, n-1)
		for i := range v {
			v[i] = true
		}
		want := m.ErrShape
		if n > 65536 {
			want = m.ErrTree
		}
		check(t, v, m.Options{}, want)
	}
	for _, n := range []int{1048575, 1048576, 1048577} {
		want := m.ErrShape
		if n > 1048576 {
			want = m.ErrTree
		}
		check(t, strings.Repeat("a", n), m.Options{}, want)
	}
	for _, n := range []int{15, 16, 17} {
		var v any = true
		for i := 0; i < n; i++ {
			v = []any{v}
		}
		want := m.ErrShape
		if n > 16 {
			want = m.ErrTree
		}
		check(t, v, m.Options{}, want)
	}
	check(t, make([]any, 1000000), m.Options{}, m.ErrTree)
}
func TestTreeCycles(t *testing.T) {
	v := map[string]any{}
	v["x"] = v
	check(t, v, m.Options{}, m.ErrTree)
	a := make([]any, 1)
	a[0] = a
	check(t, a, m.Options{}, m.ErrTree)
}
func TestShape(t *testing.T) {
	localCases(t, "ErrShape", m.ErrShape)
	for _, k := range []string{"apiVersion", "kind", "metadata", "spec", "files"} {
		v := base(t)
		delete(v, k)
		check(t, v, m.Options{}, m.ErrShape)
	}
}
func TestFields(t *testing.T) { localCases(t, "ErrField", m.ErrField) }
func TestLocalBoundaries(t *testing.T) {
	v := base(t)
	v["spec"].(map[string]any)["requires"] = map[string]any{}
	check(t, v, m.Options{}, m.ErrField)
}

func TestEmptyCapabilities(t *testing.T) {
	for _, name := range []string{"console-module", "service-connector", "macos", "windows", "linux"} {
		t.Run(name, func(t *testing.T) {
			kind, field := name, "operations"
			if name == "service-connector" {
				field = "outbound"
			} else if name != "console-module" {
				kind, field = "browser-adapter", "policy_names"
			}
			v := fixture(t, kind)
			caps := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)
			if kind == "browser-adapter" {
				entry := caps["os"].(map[string]any)["linux"].(map[string]any)
				caps["os"] = map[string]any{name: entry}
				caps = entry
			}
			caps[field] = []any{}
			check(t, v, m.Options{}, nil)
		})
	}
}
func TestLocalPrecedence(t *testing.T) {
	for i := 0; i < 40; i++ {
		v := base(t)
		v["spec"].(map[string]any)["requires"] = map[string]any{}
		v["metadata"].(map[string]any)["id"] = "io.ricevanta"
		check(t, v, m.Options{}, m.ErrField)
		v["unknown"] = true
		check(t, v, m.Options{}, m.ErrShape)
		v["unknown"] = nil
		check(t, v, m.Options{}, m.ErrTree)
	}
}
func TestNoMutation(t *testing.T) {
	v := base(t)
	before, _ := json.Marshal(v)
	check(t, v, m.Options{}, nil)
	after, _ := json.Marshal(v)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("input changed")
	}
}

// A test-only schema walk exercises each local keyword on complete corpus trees.
func TestLocalSchemaInventory(t *testing.T) {
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
	if e != nil {
		t.Fatal(e)
	}
	var schema map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&schema); e != nil {
		t.Fatal(e)
	}
	for _, c := range cases(t) {
		if c.Error != "ok" {
			continue
		}
		t.Run(c.Name, func(t *testing.T) { walkSchema(t, schema, schema, c.Manifest, c.Manifest, nil) })
	}
}
func clone(v any) any {
	b, _ := json.Marshal(v)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out any
	if e := d.Decode(&out); e != nil {
		panic(e)
	}
	return out
}
func replace(root map[string]any, path []any, value any) map[string]any {
	r := clone(root).(map[string]any)
	if len(path) == 0 {
		return value.(map[string]any)
	}
	var v any = r
	for _, k := range path[:len(path)-1] {
		switch k := k.(type) {
		case string:
			v = v.(map[string]any)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	switch k := path[len(path)-1].(type) {
	case string:
		v.(map[string]any)[k] = value
	case int:
		v.([]any)[k] = value
	}
	return r
}
func walkSchema(t *testing.T, defs, s map[string]any, v any, root map[string]any, path []any) {
	t.Helper()
	if ref, ok := s["$ref"].(string); ok {
		s = defs["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
	}
	if branches, ok := s["oneOf"].([]any); ok {
		obj := v.(map[string]any)
		for _, b := range branches {
			candidate := b.(map[string]any)
			props := candidate["properties"].(map[string]any)
			if props["kind"].(map[string]any)["const"] != obj["kind"] {
				continue
			}
			iface := props["interface"].(map[string]any)
			if c, ok := iface["const"]; ok && c != obj["interface"] {
				continue
			}
			s = candidate
			break
		}
	}
	mutate := func(label string, value any, want error) {
		t.Run(label, func(t *testing.T) {
			check(t, replace(root, path, value), m.Options{AllowReservedID: true, MaxTotalFileBytes: m.HardMaxTotalFileBytes}, want)
		})
	}
	switch x := v.(type) {
	case map[string]any:
		bad := clone(x).(map[string]any)
		bad["unknown"] = true
		mutate("unknown", bad, m.ErrShape)
		if required, ok := s["required"].([]any); ok {
			for _, key := range required {
				bad := clone(x).(map[string]any)
				delete(bad, key.(string))
				mutate("missing-"+key.(string), bad, m.ErrShape)
			}
		}
		if _, ok := s["minProperties"]; ok {
			mutate("empty-object", map[string]any{}, m.ErrField)
		}
		props := s["properties"].(map[string]any)
		for k, v := range x {
			walkSchema(t, defs, props[k].(map[string]any), v, root, append(append([]any{}, path...), k))
		}
	case []any:
		min, _ := s["minItems"].(json.Number)
		max, _ := s["maxItems"].(json.Number)
		if min != "" && min != "0" {
			mutate("empty-array", []any{}, m.ErrField)
		} else {
			mutate("empty-array", []any{}, nil)
		}
		if max != "" && len(x) > 0 {
			n, _ := max.Int64()
			bad := make([]any, int(n)+1)
			for i := range bad {
				bad[i] = clone(x[0])
			}
			mutate("array-over", bad, m.ErrField)
		}
		if len(x) > 0 {
			mutate("duplicate", []any{x[0], clone(x[0])}, m.ErrField)
			for i, v := range x {
				walkSchema(t, defs, s["items"].(map[string]any), v, root, append(append([]any{}, path...), i))
			}
		}
	case string:
		if _, ok := s["const"]; ok {
			want := m.ErrField
			if len(path) >= 4 && path[0] == "spec" && path[1] == "components" && (path[len(path)-1] == "kind" || path[len(path)-1] == "interface") {
				want = m.ErrShape
			}
			mutate("constant", x+"x", want)
		}
		if values, ok := s["enum"].([]any); ok {
			mutate("enum-invalid", "getDeviceSoftware", m.ErrField)
			for _, allowed := range values {
				doc := replace(root, path, allowed)
				err := m.Validate(doc, m.Options{AllowReservedID: true, MaxTotalFileBytes: m.HardMaxTotalFileBytes})
				if errors.Is(err, m.ErrField) || errors.Is(err, m.ErrShape) {
					t.Fatalf("enum %v rejected: %v", allowed, err)
				}
			}
		}
		if max, ok := s["maxLength"].(json.Number); ok {
			n, _ := max.Int64()
			mutate("string-over", strings.Repeat("a", int(n)+1), m.ErrField)
		}
		if min, ok := s["minLength"].(json.Number); ok && min != "0" {
			mutate("string-empty", "", m.ErrField)
		}
		if _, ok := s["pattern"]; ok {
			mutate("pattern-newline", x+"\n", m.ErrField)
		}
	case json.Number:
		max := s["maximum"].(json.Number)
		n, _ := max.Int64()
		mutate("number-over", json.Number(fmt.Sprint(n+1)), m.ErrField)
		min := s["minimum"].(json.Number)
		low, _ := min.Int64()
		if low > 0 {
			mutate("number-under", json.Number(fmt.Sprint(low-1)), m.ErrField)
		}
		for _, boundary := range []json.Number{min, max} {
			doc := replace(root, path, boundary)
			err := m.Validate(doc, m.Options{AllowReservedID: true, MaxTotalFileBytes: m.HardMaxTotalFileBytes})
			if errors.Is(err, m.ErrField) {
				t.Fatalf("numeric boundary rejected: %v", err)
			}
		}
	}
	if len(path) > 0 {
		var wrong any = true
		switch v.(type) {
		case bool:
			wrong = "true"
		}
		mutate("wrong-type", wrong, m.ErrShape)
	}
}

func TestLocalContainerBounds(t *testing.T) {
	for _, c := range cases(t) {
		if c.Error != "ok" {
			continue
		}
		v := c.Manifest
		spec := v["spec"].(map[string]any)
		components := spec["components"].([]any)
		component := components[0].(map[string]any)
		for _, n := range []int{1, 64, 65} {
			doc := clone(v).(map[string]any)
			items := make([]any, n)
			for i := range items {
				x := clone(component).(map[string]any)
				x["name"] = fmt.Sprintf("component%d", i)
				items[i] = x
			}
			doc["spec"].(map[string]any)["components"] = items
			err := m.Validate(doc, m.Options{AllowReservedID: true})
			if n == 65 {
				if !errors.Is(err, m.ErrField) {
					t.Fatalf("components cap+1: %v", err)
				}
			} else if errors.Is(err, m.ErrField) || errors.Is(err, m.ErrTree) {
				t.Fatalf("components %d: %v", n, err)
			}
		}
		break
	}
	for _, n := range []int{1, 4096, 4097} {
		v := base(t)
		files := make([]any, n)
		paths := make([]any, n)
		for i := range files {
			p := fmt.Sprintf("f%d", i)
			paths[i] = p
			files[i] = map[string]any{"path": p, "sha256": strings.Repeat("0", 64), "size": json.Number("0")}
		}
		v["files"] = files
		component := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		component["files"] = paths
		component["file"] = paths[0]
		err := m.Validate(v, m.Options{})
		if n == 4097 {
			if !errors.Is(err, m.ErrField) {
				t.Fatalf("files cap+1: %v", err)
			}
		} else if err != nil {
			t.Fatalf("files %d: %v", n, err)
		}
	}
}
func TestLocalStringBounds(t *testing.T) {
	for _, n := range []int{127, 128, 129} {
		v := base(t)
		v["metadata"].(map[string]any)["publisher"].(map[string]any)["name"] = strings.Repeat("é", n)
		want := error(nil)
		if n == 129 {
			want = m.ErrField
		}
		check(t, v, m.Options{}, want)
	}
	for _, n := range []int{127, 128, 129} {
		v := base(t)
		v["metadata"].(map[string]any)["version"] = "1.0.0-" + strings.Repeat("a", n-6)
		want := error(nil)
		if n == 129 {
			want = m.ErrField
		}
		check(t, v, m.Options{}, want)
	}
	for _, n := range []int{239, 240, 241} {
		v := base(t)
		p := strings.Repeat("a", 59) + "/" + strings.Repeat("b", 59) + "/" + strings.Repeat("c", 59) + "/" + strings.Repeat("d", n-180)
		v["files"].([]any)[0].(map[string]any)["path"] = p
		c := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		c["file"] = p
		c["files"] = []any{p}
		want := error(nil)
		if n == 241 {
			want = m.ErrField
		}
		check(t, v, m.Options{}, want)
	}
}

func TestLocalOperationAndEmptyObjects(t *testing.T) {
	for _, c := range cases(t) {
		if c.Name == "console-module" {
			for _, ops := range [][]any{{"listDeviceSoftware"}, {"getDeviceSoftware"}, {"listDeviceSoftware", "getDeviceSoftware"}} {
				v := clone(c.Manifest).(map[string]any)
				v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)["operations"] = ops
				want := error(nil)
				if len(ops) > 1 || ops[0] == "getDeviceSoftware" {
					want = m.ErrField
				}
				check(t, v, m.Options{}, want)
			}
		}
		if c.Name == "browser-adapter" {
			v := c.Manifest
			v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)["os"] = map[string]any{}
			check(t, v, m.Options{}, m.ErrField)
			v["metadata"].(map[string]any)["id"] = "io.ricevanta"
			check(t, v, m.Options{}, m.ErrField)
			v["unknown"] = true
			check(t, v, m.Options{}, m.ErrShape)
		}
	}
}

func TestLocalIndependentArrayCaps(t *testing.T) {
	for _, scope := range []string{"package", "component"} {
		for _, n := range []int{4095, 4096, 4097} {
			v := base(t)
			items := make([]any, n)
			for i := range items {
				p := fmt.Sprintf("f%d", i)
				if scope == "package" {
					items[i] = map[string]any{"path": p, "sha256": strings.Repeat("0", 64), "size": json.Number("0")}
				} else {
					items[i] = p
				}
			}
			if scope == "package" {
				v["files"] = items
			} else {
				v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["files"] = items
			}
			err := m.Validate(v, m.Options{})
			if n == 4097 {
				if !errors.Is(err, m.ErrField) {
					t.Fatalf("%s %d: %v", scope, n, err)
				}
			} else if errors.Is(err, m.ErrTree) || errors.Is(err, m.ErrShape) || errors.Is(err, m.ErrField) {
				t.Fatalf("%s %d local rejection: %v", scope, n, err)
			}
		}
	}
	for _, c := range cases(t) {
		if c.Error != "ok" {
			continue
		}
		var field string
		var cap int
		switch c.Name {
		case "parser":
			field = "mime_types"
			cap = 32
		case "service-connector":
			field = "outbound"
			cap = 64
		case "browser-adapter":
			field = "policy_names"
			cap = 64
		default:
			continue
		}
		for _, n := range []int{cap - 1, cap, cap + 1} {
			v := clone(c.Manifest).(map[string]any)
			target := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)
			items := make([]any, n)
			for i := range items {
				switch field {
				case "mime_types":
					items[i] = fmt.Sprintf("application/x%d", i)
				case "outbound":
					items[i] = map[string]any{"host": fmt.Sprintf("h%d.example", i), "port": json.Number("1"), "transport": "tcp"}
				case "policy_names":
					items[i] = fmt.Sprintf("Policy%d", i)
				}
			}
			if field == "policy_names" {
				target = target["os"].(map[string]any)["linux"].(map[string]any)
			}
			target[field] = items
			want := error(nil)
			if n == cap+1 {
				want = m.ErrField
			}
			check(t, v, m.Options{}, want)
		}
	}
}
func TestTreeMapBudgets(t *testing.T) {
	for _, extra := range []int{0, 1, 2} {
		v := make(map[string]any, 32767)
		for i := 0; i < 32767; i++ {
			v[fmt.Sprint(i)] = true
		}
		if extra > 0 {
			a := make([]any, extra)
			for i := range a {
				a[i] = true
			}
			v["0"] = a
		}
		want := m.ErrShape
		if extra == 2 {
			want = m.ErrTree
		}
		check(t, v, m.Options{}, want)
	}
	v := base(t)
	v[strings.Repeat("a", m.MaxManifestBytes+1)] = true
	check(t, v, m.Options{}, m.ErrTree)
}

func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	for _, c := range cases(t) {
		if c.Name == name {
			return c.Manifest
		}
	}
	t.Fatal("fixture absent: " + name)
	return nil
}
func dotted(n int) string {
	return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", n-192)
}
func TestLocalEveryStringCap(t *testing.T) {
	tests := []struct {
		name  string
		cap   int
		path  []any
		value func(int) string
		exact bool
	}{
		{"content", 253, []any{"metadata", "id"}, dotted, false},
		{"browser-adapter", 253, []any{"spec", "components", 0, "capabilities", "registration"}, dotted, false},
		{"content", 63, []any{"spec", "components", 0, "name"}, func(n int) string { return strings.Repeat("a", n) }, false},
		{"content", 256, []any{"metadata", "license"}, func(n int) string { return strings.Repeat("a", n) }, false},
		{"content", 2048, []any{"metadata", "source"}, func(n int) string { p := "https://example.com/"; return p + strings.Repeat("a", n-len(p)) }, false},
		{"content", 2048, []any{"metadata", "homepage"}, func(n int) string { p := "https://example.com/"; return p + strings.Repeat("a", n-len(p)) }, false},
		{"parser", 127, []any{"spec", "components", 0, "capabilities", "mime_types", 0}, func(n int) string { return "a/" + strings.Repeat("b", n-2) }, false},
		{"service-connector", 253, []any{"spec", "components", 0, "capabilities", "outbound", 0, "host"}, dotted, false},
		{"browser-adapter", 64, []any{"spec", "components", 0, "capabilities", "os", "linux", "policy_names", 0}, func(n int) string { return strings.Repeat("A", n) }, false},
		{"content", 71, []any{"metadata", "publisher", "key"}, func(n int) string { return "sha256:" + strings.Repeat("a", n-7) }, true},
		{"content", 64, []any{"files", 0, "sha256"}, func(n int) string { return strings.Repeat("a", n) }, true},
	}
	for _, tc := range tests {
		for _, n := range []int{tc.cap - 1, tc.cap, tc.cap + 1} {
			v := replace(fixture(t, tc.name), tc.path, tc.value(n))
			want := error(nil)
			if n > tc.cap || tc.exact && n != tc.cap {
				want = m.ErrField
			}
			check(t, v, m.Options{}, want)
		}
	}
}
func TestLocalFullEnumArrays(t *testing.T) {
	scenarios := []struct {
		name   string
		path   []any
		values []any
	}{
		{"classifier", []any{"spec", "requires", "agent-module"}, []any{"ricevanta:agent/classifier@1.0.0", "ricevanta:agent/parser@1.0.0", "ricevanta:agent/collector@1.0.0", "ricevanta:agent/responder@1.0.0"}},
		{"service-connector", []any{"spec", "requires", "service-connector"}, []any{"ext.ricevanta.io/export-destination/v1", "ext.ricevanta.io/ca-connector/v1", "ext.ricevanta.io/notifier/v1", "ext.ricevanta.io/enricher/v1"}},
		{"responder", []any{"spec", "components", 0, "capabilities", "actions"}, []any{"edr.kill_process", "edr.quarantine_file", "edr.restore_file", "edr.isolate_host", "edr.unisolate_host", "edr.kill_and_ban", "edr.unban", "edr.collect", "edr.scan"}},
		{"console-module", []any{"spec", "components", 0, "slots"}, []any{"navigation", "device-tab", "alert-panel", "finding-panel", "dashboard-panel", "settings"}},
		{"console-module", []any{"spec", "components", 0, "capabilities", "operations"}, []any{"listDevices", "getDevice", "getDeviceInventory", "listDeviceSoftware", "getDeviceCapabilities", "getDevicePolicyState", "getDeviceFootprint", "listComplianceResults", "listAlerts", "getAlert", "listInvestigations", "listResponseActions", "listDlpFindings", "getDlpFinding", "listClassifications", "listExceptions", "queryLineage", "getLineageEdge", "updateAlert", "createInvestigation", "updateInvestigation", "updateDlpFinding", "createResponseAction"}},
	}
	for _, tc := range scenarios {
		v := replace(fixture(t, tc.name), tc.path, tc.values)
		err := m.Validate(v, m.Options{})
		if errors.Is(err, m.ErrField) || errors.Is(err, m.ErrShape) || errors.Is(err, m.ErrTree) {
			t.Fatalf("full enum array rejected: %v", err)
		}
	}
	v := fixture(t, "browser-adapter")
	os := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)["os"].(map[string]any)
	for _, name := range []string{"macos", "windows"} {
		os[name] = clone(os["linux"])
	}
	check(t, v, m.Options{}, nil)
	for _, name := range []string{"macos", "windows"} {
		v := clone(v).(map[string]any)
		v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)["os"].(map[string]any)[name].(map[string]any)["unknown"] = true
		check(t, v, m.Options{}, m.ErrShape)
	}
}
func TestTreeAggregateText(t *testing.T) {
	for _, n := range []int{m.MaxManifestBytes - 1, m.MaxManifestBytes, m.MaxManifestBytes + 1} {
		v := map[string]any{"k": strings.Repeat("a", n-22), "n": json.Number("18446744073709551615")}
		want := m.ErrShape
		if n > m.MaxManifestBytes {
			want = m.ErrTree
		}
		check(t, v, m.Options{}, want)
	}
}
func TestLocalReachableMinima(t *testing.T) {
	tests := []struct {
		name  string
		path  []any
		value string
	}{
		{"content", []any{"metadata", "id"}, "a.b"}, {"browser-adapter", []any{"spec", "components", 0, "capabilities", "registration"}, "a.b"},
		{"content", []any{"metadata", "version"}, "0.0.0"}, {"content", []any{"metadata", "publisher", "name"}, "é"},
		{"content", []any{"metadata", "license"}, "A"}, {"content", []any{"metadata", "source"}, "https://a.b"},
		{"content", []any{"spec", "components", 0, "name"}, "a"}, {"content", []any{"files", 0, "path"}, "a"},
		{"parser", []any{"spec", "components", 0, "capabilities", "mime_types", 0}, "a/b"},
		{"browser-adapter", []any{"spec", "components", 0, "capabilities", "os", "linux", "policy_names", 0}, "A"},
		{"service-connector", []any{"spec", "components", 0, "capabilities", "outbound", 0, "host"}, "a.b"},
	}
	for _, tc := range tests {
		v := replace(fixture(t, tc.name), tc.path, tc.value)
		err := m.Validate(v, m.Options{})
		if errors.Is(err, m.ErrTree) || errors.Is(err, m.ErrShape) || errors.Is(err, m.ErrField) {
			t.Fatalf("minimum rejected: %v", err)
		}
	}
}

func TestReservedID(t *testing.T) {
	localCases(t, "ErrReserved", m.ErrReserved)
	for _, id := range []string{"io.ricevanta", "io.ricevanta.rules", "io.ricevantaevil.rules", "com.io.ricevanta"} {
		for _, allow := range []bool{false, true} {
			v := base(t)
			v["metadata"].(map[string]any)["id"] = id
			want := error(nil)
			if !allow && (id == "io.ricevanta" || id == "io.ricevanta.rules") {
				want = m.ErrReserved
			}
			check(t, v, m.Options{AllowReservedID: allow}, want)
		}
	}
	for _, k := range []string{"allow_reserved_id", "grants", "targets", "trust", "ownership"} {
		v := base(t)
		v[k] = true
		check(t, v, m.Options{}, m.ErrShape)
	}
}
func TestDuplicateIdentities(t *testing.T) {
	localCases(t, "ErrDuplicate", m.ErrDuplicate)
	v := base(t)
	files := v["files"].([]any)
	v["files"] = append(files, clone(files[0]))
	check(t, v, m.Options{}, m.ErrField)
}
func pathDocument(t *testing.T, p string) map[string]any {
	v := base(t)
	v["files"].([]any)[0].(map[string]any)["path"] = p
	c := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
	c["file"] = p
	c["files"] = []any{p}
	return v
}
func TestPortablePaths(t *testing.T) {
	localCases(t, "ErrPath", m.ErrPath)
	stems := []string{"con", "prn", "aux", "nul"}
	for i := 1; i <= 9; i++ {
		stems = append(stems, fmt.Sprintf("com%d", i), fmt.Sprintf("lpt%d", i))
	}
	for _, s := range stems {
		for _, suffix := range []string{"", ".txt"} {
			check(t, pathDocument(t, "data/"+s+suffix), m.Options{}, m.ErrPath)
		}
	}
	for _, p := range []string{"extension.yaml", "extension.yaml/x", "envelope.json", "envelope.json/x", strings.Repeat("a", 64), "data/name."} {
		check(t, pathDocument(t, p), m.Options{}, m.ErrPath)
	}
	check(t, pathDocument(t, strings.Repeat("a", 63)), m.Options{}, nil)
}
func TestFileTotals(t *testing.T) {
	localCases(t, "ErrLimit", m.ErrLimit)
	for _, ceiling := range []uint64{m.DefaultMaxTotalFileBytes, 10, m.HardMaxTotalFileBytes} {
		for _, size := range []uint64{ceiling - 1, ceiling, ceiling + 1} {
			v := base(t)
			v["files"].([]any)[0].(map[string]any)["size"] = json.Number(fmt.Sprint(size))
			want := error(nil)
			if size > m.HardMaxTotalFileBytes {
				want = m.ErrField
			} else if size > ceiling {
				want = m.ErrLimit
			}
			check(t, v, m.Options{MaxTotalFileBytes: ceiling}, want)
		}
	}
	check(t, base(t), m.Options{MaxTotalFileBytes: 2}, m.ErrLimit)
}
func TestRequires(t *testing.T) {
	localCases(t, "ErrRequires", m.ErrRequires)
	check(t, mixed(t), m.Options{}, nil)
}
func mixed(t *testing.T) map[string]any {
	v := base(t)
	components := []any{}
	files := []any{}
	requires := map[string]any{}
	variants := []struct{ name, iface string }{{"classifier", ""}, {"parser", ""}, {"collector", ""}, {"responder", ""}, {"service-connector", "ext.ricevanta.io/export-destination/v1"}, {"service-connector", "ext.ricevanta.io/ca-connector/v1"}, {"service-connector", "ext.ricevanta.io/notifier/v1"}, {"service-connector", "ext.ricevanta.io/enricher/v1"}}
	for i, item := range variants {
		doc := fixture(t, item.name)
		c := doc["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		c["name"] = fmt.Sprintf("c%d", i)
		if item.iface != "" {
			c["interface"] = item.iface
		}
		paths := c["files"].([]any)
		renames := map[string]string{}
		for j, p := range paths {
			renames[p.(string)] = fmt.Sprintf("c%d/f%d", i, j)
			paths[j] = renames[p.(string)]
		}
		for _, k := range []string{"file", "entry", "row_schema"} {
			if p, ok := c[k].(string); ok {
				c[k] = renames[p]
			}
		}
		for _, f := range doc["files"].([]any) {
			f := f.(map[string]any)
			f["path"] = renames[f["path"].(string)]
			files = append(files, f)
		}
		kind := c["kind"].(string)
		a, _ := requires[kind].([]any)
		requires[kind] = append(a, c["interface"])
		components = append(components, c)
	}
	v["spec"] = map[string]any{"requires": requires, "components": components}
	v["files"] = files
	return v
}
func TestFileOwnership(t *testing.T) {
	localCases(t, "ErrReference", m.ErrReference)
	for _, name := range []string{"content", "console-module", "collector"} {
		v := fixture(t, name)
		c := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		k := "file"
		if name == "console-module" {
			k = "entry"
		}
		if name == "collector" {
			k = "row_schema"
		}
		c[k] = "missing.bin"
		check(t, v, m.Options{}, m.ErrReference)
		c["files"] = append(c["files"].([]any), "missing.bin")
		check(t, v, m.Options{}, m.ErrReference)
	}
	check(t, pathDocument(t, "attestations/proof.bin"), m.Options{}, m.ErrReference)
}
func TestCapabilityRelations(t *testing.T) {
	localCases(t, "ErrCapability", m.ErrCapability)
	v := fixture(t, "collector")
	caps := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)
	caps["max_open_handles"] = json.Number("2")
	caps["max_read_requests"] = json.Number("1")
	check(t, v, m.Options{}, m.ErrCapability)
}
func TestSemanticPrecedence(t *testing.T) {
	v := pathDocument(t, "con")
	v["files"].([]any)[0].(map[string]any)["size"] = json.Number("67108865")
	check(t, v, m.Options{}, m.ErrPath)
	v = base(t)
	v["files"].([]any)[0].(map[string]any)["size"] = json.Number("67108865")
	v["spec"].(map[string]any)["requires"] = map[string]any{"agent-module": []any{"ricevanta:agent/classifier@1.0.0"}}
	check(t, v, m.Options{}, m.ErrLimit)
	v = fixture(t, "collector")
	c := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
	c["row_schema"] = "missing.bin"
	caps := c["capabilities"].(map[string]any)
	caps["max_bytes_per_file"] = json.Number("2")
	caps["max_input_bytes"] = json.Number("1")
	check(t, v, m.Options{}, m.ErrReference)
}
func TestFileTotalsMultipleAndDefault(t *testing.T) {
	for _, total := range []uint64{m.DefaultMaxTotalFileBytes - 1, m.DefaultMaxTotalFileBytes, m.DefaultMaxTotalFileBytes + 1} {
		v := base(t)
		v["files"].([]any)[0].(map[string]any)["size"] = json.Number(fmt.Sprint(total / 2))
		v["files"] = append(v["files"].([]any), map[string]any{"path": "attestations/proof.bin", "size": json.Number(fmt.Sprint(total - total/2)), "sha256": strings.Repeat("0", 64)})
		want := error(nil)
		if total > m.DefaultMaxTotalFileBytes {
			want = m.ErrLimit
		}
		check(t, v, m.Options{}, want)
	}
}
func TestPortablePrefixOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		v := pathDocument(t, "a/b")
		a := v["files"].([]any)
		a = append(a, map[string]any{"path": "a/b/c", "size": json.Number("0"), "sha256": strings.Repeat("0", 64)})
		if reverse {
			a[0], a[1] = a[1], a[0]
		}
		v["files"] = a
		check(t, v, m.Options{}, m.ErrPath)
	}
	check(t, pathDocument(t, "attestations"), m.Options{}, nil)
	check(t, pathDocument(t, "extension.yamlx"), m.Options{}, nil)
}
func TestRequiresOrder(t *testing.T) {
	v := mixed(t)
	requires := v["spec"].(map[string]any)["requires"].(map[string]any)
	for _, a := range requires {
		x := a.([]any)
		for i, j := 0, len(x)-1; i < j; i, j = i+1, j-1 {
			x[i], x[j] = x[j], x[i]
		}
	}
	check(t, v, m.Options{}, nil)
}
func TestRequiresMissingAndSubstituted(t *testing.T) {
	v := mixed(t)
	r := v["spec"].(map[string]any)["requires"].(map[string]any)
	r["agent-module"] = r["agent-module"].([]any)[:3]
	check(t, v, m.Options{}, m.ErrRequires)
	v = mixed(t)
	delete(v["spec"].(map[string]any)["requires"].(map[string]any), "service-connector")
	check(t, v, m.Options{}, m.ErrRequires)
	v = mixed(t)
	s := v["spec"].(map[string]any)
	a := s["components"].([]any)
	s["components"] = append(a[:2], a[3:]...)
	files := []any{}
	for _, f := range v["files"].([]any) {
		if !strings.HasPrefix(f.(map[string]any)["path"].(string), "c2/") {
			files = append(files, f)
		}
	}
	v["files"] = files
	r = s["requires"].(map[string]any)
	r["agent-module"] = []any{"ricevanta:agent/classifier@1.0.0", "ricevanta:agent/parser@1.0.0", "ricevanta:agent/responder@1.0.0"}
	check(t, v, m.Options{}, nil)
	r["agent-module"] = []any{"ricevanta:agent/classifier@1.0.0", "ricevanta:agent/collector@1.0.0", "ricevanta:agent/responder@1.0.0"}
	check(t, v, m.Options{}, m.ErrRequires)
}
func TestSemanticDuplicateBeforePath(t *testing.T) {
	v := base(t)
	a := v["files"].([]any)
	duplicate := clone(a[0]).(map[string]any)
	duplicate["size"] = json.Number("4")
	v["files"] = append(a, duplicate, map[string]any{"path": "con.txt", "size": json.Number("0"), "sha256": strings.Repeat("0", 64)})
	check(t, v, m.Options{}, m.ErrDuplicate)
}

func TestLicenseExpression(t *testing.T) {
	for _, s := range []string{"MIT", "GPL-2.0+", "MIT AND Apache-2.0", "MIT OR Apache-2.0 AND BSD-3-Clause", "(MIT OR Apache-2.0) AND BSD-3-Clause", "GPL-2.0+ WITH Classpath-exception-2.0", "LicenseRef-local", "DocumentRef-doc:LicenseRef-local", "LicenseRef-AND", strings.Repeat("(", 8) + "MIT" + strings.Repeat(")", 8)} {
		v := base(t)
		v["metadata"].(map[string]any)["license"] = s
		check(t, v, m.Options{}, nil)
	}
	for _, s := range []string{"AND", "OR", "WITH", "NONE", "NOASSERTION", "MIT AND", "MIT  AND Apache-2.0", " MIT", "MIT ", "()", "LicenseRef-", "DocumentRef-:LicenseRef-a", "DocumentRef-doc:LicenseRef-", "LicenseRef-a+", "LicenseRef-a WITH Exception", "(MIT) WITH Exception", "MIT WITH LicenseRef-a", "MIT WITH DocumentRef-a", "MIT++", strings.Repeat("(", 9) + "MIT" + strings.Repeat(")", 9)} {
		v := base(t)
		v["metadata"].(map[string]any)["license"] = s
		check(t, v, m.Options{}, m.ErrLicense)
	}
}
func TestMetadataURL(t *testing.T) {
	for _, key := range []string{"source", "homepage"} {
		for _, s := range []string{"https://example.com/a%20b?q=%2F", "https://example.com:65535", "https://" + dotted(253)} {
			v := base(t)
			v["metadata"].(map[string]any)[key] = s
			check(t, v, m.Options{}, nil)
		}
		for _, s := range []string{"https://127.0.0.1", "https://example.com:65536", "https://example.com/a%GG", "https://example.com/?q=%", "https://" + dotted(254)} {
			v := base(t)
			v["metadata"].(map[string]any)[key] = s
			check(t, v, m.Options{}, m.ErrURL)
		}
	}
}
func TestAllStagePrecedence(t *testing.T) {
	defects := []struct {
		want  error
		apply func(map[string]any, *m.Options)
	}{
		{m.ErrOptions, func(v map[string]any, o *m.Options) { o.MaxTotalFileBytes = math.MaxUint64 }},
		{m.ErrTree, func(v map[string]any, o *m.Options) { v["tree-defect"] = nil }},
		{m.ErrShape, func(v map[string]any, o *m.Options) { v["shape-defect"] = true }},
		{m.ErrField, func(v map[string]any, o *m.Options) {
			v["metadata"].(map[string]any)["publisher"].(map[string]any)["name"] = ""
		}},
		{m.ErrReserved, func(v map[string]any, o *m.Options) { v["metadata"].(map[string]any)["id"] = "io.ricevanta" }},
		{m.ErrDuplicate, func(v map[string]any, o *m.Options) {
			a := v["files"].([]any)
			f := clone(a[0]).(map[string]any)
			f["size"] = json.Number("4")
			v["files"] = append(a, f)
		}},
		{m.ErrPath, func(v map[string]any, o *m.Options) {
			v["files"] = append(v["files"].([]any), map[string]any{"path": "con.bin", "size": json.Number("0"), "sha256": strings.Repeat("0", 64)})
		}},
		{m.ErrLimit, func(v map[string]any, o *m.Options) {
			v["files"].([]any)[0].(map[string]any)["size"] = json.Number("67108865")
		}},
		{m.ErrRequires, func(v map[string]any, o *m.Options) {
			v["spec"].(map[string]any)["requires"].(map[string]any)["agent-module"] = []any{"ricevanta:agent/classifier@1.0.0"}
		}},
		{m.ErrReference, func(v map[string]any, o *m.Options) {
			v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["row_schema"] = "missing.bin"
		}},
		{m.ErrCapability, func(v map[string]any, o *m.Options) {
			c := v["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["capabilities"].(map[string]any)
			c["max_bytes_per_file"] = json.Number("2")
			c["max_input_bytes"] = json.Number("1")
		}},
		{m.ErrLicense, func(v map[string]any, o *m.Options) { v["metadata"].(map[string]any)["license"] = "MIT AND" }},
		{m.ErrURL, func(v map[string]any, o *m.Options) {
			v["metadata"].(map[string]any)["source"] = "https://example.com/%GG"
		}},
	}
	for i, first := range defects {
		for j := i + 1; j < len(defects); j++ {
			t.Run(fmt.Sprintf("%d-before-%d", i+1, j+1), func(t *testing.T) {
				v := fixture(t, "collector")
				o := m.Options{}
				first.apply(v, &o)
				defects[j].apply(v, &o)
				check(t, v, o, first.want)
				check(t, clone(v), o, first.want)
			})
		}
	}
}
func TestErrorText(t *testing.T) {
	for _, secret := range []string{"PRIVATE-PUBLISHER-SECRET", "PRIVATE\nCONTROL"} {
		v := base(t)
		v[secret] = true
		err := m.Validate(v, m.Options{})
		if err == nil || strings.Contains(err.Error(), secret) || strings.ContainsAny(err.Error(), "\r\n\x00") {
			t.Fatalf("unsafe error text: %v", err)
		}
		count := 0
		for _, sentinel := range sentinels() {
			if sentinel != nil && errors.Is(err, sentinel) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("error wraps %d sentinels", count)
		}
	}
}
func TestErrorTextValues(t *testing.T) {
	secret := "PRIVATE-PUBLISHER-SECRET"
	v := base(t)
	v["metadata"].(map[string]any)["publisher"].(map[string]any)["name"] = secret + "\n"
	err := m.Validate(v, m.Options{})
	if !errors.Is(err, m.ErrField) || strings.Contains(err.Error(), secret) || strings.ContainsAny(err.Error(), "\n\r") {
		t.Fatalf("unsafe field error: %v", err)
	}
	v = base(t)
	v["metadata"].(map[string]any)["source"] = "https://example.com/?token=" + secret + "%GG"
	err = m.Validate(v, m.Options{})
	if !errors.Is(err, m.ErrURL) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe URL error: %v", err)
	}
}
