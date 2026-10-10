package reportvalidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func assertError(t testing.TB, e error, cause error, path, rule string) {
	t.Helper()
	var x *Error
	if !errors.Is(e, cause) || !errors.As(e, &x) || x.Path != path || x.Rule != rule || x.Error() != "report validation "+rule {
		t.Fatalf("error got %#v want %v %s %s", e, cause, path, rule)
	}
}
func TestUnavailableCatalogue(t *testing.T) {
	for _, c := range []*Catalogue{nil, {}} {
		r, e := Validate(map[string]any{"x": make([]any, 9000)}, c)
		assertError(t, e, ErrCatalogue, "", "catalogue")
		if r.Name != "" || r.Sources != nil || r.CatalogueRevision != 0 {
			t.Fatal("partial result")
		}
	}
}

type hostile struct{}

func (hostile) MarshalJSON() ([]byte, error) { panic("called marshaler") }
func TestInputDomain(t *testing.T) {
	c, _ := Builtin()
	for _, x := range []any{int(1), json.Number("1"), hostile{}, new(int), math.NaN(), math.Inf(1), float64(9007199254740992), map[string]any(nil), []any(nil), "\xff"} {
		_, e := Validate(map[string]any{"x": x}, c)
		assertError(t, e, ErrInput, "/x", "input")
	}
	_, e := Validate(nil, c)
	assertError(t, e, ErrEnvelope, "", "envelope")
}
func TestErrorRedaction(t *testing.T) {
	c, _ := Builtin()
	_, e := Validate(map[string]any{"secret/~": int(1)}, c)
	assertError(t, e, ErrInput, "/secret~1~0", "input")
	if strings.Contains(e.Error(), "secret") {
		t.Fatal("leak")
	}
}
func TestBranches(t *testing.T) {
	c, _ := Builtin()
	for _, f := range fixtures(t) {
		if f.Sentinel == "ErrSchema" && (strings.HasPrefix(f.ID, "reference-") || f.ID == "condition-empty-object") {
			_, e := Validate(f.Document, c)
			assertError(t, e, ErrSchema, f.Path, "schema")
		}
	}
}
func TestParameterReferences(t *testing.T) {
	c, _ := Builtin()
	for _, f := range fixtures(t) {
		if f.ID == "cross-source-enum" || f.ID == "enum-field-not-enum-with-default" || f.ID == "enum-field-not-enum-no-default" || f.ID == "unknown-param" {
			_, e := Validate(f.Document, c)
			assertError(t, e, ErrSemantic, f.Path, f.Rule)
		}
	}
}
func TestOutputReferences(t *testing.T) {
	c, _ := Builtin()
	for _, f := range fixtures(t) {
		if f.Rule == "output" {
			_, e := Validate(f.Document, c)
			assertError(t, e, ErrSemantic, f.Path, "output")
		}
	}
}
func TestErrorPrecedence(t *testing.T) {
	c, _ := Builtin()
	for _, f := range fixtures(t) {
		if strings.Contains(f.ID, "-before-") {
			for i := 0; i < 20; i++ {
				_, e := Validate(f.Document, c)
				cause := ErrSemantic
				if f.Sentinel == "ErrSchema" {
					cause = ErrSchema
				}
				if f.Sentinel == "ErrEnvelope" {
					cause = ErrEnvelope
				}
				assertError(t, e, cause, f.Path, f.Rule)
			}
		}
	}
}
func TestNoMutation(t *testing.T) {
	c, _ := Builtin()
	d := base("pki.certificates")
	before, _ := json.Marshal(d)
	Validate(d, c)
	after, _ := json.Marshal(d)
	if string(before) != string(after) {
		t.Fatal("mutation")
	}
}
func TestDetachedResult(t *testing.T) {
	c, _ := Builtin()
	d := base("pki.certificates")
	r, e := Validate(d, c)
	if e != nil {
		t.Fatal(e)
	}
	r.Sources[0].ConditionalReads[0].Permission = "changed"
	r, e = Validate(d, c)
	if e != nil || r.Sources[0].ConditionalReads[0].Permission != "pki.infrastructure.read" {
		t.Fatal("alias")
	}
}
func TestConcurrent(t *testing.T) {
	c, _ := Builtin()
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { _, e := Validate(base("devices"), c); done <- e }()
	}
	for i := 0; i < 16; i++ {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}

func TestGeneratedParameters(t *testing.T) {
	c, _ := Builtin()
	cases := []struct {
		kind        string
		def         any
		field, site string
		operand     string
	}{
		{"string", "x", "", "component", "prefix"},
		{"enum_list", []any{"high"}, "dlp.findings/severity", "severity", "in"},
		{"time_range", map[string]any{"start": "2024-02-29T00:00:00Z", "end": "2024-03-01T00:00:00Z"}, "", "occurred_at", "between"},
		{"device_groups", []any{"group-a"}, "", "device_groups", ""},
	}
	for _, x := range cases {
		for _, hasDefault := range []bool{false, true} {
			source := "dlp.findings"
			if x.kind == "string" {
				source = "agents.health"
			}
			d := base(source)
			p := map[string]any{"name": "p", "type": x.kind}
			if x.field != "" {
				p["field"] = x.field
			}
			if hasDefault {
				p["default"] = x.def
			}
			d["spec"].(map[string]any)["parameters"] = []any{p}
			ref := map[string]any{"param": "p"}
			var operand any = ref
			if x.operand != "" {
				operand = map[string]any{x.operand: ref}
			}
			dataset(d)["filter"].(map[string]any)[x.site] = operand
			if _, e := Validate(d, c); e != nil {
				t.Fatalf("positive %s %v", x.kind, e)
			}
			if x.kind == "enum_list" {
				p["field"] = "edr.alerts/severity"
				_, e := Validate(d, c)
				assertError(t, e, ErrSemantic, "/spec/datasets/0/filter/severity/in", "compatibility")
			}
			if x.kind == "string" {
				dataset(d)["filter"].(map[string]any)[x.site] = map[string]any{"in": ref}
				_, e := Validate(d, c)
				assertError(t, e, ErrSemantic, "/spec/datasets/0/filter/component/in", "compatibility")
			}
			if x.kind == "time_range" {
				dataset(d)["filter"] = map[string]any{"time": ref}
				if _, e := Validate(d, c); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
}
func TestGeneratedOutputShapes(t *testing.T) {
	c, _ := Builtin()
	for _, chart := range []string{"bar", "stacked_bar", "line", "area", "pie", "heatmap"} {
		d := base("dlp.findings")
		groups := []any{"severity"}
		x := "severity"
		if chart == "line" || chart == "area" {
			groups = []any{"occurred_at"}
			x = "occurred_at"
		}
		block := map[string]any{"type": "chart", "chart": chart, "dataset": "data", "x": x, "y": "rows"}
		if chart == "stacked_bar" || chart == "heatmap" {
			groups = append(groups, "channel")
			block["series"] = "channel"
		}
		dataset(d)["group_by"] = groups
		d["spec"].(map[string]any)["layout"] = []any{block}
		if _, e := Validate(d, c); e != nil {
			t.Fatal(e)
		}
		block["y"] = "severity"
		_, e := Validate(d, c)
		assertError(t, e, ErrSemantic, "/spec/layout/0/y", "output")
		block["y"] = "rows"
		block["x"] = "device_uid"
		_, e = Validate(d, c)
		assertError(t, e, ErrSemantic, "/spec/layout/0/x", "output")
	}
}
func TestIndexOrder(t *testing.T) {
	c, _ := Builtin()
	d := base("devices")
	blocks := []any{}
	for i := 0; i < 12; i++ {
		text := map[string]any{"en": "a", "vi": "a"}
		if i == 2 || i == 10 {
			delete(text, "vi")
		}
		blocks = append(blocks, map[string]any{"type": "text", "text": text})
	}
	d["spec"].(map[string]any)["layout"] = blocks
	for i := 0; i < 50; i++ {
		_, e := Validate(d, c)
		assertError(t, e, ErrSchema, "/spec/layout/2/text/vi", "schema")
	}
}

func TestStructuralCaps(t *testing.T) {
	for _, x := range []struct {
		key     string
		lo, cap int
	}{{"parameters", 0, 16}, {"datasets", 1, 10}, {"layout", 1, 64}, {"measures", 1, 8}, {"group_by", 1, 3}, {"order_by", 1, 11}, {"columns", 1, 11}, {"filter", 0, 32}, {"groups", 1, 64}, {"enum", 1, 64}, {"in", 1, 64}, {"between", 2, 2}} {
		for _, n := range []int{0, 1, x.cap, x.cap + 1} {
			d := base("dlp.findings")
			s := d["spec"].(map[string]any)
			a := []any{}
			for i := 0; i < n; i++ {
				name := fmt.Sprintf("v%d", i)
				switch x.key {
				case "parameters":
					a = append(a, map[string]any{"name": name, "type": "string"})
				case "datasets":
					m := dataset(base("dlp.findings"))
					m["name"] = name
					a = append(a, m)
				case "layout":
					a = append(a, map[string]any{"type": "text", "text": map[string]any{"en": "a", "vi": "a"}})
				case "measures":
					a = append(a, map[string]any{"name": name, "fn": "count"})
				case "order_by":
					a = append(a, map[string]any{"field": name})
				default:
					a = append(a, name)
				}
			}
			switch x.key {
			case "parameters", "datasets", "layout":
				s[x.key] = a
			case "measures", "group_by", "order_by":
				dataset(d)[x.key] = a
			case "columns":
				s["layout"].([]any)[0].(map[string]any)["columns"] = a
			case "filter":
				m := map[string]any{}
				for _, key := range a {
					m[key.(string)] = true
				}
				dataset(d)["filter"] = m
			case "groups":
				dataset(d)["filter"].(map[string]any)["device_groups"] = a
			case "enum":
				s["parameters"] = []any{map[string]any{"name": "p", "type": "enum_list", "field": "dlp.findings/severity", "default": a}}
			case "in", "between":
				dataset(d)["filter"].(map[string]any)["channel"] = map[string]any{x.key: a}
			}
			e := structural(d)
			if (e == nil) != (n >= x.lo && n <= x.cap) {
				t.Fatalf("%s=%d: %v", x.key, n, e)
			}
		}
	}
	for _, x := range []struct {
		key     string
		lo, cap int
	}{{"name", 1, 63}, {"description", 0, 1024}, {"title", 1, 256}, {"text", 1, 4096}, {"scalar", 0, 256}, {"identifier", 1, 32}} {
		for _, n := range []int{0, 1, x.cap, x.cap + 1} {
			d := base("devices")
			s := d["spec"].(map[string]any)
			value := strings.Repeat("a", n)
			switch x.key {
			case "name", "description":
				d["metadata"].(map[string]any)[x.key] = value
			case "title":
				s["title"].(map[string]any)["en"] = value
			case "text":
				s["layout"] = []any{map[string]any{"type": "text", "text": map[string]any{"en": value, "vi": "a"}}}
			case "scalar":
				dataset(d)["filter"].(map[string]any)["device_uid"] = value
			case "identifier":
				dataset(d)["name"] = value
			}
			var e *Error
			if x.key == "name" || x.key == "description" {
				e = envelope(d)
			} else {
				e = structural(d)
			}
			valid := e == nil
			if valid != (n >= x.lo && n <= x.cap) {
				t.Fatalf("%s length %d: %v", x.key, n, e)
			}
		}
	}
}

func TestLiteralCompatibilityPairs(t *testing.T) {
	c, _ := Builtin()
	for id, s := range c.sources {
		for name, f := range s.fields {
			var value any
			switch f.kind {
			case "string":
				value = "x"
			case "enum":
				value = f.values[0]
			case "boolean":
				value = true
			case "integer":
				value = float64(0)
			case "number":
				value = 0.5
			case "timestamp":
				value = "2024-02-29T00:00:00Z"
			}
			for _, op := range f.operators {
				d := base(id)
				operand := value
				if op == "in" || op == "not_in" {
					operand = []any{value}
				}
				if op == "between" {
					operand = []any{value, value}
				}
				if op == "exists" {
					operand = true
				}
				filter := dataset(d)["filter"].(map[string]any)
				filter[name] = map[string]any{op: operand}
				if _, e := Validate(d, c); e != nil {
					t.Fatal(e)
				}
				var wrong any = false
				if f.kind == "boolean" {
					wrong = float64(1)
				}
				path := "/spec/datasets/0/filter/" + name + "/" + op
				if op == "in" || op == "not_in" {
					wrong = []any{wrong}
					path += "/0"
				}
				if op == "between" {
					wrong = []any{wrong, value}
					path += "/0"
				}
				if op == "exists" {
					wrong = float64(1)
				}
				filter[name] = map[string]any{op: wrong}
				_, e := Validate(d, c)
				cause, rule := ErrSemantic, "compatibility"
				if op == "exists" {
					cause, rule = ErrSchema, "schema"
				}
				assertError(t, e, cause, path, rule)
			}
		}
	}
}

func TestRandomizedInsertion(t *testing.T) {
	c, _ := Builtin()
	random := rand.New(rand.NewSource(7))
	var shuffle func(any) any
	shuffle = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			order := keys(x)
			random.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			for _, k := range order {
				out[k] = shuffle(x[k])
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, y := range x {
				out[i] = shuffle(y)
			}
			return out
		default:
			return v
		}
	}
	for _, f := range fixtures(t) {
		if f.Accepted {
			continue
		}
		for i := 0; i < 10; i++ {
			d := shuffle(f.Document).(map[string]any)
			_, e := Validate(d, c)
			var got *Error
			if !errors.As(e, &got) || got.Path != f.Path || got.Rule != f.Rule {
				t.Fatalf("insertion order changed %s: %v", f.ID, e)
			}
		}
	}
}
