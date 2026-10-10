package reportvalidate

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

type fixture struct {
	ID                   string `json:"id"`
	Structural, Accepted bool
	Sentinel, Path, Rule string
	Document             map[string]any
}

func fixtures(t testing.TB) []fixture {
	t.Helper()
	var a []fixture
	if e := json.Unmarshal(canonical(t, "schemas/report/v1alpha1/fixtures/templates.json"), &a); e != nil {
		t.Fatal(e)
	}
	if len(a) != 83 {
		t.Fatalf("fixture inventory %d", len(a))
	}
	seen := map[string]bool{}
	for _, f := range a {
		if seen[f.ID] {
			t.Fatal("duplicate fixture")
		}
		seen[f.ID] = true
	}
	return a
}
func TestFixtureDrift(t *testing.T) {
	c, e := Builtin()
	if e != nil {
		t.Fatal(e)
	}
	causes := map[string]error{"ErrCatalogue": ErrCatalogue, "ErrInput": ErrInput, "ErrLimit": ErrLimit, "ErrEnvelope": ErrEnvelope, "ErrSchema": ErrSchema, "ErrSemantic": ErrSemantic}
	for _, f := range fixtures(t) {
		t.Run(f.ID, func(t *testing.T) {
			r, e := Validate(f.Document, c)
			if f.Accepted {
				if e != nil {
					t.Fatal(e)
				}
				if r.Name != f.Document["metadata"].(map[string]any)["name"] || r.CatalogueRevision != 1 {
					t.Fatal("result")
				}
				used := map[string]bool{}
				for _, x := range f.Document["spec"].(map[string]any)["datasets"].([]any) {
					used[x.(map[string]any)["source"].(string)] = true
				}
				ids := []string{}
				for id := range used {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				if len(r.Sources) != len(ids) {
					t.Fatal("source count")
				}
				for i, id := range ids {
					if !reflect.DeepEqual(r.Sources[i], c.sources[id].requirement) {
						t.Fatal("requirement")
					}
				}
			} else {
				assertError(t, e, causes[f.Sentinel], f.Path, f.Rule)
				if !reflect.DeepEqual(r, Result{}) {
					t.Fatal("partial result")
				}
			}
		})
	}
}
func base(source string) map[string]any {
	return map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "ReportTemplate", "metadata": map[string]any{"name": "sample"}, "spec": map[string]any{"title": map[string]any{"en": "Report", "vi": "Báo cáo"}, "datasets": []any{map[string]any{"name": "data", "source": source, "filter": map[string]any{}, "measures": []any{map[string]any{"name": "rows", "fn": "count"}}}}, "layout": []any{map[string]any{"type": "table", "dataset": "data", "columns": []any{"rows"}}}}}
}
func dataset(d map[string]any) map[string]any {
	return d["spec"].(map[string]any)["datasets"].([]any)[0].(map[string]any)
}
func TestAllCapabilities(t *testing.T) {
	c, _ := Builtin()
	fields, ops, aggs := 0, 0, 0
	for id, s := range c.sources {
		for name, f := range s.fields {
			fields++
			var value any
			switch f.kind {
			case "string":
				value = "x"
			case "enum":
				value = f.values[0]
			case "boolean":
				value = true
			case "integer":
				value = float64(1)
			case "number":
				value = 1.5
			case "timestamp":
				value = "2024-01-01T00:00:00Z"
			}
			for _, op := range []string{"eq", "in", "not_in", "gte", "lte", "between", "prefix", "exists"} {
				d := base(id)
				operand := value
				switch op {
				case "in", "not_in":
					operand = []any{value}
				case "between":
					operand = []any{value, value}
				case "exists":
					operand = true
				}
				dataset(d)["filter"].(map[string]any)[name] = map[string]any{op: operand}
				_, e := Validate(d, c)
				allowed := contains(f.operators, op)
				if (e == nil) != allowed {
					t.Fatalf("%s/%s %s: %v", id, name, op, e)
				}
				if allowed {
					ops++
				} else {
					assertError(t, e, ErrSemantic, "/spec/datasets/0/filter/"+name, "compatibility")
				}
			}
			for _, fn := range []string{"count_distinct", "sum", "min", "max", "avg", "p50", "p95"} {
				d := base(id)
				dataset(d)["measures"] = []any{map[string]any{"name": "measure", "fn": fn, "field": name}}
				d["spec"].(map[string]any)["layout"].([]any)[0].(map[string]any)["columns"] = []any{"measure"}
				_, e := Validate(d, c)
				allowed := contains(f.aggregations, fn)
				if (e == nil) != allowed {
					t.Fatalf("%s/%s %s: %v", id, name, fn, e)
				}
				if allowed {
					aggs++
				} else {
					assertError(t, e, ErrSemantic, "/spec/datasets/0/measures/0/fn", "compatibility")
				}
			}
		}
	}
	if fields != 88 || ops != 422 || aggs != 106 {
		t.Fatalf("capability drift %d/%d/%d", fields, ops, aggs)
	}
	t.Logf("88 fields; 422 operators; 106 aggregations")
}

func TestFixtureInventory(t *testing.T) {
	all := fixtures(t)
	if !completeFixtures(all) {
		t.Fatal("incomplete corpus")
	}
	for _, id := range []string{"source-devices", "source-pki-certificates", "dlp-category", "chart-line"} {
		reduced := []fixture{}
		for _, f := range all {
			if f.ID != id {
				reduced = append(reduced, f)
			}
		}
		if completeFixtures(reduced) {
			t.Fatalf("coverage removal not detected: %s", id)
		}
	}
}
func completeFixtures(all []fixture) bool {
	if len(all) != 83 {
		return false
	}
	sources, params, blocks, charts := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	accepted := 0
	for _, f := range all {
		if !f.Accepted {
			continue
		}
		accepted++
		s := f.Document["spec"].(map[string]any)
		for _, d := range objects(s["datasets"]) {
			sources[d["source"].(string)] = true
		}
		for _, p := range objects(s["parameters"]) {
			params[p["type"].(string)] = true
		}
		for _, b := range objects(s["layout"]) {
			blocks[b["type"].(string)] = true
			if b["type"] == "chart" {
				charts[b["chart"].(string)] = true
			}
		}
	}
	if accepted != 33 {
		return false
	}
	for id := range bindings {
		if !sources[id] {
			return false
		}
	}
	for _, p := range []string{"string", "enum_list", "time_range", "device_groups"} {
		if !params[p] {
			return false
		}
	}
	for _, b := range []string{"heading", "text", "kpi", "table", "chart"} {
		if !blocks[b] {
			return false
		}
	}
	for _, c := range []string{"bar", "stacked_bar", "line", "area", "pie", "heatmap"} {
		if !charts[c] {
			return false
		}
	}
	return true
}
func TestFieldDeclarations(t *testing.T) {
	c, _ := Builtin()
	for id, s := range c.sources {
		for name, f := range s.fields {
			for _, explicit := range []bool{false, true} {
				d := base(id)
				p := map[string]any{"name": "values", "type": "enum_list", "field": id + "/" + name}
				if explicit {
					value := "x"
					if f.kind == "enum" {
						value = f.values[0]
					}
					p["default"] = []any{value}
				}
				d["spec"].(map[string]any)["parameters"] = []any{p}
				_, e := Validate(d, c)
				if f.kind == "enum" {
					if e != nil {
						t.Fatal(e)
					}
				} else {
					assertError(t, e, ErrSemantic, "/spec/parameters/0/field", "compatibility")
				}
			}
			d := base(id)
			dataset(d)["group_by"] = []any{name}
			_, e := Validate(d, c)
			if f.groupable {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				assertError(t, e, ErrSemantic, "/spec/datasets/0/group_by/0", "compatibility")
			}
		}
	}
}
