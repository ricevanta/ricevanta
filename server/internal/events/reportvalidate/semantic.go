package reportvalidate

import (
	"math"
	"strings"
	"time"
)

func objects(v any) []map[string]any {
	if v == nil {
		return nil
	}
	a := v.([]any)
	out := make([]map[string]any, 0, len(a))
	for _, x := range a {
		out = append(out, x.(map[string]any))
	}
	return out
}
func optionalStrings(v any) []string {
	if v == nil {
		return nil
	}
	return stringsOf(v)
}
func instant(s string) bool {
	if !timestampPattern.MatchString(s) {
		return false
	}
	_, e := time.Parse("2006-01-02T15:04:05Z", s)
	return e == nil && !strings.HasPrefix(s, "0000")
}
func (c checker) rangeCompatibility(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	a, b := m["start"].(string), m["end"].(string)
	if !instant(a) {
		c.at("start").bad(1)
	}
	if !instant(b) {
		c.at("end").bad(1)
	}
	if instant(a) && instant(b) && a >= b {
		c.at("end").bad(1)
	}
}
func (c checker) literal(v any, f field) bool {
	ok := false
	switch f.kind {
	case "string":
		_, ok = v.(string)
	case "enum":
		s, is := v.(string)
		ok = is && contains(f.values, s)
	case "boolean":
		_, ok = v.(bool)
	case "integer", "number":
		n, is := v.(float64)
		ok = is && (f.kind == "number" || math.Trunc(n) == n)
	case "timestamp":
		s, is := v.(string)
		ok = is && instant(s)
	}
	if !ok {
		c.bad(3)
	}
	return ok
}
func (c checker) unique(a []map[string]any, key string) {
	seen := map[string]bool{}
	for i, x := range a {
		name := x[key].(string)
		if seen[name] {
			c.at(i).at(key).bad(0)
		}
		seen[name] = true
	}
}
func (c checker) resolveParam(v any, params map[string]map[string]any) {
	if m, ok := v.(map[string]any); ok {
		if _, ok := params[m["param"].(string)]; !ok {
			c.at("param").bad(0)
		}
	}
}
func semantic(resource map[string]any, cat *Catalogue) *Error {
	s := resource["spec"].(map[string]any)
	params, datasets, layout := objects(s["parameters"]), objects(s["datasets"]), objects(s["layout"])
	pm, dm := map[string]map[string]any{}, map[string]map[string]any{}
	for _, x := range params {
		pm[x["name"].(string)] = x
	}
	for _, x := range datasets {
		dm[x["name"].(string)] = x
	}
	var best [4]*defect
	checks := [4]checker{}
	for i := range checks {
		checks[i] = checker{path: location{"spec"}, best: &best[i]}
	}
	unique, refs, compat, output := checks[0], checks[1], checks[2], checks[3]
	unique.at("parameters").unique(params, "name")
	unique.at("datasets").unique(datasets, "name")
	for i, x := range params {
		r, c := refs.at("parameters").at(i), compat.at("parameters").at(i)
		switch x["type"] {
		case "enum_list":
			parts := strings.Split(x["field"].(string), "/")
			source, ok := cat.sources[parts[0]]
			f, found := source.fields[parts[1]]
			if !ok || !found {
				r.at("field").bad(0)
			} else if f.kind != "enum" {
				c.at("field").bad(0)
			} else if x["default"] != nil {
				for j, v := range x["default"].([]any) {
					c.at("default").at(j).literal(v, f)
				}
			}
		case "time_range":
			if x["default"] != nil {
				c.at("default").rangeCompatibility(x["default"])
			}
		}
	}
	for i, x := range datasets {
		u, r, c, o := unique.at("datasets").at(i), refs.at("datasets").at(i), compat.at("datasets").at(i), output.at("datasets").at(i)
		sourceID := x["source"].(string)
		source, known := cat.sources[sourceID]
		if !known {
			r.at("source").bad(0)
		}
		measures := objects(x["measures"])
		u.at("measures").unique(measures, "name")
		u.at("order_by").unique(objects(x["order_by"]), "field")
		for k, v := range x["filter"].(map[string]any) {
			rq, cq := r.at("filter").at(k), c.at("filter").at(k)
			if k == "time" || k == "device_groups" {
				if m, is := v.(map[string]any); is && m["param"] != nil {
					rq.resolveParam(v, pm)
					if p, ok := pm[m["param"].(string)]; ok {
						expected := "device_groups"
						if k == "time" {
							expected = "time_range"
						}
						if p["type"] != expected {
							cq.bad(3)
						}
					}
				} else if k == "time" {
					cq.rangeCompatibility(v)
				}
				continue
			}
			f, found := source.fields[k]
			if known && !found {
				rq.bad(0)
			}
			op := "eq"
			operand := v
			operandRef, operandCompat := rq, cq
			if m, is := v.(map[string]any); is && m["param"] == nil {
				for key, val := range m {
					op, operand = key, val
				}
				operandRef, operandCompat = rq.at(op), cq.at(op)
			}
			operandRef.resolveParam(operand, pm)
			if !found {
				continue
			}
			if !contains(f.operators, op) {
				cq.bad(2)
				continue
			}
			if m, is := operand.(map[string]any); is {
				p, ok := pm[m["param"].(string)]
				if !ok {
					continue
				}
				valid := (p["type"] == "string" && f.kind == "string" && (op == "eq" || op == "prefix")) || (p["type"] == "enum_list" && (op == "in" || op == "not_in") && p["field"] == sourceID+"/"+k) || (p["type"] == "time_range" && f.kind == "timestamp" && op == "between")
				if !valid {
					operandCompat.bad(3)
				}
			} else if op == "exists" {
			} else if a, is := operand.([]any); is {
				valid := true
				for j, v := range a {
					if !operandCompat.at(j).literal(v, f) {
						valid = false
					}
				}
				if op == "between" && valid {
					reversed := false
					switch a[0].(type) {
					case string:
						reversed = a[0].(string) > a[1].(string)
					case float64:
						reversed = a[0].(float64) > a[1].(float64)
					}
					if reversed {
						operandCompat.at(1).bad(3)
					}
				}
			} else {
				operandCompat.literal(operand, f)
			}
		}
		groups := optionalStrings(x["group_by"])
		for j, k := range groups {
			f, found := source.fields[k]
			if known && !found {
				r.at("group_by").at(j).bad(0)
			} else if found && !f.groupable {
				c.at("group_by").at(j).bad(4)
			}
		}
		outputs := append([]string{}, groups...)
		for j, m := range measures {
			outputs = append(outputs, m["name"].(string))
			if m["fn"] != "count" {
				f, found := source.fields[m["field"].(string)]
				if known && !found {
					r.at("measures").at(j).at("field").bad(0)
				} else if found && !contains(f.aggregations, m["fn"].(string)) {
					c.at("measures").at(j).at("fn").bad(4)
				}
			}
			if _, found := source.fields[m["name"].(string)]; found {
				o.at("measures").at(j).at("name").bad(0)
			}
		}
		for j, v := range objects(x["order_by"]) {
			if !contains(outputs, v["field"].(string)) {
				o.at("order_by").at(j).at("field").bad(1)
			}
		}
	}
	for i, b := range layout {
		if b["type"] == "heading" || b["type"] == "text" {
			continue
		}
		r, o := refs.at("layout").at(i), output.at("layout").at(i)
		x, found := dm[b["dataset"].(string)]
		if !found {
			r.at("dataset").bad(0)
			continue
		}
		groups := optionalStrings(x["group_by"])
		measures := []string{}
		for _, m := range objects(x["measures"]) {
			measures = append(measures, m["name"].(string))
		}
		outputs := append(append([]string{}, groups...), measures...)
		switch b["type"] {
		case "kpi":
			if len(groups) > 0 {
				o.at("dataset").bad(3)
			}
			if !contains(measures, b["measure"].(string)) {
				o.at("measure").bad(2)
			}
		case "table":
			for j, k := range stringsOf(b["columns"]) {
				if !contains(outputs, k) {
					o.at("columns").at(j).bad(2)
				}
			}
		case "chart":
			expected := 1
			if _, ok := b["series"]; ok {
				expected = 2
			}
			if len(groups) != expected {
				o.at("dataset").bad(3)
			}
			if !contains(groups, b["x"].(string)) {
				o.at("x").bad(4)
			}
			if series, ok := b["series"].(string); ok {
				if !contains(groups, series) || series == b["x"] {
					o.at("series").bad(4)
				}
			}
			if !contains(measures, b["y"].(string)) {
				o.at("y").bad(2)
			}
			if b["chart"] == "line" || b["chart"] == "area" {
				f, ok := cat.sources[x["source"].(string)].fields[b["x"].(string)]
				if ok && f.kind != "timestamp" {
					o.at("x").bad(5)
				}
			}
		}
	}
	for i, rule := range []string{"unique", "reference", "compatibility", "output"} {
		if best[i] != nil {
			return failure(ErrSemantic, best[i].path, rule)
		}
	}
	return nil
}
