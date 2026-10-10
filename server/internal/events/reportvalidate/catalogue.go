package reportvalidate

import (
	_ "embed"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"unicode/utf8"
)

//go:embed catalogue.json
var catalogueJSON string

type field struct {
	kind                            string
	nullable, filterable, groupable bool
	operators, aggregations, values []string
}
type source struct {
	owner, timeField string
	fields           map[string]field
	requirement      SourceRequirement
}
type Catalogue struct {
	revision uint32
	raw      string
	sources  map[string]source
}

func (c *Catalogue) Revision() uint32 {
	if c == nil {
		return 0
	}
	return c.revision
}
func (c *Catalogue) JSON() []byte {
	if c == nil || c.revision == 0 {
		return nil
	}
	return []byte(c.raw)
}

var builtinOnce sync.Once
var builtinCatalogue *Catalogue
var builtinError error

func Builtin() (*Catalogue, error) {
	builtinOnce.Do(func() { builtinCatalogue, builtinError = loadCatalogue(catalogueJSON) })
	return builtinCatalogue, builtinError
}

var bindings = map[string][3]string{
	"devices": {"devices", "mdm.devices.read", "devices"}, "devices.software": {"mdm", "mdm.inventory.read", "devices"}, "mdm.compliance": {"mdm", "mdm.compliance.read", "devices"},
	"edr.alerts": {"detection", "edr.alerts.read", "devices"}, "edr.response_actions": {"detection", "edr.response.read", "devices"}, "dlp.findings": {"dlp", "dlp.findings.read", "devices"},
	"lineage.edges": {"lineage", "lineage.edges.read", "lineage_endpoints"}, "pki.certificates": {"pki", "pki.certificates.read", "certificate_profile"}, "radius.authentications": {"radius", "radius.authentications.read", "radius_attribution"},
	"agents.versions": {"devices", "mdm.versions.read", "devices"}, "agents.health": {"events", "events.health.read", "devices"}, "audit.events": {"audit", "audit.events.read", "organization"},
}

// decodeCatalogue is private and accepts only bounded bundled metadata. Tokens
// retain duplicate keys so the loader can refuse them before building state.
func decodeCatalogue(raw string) (any, error) {
	if len(raw) > 1048576 || !utf8.ValidString(raw) {
		return nil, ErrCatalogue
	}
	d := json.NewDecoder(strings.NewReader(raw))
	nodes := 0
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		nodes++
		if nodes > 32768 {
			return nil, ErrCatalogue
		}
		token, e := d.Token()
		if e != nil {
			return nil, ErrCatalogue
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return token, nil
		}
		depth++
		if depth > 16 {
			return nil, ErrCatalogue
		}
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				nodes++
				if nodes > 32768 {
					return nil, ErrCatalogue
				}
				k, e := d.Token()
				if e != nil {
					return nil, ErrCatalogue
				}
				key, ok := k.(string)
				if !ok {
					return nil, ErrCatalogue
				}
				if _, ok = m[key]; ok {
					return nil, ErrCatalogue
				}
				v, e := walk(depth)
				if e != nil {
					return nil, e
				}
				m[key] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrCatalogue
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, e := walk(depth)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrCatalogue
			}
			return a, nil
		}
		return nil, ErrCatalogue
	}
	v, e := walk(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrCatalogue
	}
	return v, nil
}
func stringsOf(a any) []string {
	out := []string{}
	for _, v := range a.([]any) {
		out = append(out, v.(string))
	}
	return out
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
func (c checker) stringSet(v any, choices string, lo, hi int) {
	c.array(v, lo, hi, true, func(q checker, x any) { q.enum(x, choices) })
}
func loadCatalogue(raw string) (*Catalogue, error) {
	fail := func() (*Catalogue, error) { return nil, failure(ErrCatalogue, nil, "catalogue") }
	v, e := decodeCatalogue(raw)
	if e != nil {
		return fail()
	}
	var best *defect
	c := checker{best: &best}
	m := c.obj(v, "format_version revision sources", "")
	if m == nil {
		return fail()
	}
	c.field(m, "format_version", func(q checker, x any) { q.one(x, float64(1)) })
	c.field(m, "revision", func(q checker, x any) { q.integer(x, 1, 4294967295) })
	c.field(m, "sources", func(q checker, x any) {
		q.array(x, 1, 64, false, func(r checker, y any) {
			s := r.obj(y, "id owner read_permission scope footprint conditional_reads time_field row_aggregations fields", "")
			if s == nil {
				return
			}
			r.field(s, "id", func(q checker, x any) { q.pattern(x, 1, 64, sourcePattern) })
			r.field(s, "owner", func(q checker, x any) { q.enum(x, "devices mdm detection dlp lineage pki radius events audit") })
			r.field(s, "read_permission", func(q checker, x any) { q.text(x, 1, 98, false) })
			r.field(s, "scope", func(q checker, x any) { q.enum(x, "device_group organization") })
			r.field(s, "footprint", func(q checker, x any) {
				q.enum(x, "devices lineage_endpoints certificate_profile radius_attribution organization")
			})
			r.field(s, "time_field", func(q checker, x any) { q.identifier(x) })
			r.field(s, "row_aggregations", func(q checker, x any) { q.stringSet(x, "count", 1, 1) })
			r.field(s, "conditional_reads", func(q checker, x any) {
				q.array(x, 0, 1, true, func(r checker, y any) {
					a := r.obj(y, "condition permission scope", "")
					if a == nil {
						return
					}
					r.field(a, "condition", func(q checker, x any) { q.one(x, "infrastructure_certificate") })
					r.field(a, "permission", func(q checker, x any) { q.one(x, "pki.infrastructure.read") })
					r.field(a, "scope", func(q checker, x any) { q.one(x, "organization") })
				})
			})
			r.field(s, "fields", func(q checker, x any) {
				q.array(x, 1, 64, false, func(r checker, y any) {
					a := r.obj(y, "name type nullable filterable groupable operators aggregations description", "values")
					if a == nil {
						return
					}
					r.field(a, "name", func(q checker, x any) { q.identifier(x) })
					r.field(a, "type", func(q checker, x any) { q.enum(x, "string enum boolean integer number timestamp") })
					for _, k := range []string{"nullable", "filterable", "groupable"} {
						r.field(a, k, func(q checker, x any) { q.boolean(x) })
					}
					r.field(a, "operators", func(q checker, x any) { q.stringSet(x, "between eq exists gte in lte not_in prefix", 0, 8) })
					r.field(a, "aggregations", func(q checker, x any) { q.stringSet(x, "count_distinct sum min max avg p50 p95", 0, 7) })
					r.field(a, "description", func(q checker, x any) { q.text(x, 1, 256, false) })
					r.field(a, "values", func(q checker, x any) { q.array(x, 1, 64, true, func(r checker, y any) { r.text(y, 1, 256, false) }) })
					if a["type"] == "enum" {
						if _, ok := a["values"]; !ok {
							r.at("values").bad(0)
						}
					} else if _, ok := a["values"]; ok {
						r.at("values").bad(1)
					}
				})
			})
		})
	})
	if best != nil {
		return fail()
	}
	cat := &Catalogue{revision: uint32(m["revision"].(float64)), raw: raw, sources: map[string]source{}}
	previous := ""
	for _, x := range m["sources"].([]any) {
		s := x.(map[string]any)
		id := s["id"].(string)
		binding, ok := bindings[id]
		if !ok || id <= previous || s["owner"] != binding[0] || s["read_permission"] != binding[1] || s["footprint"] != binding[2] {
			return fail()
		}
		previous = id
		scope := "device_group"
		if id == "audit.events" {
			scope = "organization"
		}
		if s["scope"] != scope {
			return fail()
		}
		entry := source{owner: binding[0], timeField: s["time_field"].(string), fields: map[string]field{}, requirement: SourceRequirement{Source: id, Permission: binding[1], Scope: scope, Footprint: binding[2]}}
		conditions := s["conditional_reads"].([]any)
		if (id == "pki.certificates" && len(conditions) != 1) || (id != "pki.certificates" && len(conditions) != 0) {
			return fail()
		}
		for _, x := range conditions {
			a := x.(map[string]any)
			entry.requirement.ConditionalReads = append(entry.requirement.ConditionalReads, ConditionalRead{a["condition"].(string), a["permission"].(string), a["scope"].(string)})
		}
		previousField := ""
		for _, x := range s["fields"].([]any) {
			a := x.(map[string]any)
			name := a["name"].(string)
			if name <= previousField || name == "time" || name == "device_groups" {
				return fail()
			}
			previousField = name
			f := field{kind: a["type"].(string), nullable: a["nullable"].(bool), filterable: a["filterable"].(bool), groupable: a["groupable"].(bool), operators: stringsOf(a["operators"]), aggregations: stringsOf(a["aggregations"])}
			if a["values"] != nil {
				f.values = stringsOf(a["values"])
			}
			ops := map[string]string{"string": "eq in not_in prefix exists", "enum": "eq in not_in exists", "boolean": "eq exists", "integer": "eq in not_in gte lte between exists", "number": "eq in not_in gte lte between exists", "timestamp": "eq gte lte between exists"}
			if f.filterable != (len(f.operators) > 0) {
				return fail()
			}
			for _, op := range f.operators {
				if !contains(strings.Fields(ops[f.kind]), op) {
					return fail()
				}
			}
			for _, fn := range f.aggregations {
				if fn != "count_distinct" && f.kind != "integer" && f.kind != "number" {
					return fail()
				}
			}
			entry.fields[name] = f
		}
		time, ok := entry.fields[entry.timeField]
		if !ok || time.kind != "timestamp" || time.nullable {
			return fail()
		}
		cat.sources[id] = entry
	}
	if len(cat.sources) != len(bindings) {
		return fail()
	}
	return cat, nil
}
