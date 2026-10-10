package reportvalidate

func (c checker) localized(v any, multiline bool) {
	m := c.obj(v, "en vi", "")
	if m == nil {
		return
	}
	hi := 256
	if multiline {
		hi = 4096
	}
	for _, k := range []string{"en", "vi"} {
		c.field(m, k, func(q checker, x any) { q.text(x, 1, hi, multiline) })
	}
}
func (c checker) reference(v any) {
	m := c.obj(v, "param", "")
	if m != nil {
		c.field(m, "param", func(q checker, x any) { q.identifier(x) })
	}
}
func (c checker) scalar(v any) {
	switch v.(type) {
	case string:
		c.text(v, 0, 256, false)
	case float64, bool:
	default:
		c.bad(2)
	}
}
func (c checker) operand(v any) {
	if _, ok := v.(map[string]any); ok {
		c.reference(v)
	} else {
		c.scalar(v)
	}
}
func (c checker) groups(v any, refs bool) {
	if _, ok := v.(map[string]any); ok && refs {
		c.reference(v)
		return
	}
	if _, ok := v.(string); ok {
		c.one(v, "all")
		return
	}
	c.array(v, 1, 64, true, func(q checker, x any) { q.name(x) })
}
func (c checker) time(v any, refs bool) {
	if m, ok := v.(map[string]any); ok {
		if _, ref := m["param"]; ref && refs {
			c.reference(v)
			return
		}
		a := c.obj(v, "start end", "")
		if a != nil {
			for _, k := range []string{"start", "end"} {
				c.field(a, k, func(q checker, x any) { q.pattern(x, 20, 20, timestampPattern) })
			}
		}
		return
	}
	c.enum(v, "last_24h last_7d last_30d last_90d this_month previous_month")
}
func (c checker) condition(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.scalar(v)
		return
	}
	if _, ok := m["param"]; ok {
		c.reference(v)
		return
	}
	if len(m) != 1 {
		c.bad(6)
		return
	}
	for op, x := range m {
		q := c.at(op)
		switch op {
		case "eq", "gte", "lte", "prefix":
			q.operand(x)
		case "exists":
			q.boolean(x)
		case "in", "not_in", "between":
			if _, ok := x.(map[string]any); ok {
				q.reference(x)
			} else {
				lo, hi, set := 1, 64, true
				if op == "between" {
					lo, hi, set = 2, 2, false
				}
				q.array(x, lo, hi, set, func(r checker, y any) { r.scalar(y) })
			}
		default:
			c.bad(6)
		}
	}
}
func (c checker) filter(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return
	}
	if len(m) > 32 {
		c.bad(4)
	}
	for k, x := range m {
		q := c.at(k)
		q.identifier(k)
		switch k {
		case "time":
			q.time(x, true)
		case "device_groups":
			q.groups(x, true)
		default:
			q.condition(x)
		}
	}
}
func (c checker) parameter(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return
	}
	tag, exists := m["type"]
	if !exists {
		c.at("type").bad(0)
		return
	}
	if !c.at("type").enum(tag, "time_range device_groups enum_list string") {
		return
	}
	required := "name type"
	optional := "default"
	if tag == "enum_list" {
		required += " field"
	}
	c.obj(v, required, optional)
	c.field(m, "name", func(q checker, x any) { q.identifier(x) })
	if tag == "enum_list" {
		c.field(m, "field", func(q checker, x any) { q.pattern(x, 1, 97, fieldPattern) })
	}
	c.field(m, "default", func(q checker, x any) {
		switch tag {
		case "time_range":
			q.time(x, false)
		case "device_groups":
			q.groups(x, false)
		case "enum_list":
			q.array(x, 1, 64, true, func(r checker, y any) { r.text(y, 1, 256, false) })
		case "string":
			q.text(x, 0, 256, false)
		}
	})
}
func (c checker) measure(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return
	}
	fn, exists := m["fn"]
	if !exists {
		c.at("fn").bad(0)
		return
	}
	if !c.at("fn").enum(fn, "count count_distinct sum min max avg p50 p95") {
		return
	}
	required := "name fn"
	if fn != "count" {
		required += " field"
	}
	c.obj(v, required, "")
	c.field(m, "name", func(q checker, x any) { q.identifier(x) })
	if fn != "count" {
		c.field(m, "field", func(q checker, x any) { q.identifier(x) })
	}
}
func (c checker) dataset(v any) {
	m := c.obj(v, "name source filter measures", "group_by order_by limit")
	if m == nil {
		return
	}
	c.field(m, "name", func(q checker, x any) { q.identifier(x) })
	c.field(m, "source", func(q checker, x any) { q.pattern(x, 1, 64, sourcePattern) })
	c.field(m, "filter", func(q checker, x any) { q.filter(x) })
	c.field(m, "measures", func(q checker, x any) { q.array(x, 1, 8, false, func(r checker, y any) { r.measure(y) }) })
	c.field(m, "group_by", func(q checker, x any) { q.array(x, 1, 3, true, func(r checker, y any) { r.identifier(y) }) })
	c.field(m, "order_by", func(q checker, x any) {
		q.array(x, 1, 11, false, func(r checker, y any) {
			a := r.obj(y, "field", "desc")
			if a != nil {
				r.field(a, "field", func(q checker, x any) { q.identifier(x) })
				r.field(a, "desc", func(q checker, x any) { q.boolean(x) })
			}
		})
	})
	c.field(m, "limit", func(q checker, x any) { q.integer(x, 1, 10000) })
}
func (c checker) block(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return
	}
	tag, exists := m["type"]
	if !exists {
		c.at("type").bad(0)
		return
	}
	if !c.at("type").enum(tag, "heading text kpi table chart") {
		return
	}
	switch tag {
	case "heading", "text":
		c.obj(m, "type text", "")
		c.field(m, "text", func(q checker, x any) { q.localized(x, true) })
	case "kpi":
		c.obj(m, "type dataset measure label", "")
		c.field(m, "dataset", func(q checker, x any) { q.identifier(x) })
		c.field(m, "measure", func(q checker, x any) { q.identifier(x) })
		c.field(m, "label", func(q checker, x any) { q.localized(x, false) })
	case "table":
		c.obj(m, "type dataset columns", "")
		c.field(m, "dataset", func(q checker, x any) { q.identifier(x) })
		c.field(m, "columns", func(q checker, x any) { q.array(x, 1, 11, true, func(r checker, y any) { r.identifier(y) }) })
	case "chart":
		c.obj(m, "type chart dataset x y", "series")
		c.field(m, "chart", func(q checker, x any) { q.enum(x, "bar stacked_bar line area pie heatmap") })
		for _, k := range []string{"dataset", "x", "y", "series"} {
			c.field(m, k, func(q checker, x any) { q.identifier(x) })
		}
		if m["chart"] == "stacked_bar" || m["chart"] == "heatmap" {
			if _, ok := m["series"]; !ok {
				c.at("series").bad(0)
			}
		}
		if m["chart"] == "pie" {
			if _, ok := m["series"]; ok {
				c.at("series").bad(1)
			}
		}
	}
}
func structural(m map[string]any) *Error {
	var best *defect
	c := checker{path: location{"spec"}, best: &best}
	s := m["spec"].(map[string]any)
	c.obj(s, "title datasets layout", "parameters")
	c.field(s, "title", func(q checker, x any) { q.localized(x, false) })
	c.field(s, "parameters", func(q checker, x any) { q.array(x, 0, 16, false, func(r checker, y any) { r.parameter(y) }) })
	c.field(s, "datasets", func(q checker, x any) { q.array(x, 1, 10, false, func(r checker, y any) { r.dataset(y) }) })
	c.field(s, "layout", func(q checker, x any) { q.array(x, 1, 64, false, func(r checker, y any) { r.block(y) }) })
	if best != nil {
		return failure(ErrSchema, best.path, "schema")
	}
	return nil
}
