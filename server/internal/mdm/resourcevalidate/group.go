package resourcevalidate

func (c checker) group(v any) {
	m := c.obj(v, "", "members selector")
	if m == nil {
		return
	}
	c.nonempty(m)
	c.field(m, "members", func(q checker, x any) { q.array(x, 1, 20000, true, func(r checker, x any) { r.name(x) }) })
	c.field(m, "selector", func(q checker, x any) {
		a := q.obj(x, "", "matchLabels matchExpressions os")
		if a == nil {
			return
		}
		q.nonempty(a)
		q.field(a, "matchLabels", func(r checker, x any) {
			b, ok := x.(map[string]any)
			if !ok {
				r.bad(2)
				return
			}
			if len(b) < 1 || len(b) > 16 {
				r.bad(4)
			}
			for key, v := range b {
				r.text(key, 1, 63, false)
				r.at(key).text(v, 0, 63, false)
			}
		})
		q.field(a, "matchExpressions", func(r checker, x any) {
			r.array(x, 1, 16, true, func(r checker, x any) {
				b := r.obj(x, "key operator", "values")
				if b == nil {
					return
				}
				r.field(b, "key", func(t checker, x any) { t.text(x, 1, 63, false) })
				r.field(b, "operator", func(t checker, x any) { t.enum(x, "In NotIn Exists DoesNotExist") })
				r.field(b, "values", func(t checker, x any) { t.array(x, 1, 64, true, func(u checker, x any) { u.text(x, 0, 63, false) }) })
				_, has := b["values"]
				switch b["operator"] {
				case "In", "NotIn":
					if !has {
						r.at("values").bad(0)
					}
				case "Exists", "DoesNotExist":
					if has {
						r.at("values").bad(1)
					}
				}
			})
		})
		q.field(a, "os", func(r checker, x any) {
			b := r.obj(x, "", "macos windows linux")
			if b == nil {
				return
			}
			r.nonempty(b)
			for _, k := range []string{"macos", "windows", "linux"} {
				r.field(b, k, func(t checker, x any) { t.text(x, 0, 16, false) })
			}
		})
	})
}
