package admission

import "strconv"

// Subset rules of extension-admission section 4. bounded reports whether
// values v stay within bound for one agreeing kind and interface. Against the
// manifest request (current false) collector roots and the disclosure profile
// are not compared, because the request carries neither; against a current
// grant (current true) every root must be a current root and the profile must
// be equal, so a changed profile or a root outside the current roots widens.
func bounded(iface string, v, bound *Values, current bool) bool {
	switch {
	case v.Content != nil:
		return bound.Content != nil
	case v.BrowserAdapter != nil:
		b := bound.BrowserAdapter
		if b == nil || current && v.BrowserAdapter.Registration != b.Registration {
			return false
		}
		return osWithin(v.BrowserAdapter.OS.MacOS, b.OS.MacOS) &&
			osWithin(v.BrowserAdapter.OS.Windows, b.OS.Windows) &&
			osWithin(v.BrowserAdapter.OS.Linux, b.OS.Linux)
	case v.AgentModule != nil:
		a, b := v.AgentModule, bound.AgentModule
		if b == nil {
			return false
		}
		for _, f := range numericFields(iface) {
			if *f.get(a) > *f.get(b) {
				return false
			}
		}
		switch iface {
		case ifaceParser:
			return subset(a.MIMETypes, b.MIMETypes)
		case ifaceResponder:
			return subset(a.Actions, b.Actions)
		case ifaceCollector:
			if !current {
				return true
			}
			if a.DisclosureProfile != b.DisclosureProfile {
				return false
			}
			for _, r := range a.Roots {
				found := false
				for _, s := range b.Roots {
					if r == s {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
		return true
	case v.ConsoleModule != nil:
		b := bound.ConsoleModule
		if b == nil {
			return false
		}
		for slot, ops := range v.ConsoleModule.Slots {
			allowed, ok := b.Slots[slot]
			if !ok || !subset(ops, allowed) {
				return false
			}
		}
		return true
	case v.ServiceConnector != nil:
		b := bound.ServiceConnector
		if b == nil {
			return false
		}
		for _, o := range v.ServiceConnector.Outbound {
			found := false
			for _, p := range b.Outbound {
				if o == p {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

// osWithin: an OS the bound lacks is outside it; names are a subset and
// native_host only where the bound has it.
func osWithin(v, bound *OSPolicy) bool {
	if v == nil {
		return true
	}
	if bound == nil {
		return false
	}
	return subset(v.PolicyNames, bound.PolicyNames) && (!v.NativeHost || bound.NativeHost)
}

func subset(values, of []string) bool {
	for _, v := range values {
		if !contains(of, v) {
			return false
		}
	}
	return true
}

func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// widened is the release and retired-key comparison of section 6: a
// component the current install does not have, a changed kind or interface,
// or values not bounded by the current grant.
func widened(g *Grant, current *Grant) bool {
	if current == nil || g.Kind != current.Kind || g.Interface != current.Interface {
		return true
	}
	return !bounded(g.Interface, &g.Values, &current.Values, true)
}

// grantEqual is identical-retry equality: set-valued arrays compare as sets
// (extension-admission section 4).
func grantEqual(a, b *Grant) bool { return grantKey(a, true) == grantKey(b, true) }

// equalityKey is an injective, length-prefixed encoding: two values encode
// alike exactly when they are equal. With canonical false arrays keep their
// order (JSON equality, for uniqueItems); with canonical true set-valued grant
// arrays are sorted first (set equality). Console slots are keyed by name.
type equalityKey []byte

func (k *equalityKey) str(s string) {
	*k = strconv.AppendInt(*k, int64(len(s)), 10)
	*k = append(*k, ':')
	*k = append(*k, s...)
}

func (k *equalityKey) bytes(b []byte) { k.str(string(b)) }

func (k *equalityKey) u64(n uint64) {
	*k = strconv.AppendUint(*k, n, 10)
	*k = append(*k, ';')
}

func (k *equalityKey) flags(values ...bool) {
	for _, v := range values {
		if v {
			*k = append(*k, 't')
		} else {
			*k = append(*k, 'f')
		}
	}
}

func (k *equalityKey) strs(values []string) {
	k.u64(uint64(len(values)))
	for _, v := range values {
		k.str(v)
	}
}

func (k *equalityKey) osPolicies(p *OSPolicies, canonical bool) {
	for _, e := range []*OSPolicy{p.MacOS, p.Windows, p.Linux} {
		k.flags(e != nil)
		if e != nil {
			k.strs(set(e.PolicyNames, canonical))
			k.flags(e.NativeHost)
		}
	}
}

func grantKey(g *Grant, canonical bool) string {
	var k equalityKey
	k.str(g.Component)
	k.str(g.Kind)
	k.str(g.Interface)
	k.values(&g.Values, canonical)
	return string(k)
}

// set returns values, sorted when canonical.
func set(values []string, canonical bool) []string {
	if !canonical {
		return values
	}
	return sortedStrings(values)
}

// sortedByKey sorts element keys when canonical; the keys are injective, so
// any fixed order gives set equality.
func sortedByKey(keys []string, canonical bool) []string {
	if canonical {
		return sortedStrings(keys)
	}
	return keys
}

// values encodes every field of a Values; a nil and an empty set-valued
// agent array differ, as JSON absence and an empty array do.
func (k *equalityKey) values(v *Values, canonical bool) {
	k.flags(v.Content != nil, v.BrowserAdapter != nil, v.AgentModule != nil, v.ConsoleModule != nil, v.ServiceConnector != nil)
	if b := v.BrowserAdapter; b != nil {
		k.str(b.Registration)
		k.osPolicies(&b.OS, canonical)
	}
	if a := v.AgentModule; a != nil {
		for _, f := range append(append(append([]agentField{}, budgetFields...), collectorFields...), responderFields...) {
			k.u64(*f.get(a))
		}
		k.flags(a.MIMETypes != nil, a.Actions != nil, a.Roots != nil)
		k.strs(set(a.MIMETypes, canonical))
		k.strs(set(a.Actions, canonical))
		roots := make([]string, len(a.Roots))
		for i, r := range a.Roots {
			var rk equalityKey
			rk.str(r.OS)
			rk.str(r.Path)
			roots[i] = string(rk)
		}
		k.u64(uint64(len(roots)))
		for _, r := range sortedByKey(roots, canonical) {
			*k = append(*k, r...)
		}
		k.str(a.DisclosureProfile)
	}
	if c := v.ConsoleModule; c != nil {
		names := sortedKeys(c.Slots)
		k.u64(uint64(len(names)))
		for _, name := range names {
			k.str(name)
			k.strs(set(c.Slots[name], canonical))
		}
	}
	if c := v.ServiceConnector; c != nil {
		out := make([]string, len(c.Outbound))
		for i, o := range c.Outbound {
			var ok equalityKey
			ok.str(o.Host)
			ok.u64(o.Port)
			ok.str(o.Transport)
			out[i] = string(ok)
		}
		k.u64(uint64(len(out)))
		for _, o := range sortedByKey(out, canonical) {
			*k = append(*k, o...)
		}
	}
}
