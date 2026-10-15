package admission

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

func grantEqual(a, b *Grant) bool {
	return a.Component == b.Component && a.Kind == b.Kind && a.Interface == b.Interface && valuesEqual(&a.Values, &b.Values)
}

// valuesEqual is JSON equality of two values objects: arrays compare in order.
func valuesEqual(a, b *Values) bool {
	if (a.Content == nil) != (b.Content == nil) || (a.BrowserAdapter == nil) != (b.BrowserAdapter == nil) ||
		(a.AgentModule == nil) != (b.AgentModule == nil) || (a.ConsoleModule == nil) != (b.ConsoleModule == nil) ||
		(a.ServiceConnector == nil) != (b.ServiceConnector == nil) {
		return false
	}
	if a.BrowserAdapter != nil && (a.BrowserAdapter.Registration != b.BrowserAdapter.Registration || !osPoliciesEqual(&a.BrowserAdapter.OS, &b.BrowserAdapter.OS)) {
		return false
	}
	if x, y := a.AgentModule, b.AgentModule; x != nil {
		for _, f := range append(append(append([]agentField{}, budgetFields...), collectorFields...), responderFields...) {
			if *f.get(x) != *f.get(y) {
				return false
			}
		}
		if !stringsEqual(x.MIMETypes, y.MIMETypes) || !stringsEqual(x.Actions, y.Actions) || x.DisclosureProfile != y.DisclosureProfile || len(x.Roots) != len(y.Roots) {
			return false
		}
		if (x.MIMETypes == nil) != (y.MIMETypes == nil) || (x.Actions == nil) != (y.Actions == nil) || (x.Roots == nil) != (y.Roots == nil) {
			return false
		}
		for i := range x.Roots {
			if x.Roots[i] != y.Roots[i] {
				return false
			}
		}
	}
	if x, y := a.ConsoleModule, b.ConsoleModule; x != nil {
		if len(x.Slots) != len(y.Slots) {
			return false
		}
		for k, ops := range x.Slots {
			other, ok := y.Slots[k]
			if !ok || !stringsEqual(ops, other) {
				return false
			}
		}
	}
	if x, y := a.ServiceConnector, b.ServiceConnector; x != nil {
		if len(x.Outbound) != len(y.Outbound) {
			return false
		}
		for i := range x.Outbound {
			if x.Outbound[i] != y.Outbound[i] {
				return false
			}
		}
	}
	return true
}
