package admission

import (
	"errors"
	"slices"
	"testing"
)

// Tests that pin rules the corpus exercises only partly (review R-04, R-05).

const chromeRegistration = "io.ricevanta.browser.chrome"

// allKinds extends agentInputs with a content, browser-adapter,
// console-module and service-connector component, proposing exactly the
// requested values.
func allKinds(t testing.TB) inputs {
	t.Helper()
	in := agentInputs(t)
	adapter := BrowserAdapterValues{Registration: chromeRegistration, OS: OSPolicies{
		Windows: &OSPolicy{PolicyNames: []string{"ExtensionInstallForcelist", "NativeMessagingUserLevelHosts"}, NativeHost: true},
		MacOS:   &OSPolicy{PolicyNames: []string{"ExtensionInstallForcelist"}},
	}}
	console := ConsoleModuleValues{Slots: map[string][]string{"device-tab": {"getDevice", "listAlerts"}, "navigation": {"getDevice", "listAlerts"}}}
	connector := ServiceConnectorValues{Outbound: []Outbound{{Host: "hooks.example.com", Port: 443, Transport: "tcp"}, {Host: "alt.example.com", Port: 8443, Transport: "udp"}}}
	extra := []Component{
		{Name: "chrome", Kind: kindBrowserAdapter, Interface: "ext.ricevanta.io/browser-adapter/v1", Requested: Values{BrowserAdapter: &adapter}},
		{Name: "notifier", Kind: kindServiceConnector, Interface: "ext.ricevanta.io/notifier/v1", Requested: Values{ServiceConnector: &connector}},
		{Name: "panel", Kind: kindConsoleModule, Interface: "ext.ricevanta.io/console-module/v1", Slots: []string{"device-tab", "navigation"}, Requested: Values{ConsoleModule: &console}},
		{Name: "rules", Kind: kindContent, Interface: "ext.ricevanta.io/content/v1", Format: "sigma", Requested: Values{Content: &struct{}{}}},
	}
	in.e.Components = append(in.e.Components, extra...)
	slices.SortFunc(in.e.Components, func(a, b Component) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	in.e.Requires[kindBrowserAdapter] = []string{"ext.ricevanta.io/browser-adapter/v1"}
	in.e.Requires[kindServiceConnector] = []string{"ext.ricevanta.io/notifier/v1"}
	in.e.Requires[kindConsoleModule] = []string{"ext.ricevanta.io/console-module/v1"}
	in.e.Requires[kindContent] = []string{"ext.ricevanta.io/content/v1"}
	for _, c := range extra {
		in.r.Grants = append(in.r.Grants, Grant{Component: c.Name, Kind: c.Kind, Interface: c.Interface, Values: cloneValues(c.Requested)})
		in.v = append(in.v, Verdict{Component: c.Name, OK: true})
	}
	in.r.Targets.Console, in.r.Targets.Jobs = true, true
	in.s.DisclosureProfiles = append(in.s.DisclosureProfiles, "inventory.other.v1")
	if d := decideInputs(in); d.Outcome != ApprovalRequired {
		t.Fatalf("all-kinds install: %+v", d)
	}
	return in
}

// cloneValues deep-copies values so a test can change a grant without
// touching the request it was built from.
func cloneValues(v Values) Values {
	out := v
	if b := v.BrowserAdapter; b != nil {
		c := *b
		for _, p := range []**OSPolicy{&c.OS.MacOS, &c.OS.Windows, &c.OS.Linux} {
			if *p != nil {
				q := **p
				q.PolicyNames = slices.Clone(q.PolicyNames)
				*p = &q
			}
		}
		out.BrowserAdapter = &c
	}
	if a := v.AgentModule; a != nil {
		c := *a
		c.MIMETypes, c.Actions, c.Roots = slices.Clone(a.MIMETypes), slices.Clone(a.Actions), slices.Clone(a.Roots)
		out.AgentModule = &c
	}
	if m := v.ConsoleModule; m != nil {
		c := ConsoleModuleValues{Slots: map[string][]string{}}
		for k, ops := range m.Slots {
			c.Slots[k] = slices.Clone(ops)
		}
		out.ConsoleModule = &c
	}
	if s := v.ServiceConnector; s != nil {
		out.ServiceConnector = &ServiceConnectorValues{Outbound: slices.Clone(s.Outbound)}
	}
	return out
}

// installed commits the request as the active install of this version.
func installed(in inputs) inputs {
	install := &Install{ID: in.e.ID, Version: in.e.Version, PackageSHA256: in.e.PackageSHA256, State: StateActive, Enabled: true, Generation: 3, Targets: in.r.Targets}
	install.Targets.DeviceGroups = slices.Clone(in.r.Targets.DeviceGroups)
	for i, g := range in.r.Grants {
		install.Grants = append(install.Grants, GrantRecord{ExtensionID: in.e.ID, Version: in.e.Version, PackageSHA256: in.e.PackageSHA256,
			RecoveryEpoch: in.s.RecoveryEpoch, GrantGeneration: uint64(i + 1), Approval: Approval{Kind: ReleaseFixed, ReleaseVersion: "1.0.0"},
			Grant: Grant{Component: g.Component, Kind: g.Kind, Interface: g.Interface, Values: cloneValues(g.Values)}})
	}
	in.s.Install = install
	in.s.Tombstones = []Tombstone{{ID: in.e.ID, Version: in.e.Version, Publisher: in.e.PublisherFingerprint, ManifestSHA256: in.e.ManifestSHA256, PackageSHA256: in.e.PackageSHA256}}
	in.s.Ownership = &Ownership{ID: in.e.ID, Owner: in.e.PublisherFingerprint, OwnershipGeneration: 1}
	in.r.Approval = nil
	return in
}

func grantOf(in *inputs, component string) *Grant {
	for i := range in.r.Grants {
		if in.r.Grants[i].Component == component {
			return &in.r.Grants[i]
		}
	}
	panic("no grant " + component)
}

// valueChanges each change one set-valued array of one component.
var valueChanges = []struct {
	name, component string
	content         func(*Grant) // a different set
	order           func(*Grant) // the same set in another order
}{
	{"browser policy names", "chrome",
		func(g *Grant) {
			g.Values.BrowserAdapter.OS.Windows.PolicyNames = g.Values.BrowserAdapter.OS.Windows.PolicyNames[:1]
		},
		func(g *Grant) { slices.Reverse(g.Values.BrowserAdapter.OS.Windows.PolicyNames) }},
	{"browser native host", "chrome",
		func(g *Grant) { g.Values.BrowserAdapter.OS.Windows.NativeHost = false }, nil},
	{"browser OS", "chrome",
		func(g *Grant) { g.Values.BrowserAdapter.OS.MacOS = nil }, nil},
	{"MIME types", "parser",
		func(g *Grant) { g.Values.AgentModule.MIMETypes = g.Values.AgentModule.MIMETypes[1:] },
		func(g *Grant) { slices.Reverse(g.Values.AgentModule.MIMETypes) }},
	{"actions", "responder",
		func(g *Grant) { g.Values.AgentModule.Actions = g.Values.AgentModule.Actions[1:] },
		func(g *Grant) { slices.Reverse(g.Values.AgentModule.Actions) }},
	{"roots", "collector",
		func(g *Grant) { g.Values.AgentModule.Roots = g.Values.AgentModule.Roots[1:] },
		func(g *Grant) { slices.Reverse(g.Values.AgentModule.Roots) }},
	{"root path", "collector",
		func(g *Grant) { g.Values.AgentModule.Roots[0].Path = "/var/lib/other" }, nil},
	{"root OS", "collector",
		func(g *Grant) { g.Values.AgentModule.Roots[0].OS = "macos" }, nil},
	{"disclosure profile", "collector",
		func(g *Grant) { g.Values.AgentModule.DisclosureProfile = "inventory.other.v1" }, nil},
	{"console operations", "panel",
		func(g *Grant) { g.Values.ConsoleModule.Slots["device-tab"] = []string{"getDevice"} },
		func(g *Grant) { slices.Reverse(g.Values.ConsoleModule.Slots["device-tab"]) }},
	{"console slots", "panel",
		func(g *Grant) { delete(g.Values.ConsoleModule.Slots, "navigation") }, nil},
	{"outbound", "notifier",
		func(g *Grant) { g.Values.ServiceConnector.Outbound = g.Values.ServiceConnector.Outbound[1:] },
		func(g *Grant) { slices.Reverse(g.Values.ServiceConnector.Outbound) }},
	{"outbound port", "notifier",
		func(g *Grant) { g.Values.ServiceConnector.Outbound[0].Port = 444 }, nil},
	{"outbound transport", "notifier",
		func(g *Grant) { g.Values.ServiceConnector.Outbound[0].Transport = "udp" }, nil},
	{"agent number", "classifier",
		func(g *Grant) { g.Values.AgentModule.MemoryPages-- }, nil},
}

func TestIdenticalRetryEquality(t *testing.T) {
	if d := decideInputs(installed(allKinds(t))); d.Outcome != IdenticalRetry {
		t.Fatalf("unchanged retry: %+v", d)
	}
	for _, c := range valueChanges {
		t.Run(c.name, func(t *testing.T) {
			in := installed(allKinds(t))
			c.content(grantOf(&in, c.component))
			d := decideInputs(in)
			if d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeTombstoneGrants, in.e.Version}}) {
				t.Fatalf("changed %s: %+v", c.name, d)
			}
			if c.order == nil {
				return
			}
			in = installed(allKinds(t))
			c.order(grantOf(&in, c.component))
			if d := decideInputs(in); d.Outcome != IdenticalRetry {
				t.Fatalf("reordered %s is not an identical retry: %+v", c.name, d)
			}
		})
	}
}

// TestSetOrderDigests: set-valued arrays enter both digests in canonical
// order, so reordering a proposal never changes them.
func TestSetOrderDigests(t *testing.T) {
	want := decideInputs(allKinds(t))
	for _, c := range valueChanges {
		if c.order == nil {
			continue
		}
		in := allKinds(t)
		c.order(grantOf(&in, c.component))
		if d := decideInputs(in); d.ClosureDigest != want.ClosureDigest || d.RequestDigest != want.RequestDigest {
			t.Errorf("reordered %s changed a digest", c.name)
		}
		in = allKinds(t)
		c.content(grantOf(&in, c.component))
		if d := decideInputs(in); d.Outcome == ApprovalRequired && d.RequestDigest == want.RequestDigest {
			t.Errorf("changed %s kept the request digest", c.name)
		}
	}
	// The install's stored grant values enter the closure canonically too.
	a, b := installed(allKinds(t)), installed(allKinds(t))
	for i := range b.s.Install.Grants {
		g := &b.s.Install.Grants[i].Grant
		for _, c := range valueChanges {
			if c.order != nil && c.component == g.Component {
				c.order(g)
			}
		}
	}
	a.r.GrantUpdate, b.r.GrantUpdate = true, true
	if da, db := decideInputs(a), decideInputs(b); da.ClosureDigest == "" || da.ClosureDigest != db.ClosureDigest {
		t.Errorf("reordered stored grants changed the closure: %+v %+v", da, db)
	}
}

// TestWidenedAgainstCurrentGrant: under a retired key a grant update may only
// narrow; a changed profile, a new root, a wider number or set widens.
func TestWidenedAgainstCurrentGrant(t *testing.T) {
	retired := func(t *testing.T) inputs {
		in := installed(allKinds(t))
		in.r.GrantUpdate = true
		findEntry(&in.s, in.e.PublisherFingerprint).Retired = true
		return in
	}
	if d := decideInputs(retired(t)); d.Outcome != ApprovalRequired {
		t.Fatalf("equal grant update under a retired key: %+v", d)
	}
	for _, c := range valueChanges {
		t.Run(c.name, func(t *testing.T) {
			// Each content change above narrows except the profile and
			// native-host changes, which are checked below.
			in := retired(t)
			c.content(grantOf(&in, c.component))
			d := decideInputs(in)
			switch c.name {
			case "disclosure profile", "root path", "root OS", "outbound port", "outbound transport":
				if d.Outcome != Reject || !slices.Contains(d.Reasons, Reason{CodeGrantRetiredKey, c.component}) && !slices.Contains(d.Reasons, Reason{CodeGrantExceeds, c.component}) {
					t.Fatalf("widening %s: %+v", c.name, d)
				}
			default:
				if d.Outcome != ApprovalRequired {
					t.Fatalf("narrowing %s: %+v", c.name, d)
				}
			}
		})
	}
	// A root that the current grant lacks widens even within max_roots.
	in := retired(t)
	installedRoots := in.s.Install.Grants
	for i := range installedRoots {
		if g := &installedRoots[i].Grant; g.Component == "collector" {
			g.Values.AgentModule.Roots = g.Values.AgentModule.Roots[:1]
		}
	}
	if d := decideInputs(in); d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeGrantRetiredKey, "collector"}}) {
		t.Fatalf("root outside the current roots: %+v", d)
	}
	// The same comparison drives release-fixed widening.
	collector := grantOf(&in, "collector")
	current := *currentGrant(in.s.Install, "collector")
	if !widened(collector, &current) {
		t.Fatal("widened misses a new root")
	}
	narrowed := *collector
	narrowed.Values = cloneValues(collector.Values)
	narrowed.Values.AgentModule.Roots = narrowed.Values.AgentModule.Roots[:1]
	if widened(&narrowed, &current) {
		t.Fatal("widened flags an equal root set")
	}
	narrowed.Values.AgentModule.DisclosureProfile = "inventory.other.v1"
	if !widened(&narrowed, &current) {
		t.Fatal("widened misses a changed profile")
	}
}

// TestGrantWithinRequest: values outside the manifest request are refused.
func TestGrantWithinRequest(t *testing.T) {
	for name, c := range map[string]struct {
		component string
		mutate    func(*Grant)
	}{
		"console operation not requested": {"panel", func(g *Grant) { g.Values.ConsoleModule.Slots["device-tab"] = []string{"getDevice", "updateAlert"} }},
		"console slot not declared":       {"panel", func(g *Grant) { g.Values.ConsoleModule.Slots["settings"] = []string{} }},
		"outbound port":                   {"notifier", func(g *Grant) { g.Values.ServiceConnector.Outbound[0].Port = 444 }},
		"outbound transport":              {"notifier", func(g *Grant) { g.Values.ServiceConnector.Outbound[0].Transport = "udp" }},
		"outbound host":                   {"notifier", func(g *Grant) { g.Values.ServiceConnector.Outbound[0].Host = "other.example.com" }},
		"browser OS not requested":        {"chrome", func(g *Grant) { g.Values.BrowserAdapter.OS.Linux = &OSPolicy{PolicyNames: []string{}} }},
		"browser policy not requested": {"chrome", func(g *Grant) {
			g.Values.BrowserAdapter.OS.MacOS.PolicyNames = []string{"NativeMessagingUserLevelHosts"}
		}},
		"browser native host": {"chrome", func(g *Grant) { g.Values.BrowserAdapter.OS.MacOS.NativeHost = true }},
	} {
		t.Run(name, func(t *testing.T) {
			in := allKinds(t)
			c.mutate(grantOf(&in, c.component))
			if d := decideInputs(in); d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeGrantExceeds, c.component}}) {
				t.Fatalf("got %+v, want grant.exceeds", d)
			}
		})
	}
}

func TestPriorOwnerNeedsRecord(t *testing.T) {
	for _, name := range []string{"prior-owner-reinstall-after-transfer", "prior-owner-rollback-upgrade"} {
		in := caseInputs(t, name)
		if d := decideInputs(in); d.Outcome != ApprovalRequired {
			t.Fatalf("%s: %+v", name, d)
		}
		fp := in.e.PublisherFingerprint
		in.s.Ownership.PriorOwners = slices.DeleteFunc(slices.Clone(in.s.Ownership.PriorOwners), func(p string) bool { return p == fp })
		if d := decideInputs(in); d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeOwnershipOwner, in.e.ID}}) {
			t.Fatalf("%s without the prior-owner record: %+v", name, d)
		}
	}
}

func TestAllDevicesKeptOnlyByGrantUpdate(t *testing.T) {
	in := caseInputs(t, "upgrade-approval-required")
	in.s.Install.Targets = Targets{AllDevices: true, DeviceGroups: []string{}}
	in.r.Targets = Targets{AllDevices: true, DeviceGroups: []string{}}
	if d := decideInputs(in); d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{Code: CodeTargetsAllDevices}}) {
		t.Fatalf("upload upgrade keeping all_devices: %+v", d)
	}
	in = installed(allKinds(t))
	in.s.Install.Targets = Targets{AllDevices: true, DeviceGroups: []string{}, Console: true, Jobs: true}
	in.r.Targets = in.s.Install.Targets
	in.r.GrantUpdate = true
	if d := decideInputs(in); d.Outcome != ApprovalRequired {
		t.Fatalf("grant update keeping all_devices: %+v", d)
	}
}

// TestBindingHolder: an active binding blocks only when another id holds it.
func TestBindingHolder(t *testing.T) {
	base := "registration-bound-recovery-pending-holder"
	in := caseInputs(t, base)
	reg := findRegistration(&in.s, chromeRegistration)
	if reg == nil || reg.Bound == nil {
		t.Fatalf("%s has no bound registration", base)
	}
	component := in.e.Components[0].Name
	for _, c := range []struct {
		name    string
		bound   Bound
		blocked bool
	}{
		{"same id and component", Bound{ID: in.e.ID, Component: component, State: StateActive}, false},
		{"same id, renamed component", Bound{ID: in.e.ID, Component: "renamed", State: StateActive}, false},
		{"other id, same component", Bound{ID: "com.example.other", Component: component, State: StateActive}, true},
		{"other id, recovery pending", Bound{ID: "com.example.other", Component: component, State: StateRecoveryPending}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := caseInputs(t, base)
			b := c.bound
			findRegistration(&in.s, chromeRegistration).Bound = &b
			d := decideInputs(in)
			if c.blocked {
				if d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeComponentRegistrationBound, component}}) {
					t.Fatalf("got %+v, want component.registration_bound", d)
				}
			} else if d.Outcome != ApprovalRequired {
				t.Fatalf("got %+v, want approval_required", d)
			}
		})
	}
}

// TestOneDefectOneReason: a malformed evidence id is input.evidence alone,
// not also input.snapshot from the evidence-relative snapshot rules (R-04).
func TestOneDefectOneReason(t *testing.T) {
	for _, name := range []string{"upgrade-admit", "prior-owner-rollback-upgrade", "revocation-version", "input-snapshot-ownership-other-id"} {
		in := caseInputs(t, name)
		in.e.ID = "Bad.ID"
		// input-snapshot-ownership-other-id breaks only rule 4, which
		// compares with the evidence id, so the evidence defect is all that
		// remains to report.
		d := decideInputs(in)
		if d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{Code: CodeInputEvidence}}) {
			t.Errorf("%s with a bad evidence id: %+v", name, d)
		}
		in = caseInputs(t, name)
		in.e.Version = "1.0"
		if d := decideInputs(in); !slices.Equal(d.Reasons, []Reason{{Code: CodeInputEvidence}}) {
			t.Errorf("%s with a bad evidence version: %+v", name, d)
		}
	}
}

// TestDuplicateKeysAfterEightMembers covers the map path of the duplicate
// check, which objects with eight or more members take.
func TestDuplicateKeysAfterEightMembers(t *testing.T) {
	snapshot, _ := corpusRaw(t, 0)
	for _, dup := range []string{`,"consumed_approvals":[]}`, `,"recovery_epoch":"3"}`, `,"recovery_epoch":"3"}`} {
		data := append(append([]byte{}, snapshot[:len(snapshot)-1]...), dup...)
		if _, err := ParseSnapshot(data); !errors.Is(err, ErrJSON) {
			t.Errorf("duplicate %s: %v, want ErrJSON", dup, err)
		}
	}
	collector := grantCase(t, "collector-max-generation-lexeme")
	data := replaceOnce(t, collector, `"disclosure_profile":"inventory.software.v1"}`, `"disclosure_profile":"inventory.software.v1","max_rows":100}`)
	if _, err := ParseGrantRecord(data); !errors.Is(err, ErrJSON) {
		t.Errorf("duplicate value member: %v, want ErrJSON", err)
	}
}
