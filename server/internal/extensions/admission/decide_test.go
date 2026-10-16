package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
)

// agentInputs replaces install-new-approval-required's package with one
// component per agent interface and proposes exactly the requested values.
func agentInputs(t testing.TB) inputs {
	t.Helper()
	in := caseInputs(t, "install-new-approval-required")
	budget := AgentModuleValues{MemoryPages: 256, FuelPerCall: 1000000, DeadlineMS: 500}
	classifier, parser, collector, responder := budget, budget, budget, budget
	parser.MIMETypes = []string{"application/x-a", "application/x-b"}
	collector.MaxRoots, collector.MaxPathDepth, collector.MaxDirectoryEntries, collector.MaxOpenHandles = 2, 4, 100, 4
	collector.MaxListRequests, collector.MaxReadRequests, collector.MaxBytesPerFile = 16, 16, 65536
	collector.MaxInputBytes, collector.MaxRows, collector.MaxOutputBytes = 262144, 100, 65536
	responder.Actions = []string{"edr.collect", "edr.scan"}
	responder.MaxEntities, responder.MaxParametersBytes, responder.MaxPlanSteps, responder.MaxPlanBytes = 16, 4096, 8, 65536
	in.e.Components = []Component{
		{Name: "classifier", Kind: kindAgentModule, Interface: ifaceClassifier, Requested: Values{AgentModule: &classifier}},
		{Name: "collector", Kind: kindAgentModule, Interface: ifaceCollector, Requested: Values{AgentModule: &collector}},
		{Name: "parser", Kind: kindAgentModule, Interface: ifaceParser, Requested: Values{AgentModule: &parser}},
		{Name: "responder", Kind: kindAgentModule, Interface: ifaceResponder, Requested: Values{AgentModule: &responder}},
	}
	in.e.Requires = map[string][]string{kindAgentModule: {ifaceClassifier, ifaceCollector, ifaceParser, ifaceResponder}}
	in.r.Grants = nil
	in.v = nil
	for _, c := range in.e.Components {
		values := *c.Requested.AgentModule
		if c.Interface == ifaceCollector {
			values.Roots = []Root{{OS: "linux", Path: "/var/lib/example"}, {OS: "windows", Path: `C:\Data`}}
			values.DisclosureProfile = "inventory.software.v1"
		}
		in.r.Grants = append(in.r.Grants, Grant{Component: c.Name, Kind: c.Kind, Interface: c.Interface, Values: Values{AgentModule: &values}})
		in.v = append(in.v, Verdict{Component: c.Name, OK: true})
	}
	return in
}

func TestDecideValueBounds(t *testing.T) {
	if d := decideInputs(agentInputs(t)); d.Outcome != ApprovalRequired {
		t.Fatalf("grants equal to the request: %+v", d)
	}
	for i, c := range agentInputs(t).e.Components {
		for _, f := range numericFields(c.Interface) {
			for _, delta := range []int{-1, 0, 1} {
				in := agentInputs(t)
				values := *in.r.Grants[i].Values.AgentModule
				*f.get(&values) = uint64(int(*f.get(&values)) + delta)
				in.r.Grants[i].Values.AgentModule = &values
				d := decideInputs(in)
				switch {
				case f.name == "max_roots" && delta == -1:
					// Two roots exceed a max_roots narrowed to one.
					if d.Outcome != Reject || !slices.Equal(d.Reasons, []Reason{{CodeGrantRoots, c.Name}}) {
						t.Errorf("%s %s%+d: %+v", c.Name, f.name, delta, d)
					}
				case delta <= 0:
					if d.Outcome != ApprovalRequired {
						t.Errorf("%s %s%+d: %+v", c.Name, f.name, delta, d)
					}
				default:
					if d.Outcome != Reject || d.Stage != StageGrant || !slices.Equal(d.Reasons, []Reason{{CodeGrantExceeds, c.Name}}) {
						t.Errorf("%s %s%+d: %+v", c.Name, f.name, delta, d)
					}
				}
			}
		}
	}
	for name, mutate := range map[string]func(*inputs){
		"mime type not requested": func(in *inputs) { in.r.Grants[2].Values.AgentModule.MIMETypes = []string{"text/plain"} },
		"action not requested":    func(in *inputs) { in.r.Grants[3].Values.AgentModule.Actions = []string{"edr.kill_process"} },
	} {
		in := agentInputs(t)
		mutate(&in)
		if d := decideInputs(in); d.Outcome != Reject || d.Stage != StageGrant {
			t.Errorf("%s: %+v", name, d)
		}
	}
	in := agentInputs(t)
	in.r.Grants[2].Values.AgentModule.MIMETypes = in.r.Grants[2].Values.AgentModule.MIMETypes[:1]
	in.r.Grants[3].Values.AgentModule.Actions = in.r.Grants[3].Values.AgentModule.Actions[1:]
	if d := decideInputs(in); d.Outcome != ApprovalRequired {
		t.Errorf("narrower sets: %+v", d)
	}
}

// TestDecideMaximal decides 64 components, 1,024 device groups, a full
// trust list and 1,023 prior owners.
func TestDecideMaximal(t *testing.T) {
	in := caseInputs(t, "install-new-approval-required")
	in.e.Components = nil
	in.r.Grants = nil
	in.v = nil
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("c%02d", i)
		in.e.Components = append(in.e.Components, Component{Name: name, Kind: kindContent, Interface: "ext.ricevanta.io/content/v1", Format: "sigma", Requested: Values{Content: &struct{}{}}})
		in.r.Grants = append(in.r.Grants, Grant{Component: name, Kind: kindContent, Interface: "ext.ricevanta.io/content/v1", Values: Values{Content: &struct{}{}}})
		in.v = append(in.v, Verdict{Component: name, OK: true})
	}
	in.s.DeviceGroups = nil
	for i := 0; i < 1024; i++ {
		in.s.DeviceGroups = append(in.s.DeviceGroups, uuid7(i))
	}
	in.r.Targets.DeviceGroups = append([]string{}, in.s.DeviceGroups...)
	var priors []string
	for i := 0; len(in.s.TrustList) < 1024; i++ {
		key := [32]byte{0xee, byte(i), byte(i >> 8)}
		sum := sha256.Sum256(key[:])
		fp := "sha256:" + hex.EncodeToString(sum[:])
		in.s.TrustList = append(in.s.TrustList, TrustEntry{Fingerprint: fp, PublicKey: key, Name: "Imported", Prefixes: []string{"org.imported"}, Generation: 1})
		priors = append(priors, fp)
	}
	priors = append(priors, partnerKey, in.s.ProjectKey)
	if len(priors) != 1023 {
		t.Fatalf("%d prior owners", len(priors))
	}
	in.s.Ownership = &Ownership{ID: in.e.ID, Owner: in.e.PublisherFingerprint, PriorOwners: priors, OwnershipGeneration: 7}
	d := decideInputs(in)
	if d.Outcome != ApprovalRequired || d.Operation != OperationInstall {
		t.Fatalf("maximal decision: %+v", d)
	}
	in.r.Targets.DeviceGroups = append(in.r.Targets.DeviceGroups, uuid7(5000))
	if d := decideInputs(in); d.Outcome != Reject || d.Stage != StageInput {
		t.Fatalf("1,025 device groups: %+v", d)
	}
}

func TestUint64Digest(t *testing.T) {
	for n, want := range map[uint64]string{0: `"0"`, 1: `"1"`, ^uint64(0): `"18446744073709551615"`} {
		b, err := u64(n).encode(nil)
		if err != nil || string(b) != want {
			t.Errorf("%d: %s %v", n, b, err)
		}
	}
}
