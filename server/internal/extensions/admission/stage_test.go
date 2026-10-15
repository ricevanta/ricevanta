package admission

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

type inputs struct {
	e Evidence
	s Snapshot
	r Request
	v []Verdict
}

func caseInputs(t testing.TB, name string) inputs {
	t.Helper()
	for _, c := range corpusCases(t) {
		if c.Name == name {
			e, err, s, r, v, _ := corpusInputs(t, c)
			if err != nil {
				t.Fatal(err)
			}
			return inputs{e, s, r, v}
		}
	}
	t.Fatalf("no corpus case %q", name)
	return inputs{}
}

const partnerKey = "sha256:24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28"

// stageDefects break exactly one stage of install-new-admit each.
var stageDefects = []struct {
	stage  Stage
	mutate func(*inputs)
}{
	{StageInput, func(in *inputs) { in.r.Requester = SystemPrincipal }},
	{StageKey, func(in *inputs) { findEntry(&in.s, in.e.PublisherFingerprint).Revoked = true }},
	{StageNamespace, func(in *inputs) { findEntry(&in.s, in.e.PublisherFingerprint).Prefixes = []string{"org.example"} }},
	{StageRevocation, func(in *inputs) { in.s.Revocations = []Revocation{{ID: in.e.ID}} }},
	{StageTombstone, func(in *inputs) {
		in.s.Tombstones = []Tombstone{{ID: in.e.ID, Version: in.e.Version, Publisher: in.e.PublisherFingerprint, ManifestSHA256: in.e.ManifestSHA256, PackageSHA256: [32]byte{9}}}
	}},
	{StageOwnership, func(in *inputs) { in.s.Ownership = &Ownership{ID: in.e.ID, Owner: partnerKey, OwnershipGeneration: 1} }},
	{StageInterface, func(in *inputs) {
		in.s.ServedInterfaces = slices.DeleteFunc(in.s.ServedInterfaces, func(s string) bool { return s == "ext.ricevanta.io/content/v1" })
	}},
	{StageComponent, func(in *inputs) { in.v[0].OK = false }},
	{StageTargets, func(in *inputs) {
		in.r.Targets.DeviceGroups = append(in.r.Targets.DeviceGroups, "017f22e2-79b0-7cc3-98c4-dc0c0c0739ff")
	}},
	{StageGrant, func(in *inputs) { in.r.Grants[0].Component = "other" }},
	{StageApproval, func(in *inputs) { in.r.Approval.RequestDigest = "sha256:" + strings.Repeat("0", 64) }},
}

func TestStageIsolation(t *testing.T) {
	base := "install-new-admit"
	if d := decideInputs(caseInputs(t, base)); d.Outcome != Admit {
		t.Fatalf("base case %s: %+v", base, d)
	}
	alone := map[Stage]Decision{}
	for _, defect := range stageDefects {
		in := caseInputs(t, base)
		defect.mutate(&in)
		d := decideInputs(in)
		if d.Outcome != Reject || d.Stage != defect.stage {
			t.Fatalf("defect for %s alone: %+v", defect.stage, d)
		}
		alone[defect.stage] = d
	}
	for i := 0; i+1 < len(stageDefects); i++ {
		for _, order := range [][2]int{{i, i + 1}, {i + 1, i}} {
			in := caseInputs(t, base)
			stageDefects[order[0]].mutate(&in)
			stageDefects[order[1]].mutate(&in)
			d := decideInputs(in)
			earlier := stageDefects[i].stage
			if !reflect.DeepEqual(d, alone[earlier]) {
				t.Errorf("%s with %s: %+v, want only %+v", earlier, stageDefects[i+1].stage, d, alone[earlier])
			}
		}
	}
}

func decideInputs(in inputs) Decision { return Decide(in.e, in.s, in.r, in.v) }

// permute reverses every array whose order the decision must not depend on.
func permute(in *inputs) {
	for k := range in.e.Requires {
		slices.Reverse(in.e.Requires[k])
	}
	s := &in.s
	slices.Reverse(s.ServedInterfaces)
	slices.Reverse(s.TrustList)
	for i := range s.TrustList {
		slices.Reverse(s.TrustList[i].Prefixes)
	}
	slices.Reverse(s.Revocations)
	if s.Ownership != nil {
		slices.Reverse(s.Ownership.PriorOwners)
	}
	slices.Reverse(s.Tombstones)
	if s.Install != nil {
		slices.Reverse(s.Install.Grants)
		slices.Reverse(s.Install.Targets.DeviceGroups)
	}
	slices.Reverse(s.Registrations)
	slices.Reverse(s.DisclosureProfiles)
	slices.Reverse(s.DeviceGroups)
	slices.Reverse(in.r.Grants)
	slices.Reverse(in.r.Targets.DeviceGroups)
	slices.Reverse(in.v)
}

func TestPermutationInvariance(t *testing.T) {
	for _, c := range corpusCases(t) {
		e, err, s, r, v, _ := corpusInputs(t, c)
		if err != nil {
			e = Evidence{}
		}
		want := Decide(e, s, r, v)
		e2, err, s2, r2, v2, _ := corpusInputs(t, c)
		if err != nil {
			e2 = Evidence{}
		}
		in := inputs{e2, s2, r2, v2}
		permute(&in)
		if got := decideInputs(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: permuted inputs changed the decision: %+v, want %+v", c.Name, got, want)
		}
	}
}

// scribble overwrites every string and flag reachable through input slices,
// maps and pointers, in place.
func scribble(in *inputs) {
	for k := range in.e.Requires {
		for i := range in.e.Requires[k] {
			in.e.Requires[k][i] = "x"
		}
	}
	for i := range in.e.Components {
		c := &in.e.Components[i]
		c.Name = "x"
		for j := range c.Slots {
			c.Slots[j] = "x"
		}
	}
	s := &in.s
	for i := range s.ServedInterfaces {
		s.ServedInterfaces[i] = "x"
	}
	for i := range s.TrustList {
		s.TrustList[i].Fingerprint = "x"
		for j := range s.TrustList[i].Prefixes {
			s.TrustList[i].Prefixes[j] = "x"
		}
	}
	for i := range s.Tombstones {
		s.Tombstones[i].Version = "x"
	}
	if s.Ownership != nil {
		s.Ownership.Owner = "x"
	}
	if s.Install != nil {
		s.Install.Enabled = !s.Install.Enabled
		for i := range s.Install.Targets.DeviceGroups {
			s.Install.Targets.DeviceGroups[i] = "x"
		}
		for i := range s.Install.Grants {
			s.Install.Grants[i].Grant.Component = "x"
		}
	}
	for i := range s.Registrations {
		s.Registrations[i].ID = "x"
		if b := s.Registrations[i].Bound; b != nil {
			b.Component = "x"
		}
	}
	for i := range in.r.Grants {
		in.r.Grants[i].Component = "x"
		if b := in.r.Grants[i].Values.BrowserAdapter; b != nil {
			b.Registration = "x"
		}
	}
	for i := range in.r.Targets.DeviceGroups {
		in.r.Targets.DeviceGroups[i] = "x"
	}
	if in.r.Approval != nil {
		in.r.Approval.ApprovalUID = "x"
	}
	for i := range in.v {
		in.v[i].Component = "x"
	}
}

func TestNoAliasing(t *testing.T) {
	admitted := 0
	for _, c := range corpusCases(t) {
		e, err, s, r, v, _ := corpusInputs(t, c)
		if err != nil {
			continue
		}
		in := inputs{e, s, r, v}
		d := decideInputs(in)
		reference := decideInputs(caseInputs(t, c.Name))
		pristine := caseInputs(t, c.Name)
		if !reflect.DeepEqual(in, pristine) {
			t.Errorf("%s: Decide mutated its inputs", c.Name)
		}
		scribble(&in)
		if !reflect.DeepEqual(d, reference) {
			t.Errorf("%s: mutating inputs after Decide changed the decision", c.Name)
		}
		if d.Intent == nil {
			continue
		}
		admitted++
		check := caseInputs(t, c.Name)
		dd := decideInputs(check)
		for i := range dd.Reasons {
			dd.Reasons[i].Subject = "x"
		}
		for i := range dd.Intent.Grants {
			dd.Intent.Grants[i] = "x"
		}
		for i := range dd.Intent.Targets.DeviceGroups {
			dd.Intent.Targets.DeviceGroups[i] = "x"
		}
		for i := range dd.Intent.RegistrationBind {
			dd.Intent.RegistrationBind[i].Component = "x"
		}
		if !reflect.DeepEqual(check, caseInputs(t, c.Name)) {
			t.Errorf("%s: decision slices alias inputs", c.Name)
		}
	}
	if admitted != 18 {
		t.Errorf("checked %d admitted decisions, want 18", admitted)
	}
}

// TestHandBuiltInputs: malformed typed values that never passed a parser
// are refused at the input stage, never decided and never a panic.
func TestHandBuiltInputs(t *testing.T) {
	cases := map[string]struct {
		code   Code
		mutate func(*inputs)
	}{
		"zero evidence":        {CodeInputEvidence, func(in *inputs) { in.e = Evidence{} }},
		"zero snapshot":        {CodeInputSnapshot, func(in *inputs) { in.s = Snapshot{} }},
		"zero request":         {CodeInputRequest, func(in *inputs) { in.r = Request{} }},
		"non-ascii group":      {CodeInputRequest, func(in *inputs) { in.r.Targets.DeviceGroups = []string{"é"} }},
		"grant without values": {CodeInputRequest, func(in *inputs) { in.r.Grants[0].Values = Values{} }},
		"approval stray field": {CodeInputRequest, func(in *inputs) { in.r.Approval.Principal = in.r.Requester }},
		"bad release version":  {CodeInputSnapshot, func(in *inputs) { in.s.ReleaseVersion = "latest" }},
		"bad trust name":       {CodeInputSnapshot, func(in *inputs) { in.s.TrustList[0].Name = "a\x85b" }},
		"invalid utf-8 name":   {CodeInputSnapshot, func(in *inputs) { in.s.TrustList[0].Name = "a\xffb" }},
		"install no grants":    {CodeInputSnapshot, func(in *inputs) { in.s.Install = &Install{ID: in.e.ID, Version: in.e.Version, State: StateActive} }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := caseInputs(t, "install-new-admit")
			c.mutate(&in)
			d := decideInputs(in)
			if d.Outcome != Reject || d.Stage != StageInput || !slices.Contains(d.Reasons, Reason{Code: c.code}) {
				t.Fatalf("got %+v, want input reject with %s", d, c.code)
			}
		})
	}
	if d := Decide(Evidence{}, Snapshot{}, Request{}, nil); d.Outcome != Reject || len(d.Reasons) != 3 {
		t.Fatalf("all-zero inputs: %+v", d)
	}
}
