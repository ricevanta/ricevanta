package admission

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func decodeJSONInto(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// fuzzEvidence is every distinct valid evidence the corpus embeds.
func fuzzEvidence(f *testing.F) ([]Evidence, map[string]int) {
	f.Helper()
	var out []Evidence
	index := map[string]int{}
	for _, c := range corpusCases(f) {
		e, err := FromPackage(corpusPackage(f, c.Evidence), manifest.Options{})
		if err != nil {
			continue
		}
		key := e.ID + "@" + e.Version + "@" + e.PublisherFingerprint + string(e.PackageSHA256[:]) + string(e.ManifestSHA256[:])
		if _, ok := index[key]; !ok {
			index[key] = len(out)
			out = append(out, e)
		}
		index[c.Name] = index[key]
	}
	return out, index
}

func FuzzDecide(f *testing.F) {
	evidence, index := fuzzEvidence(f)
	for _, c := range corpusCases(f) {
		i, ok := index[c.Name]
		if !ok {
			i = 0
		}
		f.Add(compact(f, c.Snapshot), compact(f, c.Request), uint8(i), uint8(0))
	}
	for _, c := range schemaCases(f, "admission-vectors/schema-cases.json", "admission-vectors.schema.json") {
		var envelope struct {
			Cases []corpusCase `json:"cases"`
		}
		if decodeJSONInto(c.Instance, &envelope) != nil {
			continue
		}
		for _, v := range envelope.Cases {
			f.Add([]byte(v.Snapshot), []byte(v.Request), uint8(0), uint8(1))
		}
	}
	f.Fuzz(func(t *testing.T, snapshot, request []byte, which, verdictMask uint8) {
		s, err := ParseSnapshot(snapshot)
		if err != nil {
			return
		}
		r, err := ParseRequest(request)
		if err != nil {
			return
		}
		e := evidence[int(which)%len(evidence)]
		var v []Verdict
		for i, c := range e.Components {
			if verdictMask&(1<<(i%7)) != 0 && verdictMask&0x80 != 0 {
				continue
			}
			v = append(v, Verdict{Component: c.Name, OK: verdictMask&(1<<(i%7)) == 0})
		}
		d := Decide(e, s, r, v)
		if again := Decide(e, s, r, v); !reflect.DeepEqual(d, again) {
			t.Fatal("nondeterministic decision")
		}
		checkInvariants(t, e, s, r, v, d)
	})
}

// checkInvariants rechecks every admitted decision independently of the
// stage code, and the zero-value rules of every outcome.
func checkInvariants(t *testing.T, e Evidence, s Snapshot, r Request, v []Verdict, d Decision) {
	t.Helper()
	switch d.Outcome {
	case Reject:
		if d.Stage == "" || len(d.Reasons) == 0 || d.Operation != "" || d.ClosureDigest != "" || d.RequestDigest != "" || d.Intent != nil {
			t.Fatalf("malformed reject: %+v", d)
		}
		return
	case IdenticalRetry:
		if d.Stage != "" || len(d.Reasons) != 0 || d.Operation != "" || d.ClosureDigest != "" || d.Intent != nil {
			t.Fatalf("malformed identical retry: %+v", d)
		}
		if s.Install == nil || s.Install.State != StateActive || s.Install.Version != e.Version || r.GrantUpdate {
			t.Fatal("identical retry without an active install of this version")
		}
		return
	case ApprovalRequired:
		if d.Intent != nil || d.Stage != "" {
			t.Fatalf("malformed approval_required: %+v", d)
		}
		for _, reason := range d.Reasons {
			switch reason.Code {
			case CodeApprovalReleaseOperation, CodeApprovalWidened, CodeApprovalTargetsChanged:
			default:
				t.Fatalf("approval_required with %s", reason.Code)
			}
		}
		if len(d.Reasons) > 0 && (r.Approval == nil || r.Approval.Kind != ReleaseFixed) {
			t.Fatal("release reasons without a release-fixed approval")
		}
	case Admit:
	default:
		t.Fatalf("unknown outcome %q", d.Outcome)
	}
	closure, err := ClosureDigest(e, s, r)
	if err != nil || closure != d.ClosureDigest {
		t.Fatalf("closure digest %s %v, decision %s", closure, err, d.ClosureDigest)
	}
	request, err := RequestDigest(e, s, r, d.Operation)
	if err != nil || request != d.RequestDigest {
		t.Fatalf("request digest %s %v, decision %s", request, err, d.RequestDigest)
	}
	if d.Outcome != Admit {
		return
	}
	a := r.Approval
	if a == nil || d.Intent == nil || d.Intent.Operation != d.Operation || d.Intent.ApprovalKind != a.Kind {
		t.Fatalf("admit without approval or intent: %+v", d)
	}
	// Key and owner rules.
	var entry *TrustEntry
	for i := range s.TrustList {
		if s.TrustList[i].Fingerprint == e.PublisherFingerprint {
			entry = &s.TrustList[i]
		}
	}
	if entry == nil || entry.Revoked || entry.Retired && !r.GrantUpdate {
		t.Fatal("admitted under an unknown, revoked or retired key")
	}
	var tomb *Tombstone
	for i := range s.Tombstones {
		if s.Tombstones[i].Version == e.Version {
			tomb = &s.Tombstones[i]
		}
	}
	if tomb != nil && (tomb.Publisher != e.PublisherFingerprint || tomb.PackageSHA256 != e.PackageSHA256 || tomb.ManifestSHA256 != e.ManifestSHA256) {
		t.Fatal("admitted bytes that differ from the tombstone")
	}
	if o := s.Ownership; o != nil {
		prior := false
		for _, p := range o.PriorOwners {
			prior = prior || p == e.PublisherFingerprint
		}
		if o.Owner != e.PublisherFingerprint && !(prior && tomb != nil) {
			t.Fatal("a non-owner published")
		}
	} else {
		n, only := 0, ""
		for _, t := range s.TrustList {
			for _, p := range t.Prefixes {
				if !t.Retired && (e.ID == p || len(e.ID) > len(p) && e.ID[:len(p)+1] == p+".") {
					n++
					only = t.Fingerprint
					break
				}
			}
		}
		if n != 1 || only != e.PublisherFingerprint || !d.Intent.OwnershipCreate {
			t.Fatal("ownership created without a single covering key")
		}
	}
	// Subset rule against the manifest request, rechecked field by field.
	if len(r.Grants) != len(e.Components) {
		t.Fatal("grant count differs from component count")
	}
	for _, c := range e.Components {
		var g *Grant
		for i := range r.Grants {
			if r.Grants[i].Component == c.Name {
				g = &r.Grants[i]
			}
		}
		if g == nil || g.Kind != c.Kind || g.Interface != c.Interface {
			t.Fatalf("component %s has no matching grant", c.Name)
		}
		recheckWithin(t, c, g)
	}
	// System principal and approval kind rules.
	if (r.Source == SourceServerImage) != (r.Requester == SystemPrincipal) || a.Approver == SystemPrincipal || a.Principal == SystemPrincipal {
		t.Fatal("system principal rule broken")
	}
	if r.Targets.AllDevices && r.Source != SourceServerImage && !(r.GrantUpdate && s.Install != nil && s.Install.Targets.AllDevices) {
		t.Fatal("all_devices from another source")
	}
	consumed := false
	for _, u := range s.ConsumedApprovals {
		consumed = consumed || u == a.ApprovalUID
	}
	switch a.Kind {
	case Operator, SingleAdministrator:
		if a.RequestDigest != d.RequestDigest || a.RecoveryEpoch != s.RecoveryEpoch || consumed || d.Intent.ApprovalConsume != a.ApprovalUID {
			t.Fatal("approval binding or consumption broken")
		}
		if a.Kind == Operator && a.Approver == r.Requester {
			t.Fatal("operator approved its own request")
		}
		if a.Kind == SingleAdministrator && (!s.ApprovalPolicyDisabled || a.Principal != r.Requester || r.Source == SourceServerImage) {
			t.Fatal("exemption outside the single-administrator setting")
		}
	case ReleaseFixed:
		reserved := e.ID == "io.ricevanta" || len(e.ID) > 13 && e.ID[:13] == "io.ricevanta."
		if !entry.ProjectPublisher || entry.Fingerprint != s.ProjectKey || !reserved || r.Source != SourceServerImage ||
			s.ReleaseVersion == "" || a.ReleaseVersion != s.ReleaseVersion || a.ReleaseVersion != e.Version || d.Intent.ApprovalConsume != "" {
			t.Fatal("release-fixed preconditions broken")
		}
		in := s.Install
		switch d.Operation {
		case OperationInstall:
			if !s.FirstStart || !d.Intent.Enabled {
				t.Fatal("release-fixed install outside first start")
			}
		case OperationUpgrade, OperationReinstall:
			if in == nil || d.Operation == OperationReinstall && (in.State != StateRecoveryPending || in.Version != e.Version) {
				t.Fatal("release-fixed reinstall of an uninstalled pair")
			}
			if !targetsEqual(&r.Targets, &in.Targets) || d.Intent.Enabled != in.Enabled {
				t.Fatal("release-fixed changed targets or the enabled state")
			}
		default:
			t.Fatal("release-fixed grant update")
		}
	}
}

// recheckWithin repeats the per-kind subset rule without the stage code.
func recheckWithin(t *testing.T, c Component, g *Grant) {
	t.Helper()
	within := func(values, of []string) {
		for _, v := range values {
			found := false
			for _, o := range of {
				found = found || v == o
			}
			if !found {
				t.Fatalf("%s: %q exceeds the request", c.Name, v)
			}
		}
	}
	req := c.Requested
	switch c.Kind {
	case kindBrowserAdapter:
		b, q := g.Values.BrowserAdapter, req.BrowserAdapter
		if b.Registration != q.Registration {
			t.Fatal("adapter grant names another registration")
		}
		for _, pair := range [][2]*OSPolicy{{b.OS.MacOS, q.OS.MacOS}, {b.OS.Windows, q.OS.Windows}, {b.OS.Linux, q.OS.Linux}} {
			if pair[0] == nil {
				continue
			}
			if pair[1] == nil || pair[0].NativeHost && !pair[1].NativeHost {
				t.Fatal("adapter grant exceeds the request")
			}
			within(pair[0].PolicyNames, pair[1].PolicyNames)
		}
	case kindAgentModule:
		a, q := reflect.ValueOf(*g.Values.AgentModule), reflect.ValueOf(*req.AgentModule)
		for i := 0; i < a.NumField(); i++ {
			if a.Field(i).Kind() == reflect.Uint64 && a.Field(i).Uint() > q.Field(i).Uint() {
				t.Fatalf("%s: %s exceeds the request", c.Name, a.Type().Field(i).Name)
			}
		}
		within(g.Values.AgentModule.MIMETypes, req.AgentModule.MIMETypes)
		within(g.Values.AgentModule.Actions, req.AgentModule.Actions)
		if c.Interface == ifaceCollector && uint64(len(g.Values.AgentModule.Roots)) > g.Values.AgentModule.MaxRoots {
			t.Fatal("collector roots above max_roots")
		}
	case kindConsoleModule:
		for slot, ops := range g.Values.ConsoleModule.Slots {
			within([]string{slot}, c.Slots)
			within(ops, req.ConsoleModule.Slots[slot])
		}
	case kindServiceConnector:
		for _, o := range g.Values.ServiceConnector.Outbound {
			found := false
			for _, p := range req.ServiceConnector.Outbound {
				found = found || o == p
			}
			if !found {
				t.Fatal("connector grant exceeds the request")
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, c := range corpusCases(f) {
		f.Add(uint8(0), compact(f, c.Snapshot))
		f.Add(uint8(1), compact(f, c.Request))
	}
	for _, c := range schemaCases(f, "capability-grant/schema-cases.json", "capability-grant.schema.json") {
		f.Add(uint8(2), compact(f, c.Instance))
	}
	for _, c := range schemaCases(f, "extension-resource/schema-cases.json", "extension-resource.schema.json") {
		f.Add(uint8(3), compact(f, c.Instance))
	}
	sentinels := []error{ErrJSON, ErrShape, ErrField, ErrGrant}
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		var err, again error
		var value, second any
		switch which % 4 {
		case 0:
			value, err = ParseSnapshot(data)
			second, again = ParseSnapshot(data)
			if err == nil {
				var c checker
				s := value.(Snapshot)
				c.validSnapshot(&s)
				if c.fieldFail || c.grantFail {
					t.Fatal("parsed snapshot fails typed validation")
				}
			}
		case 1:
			value, err = ParseRequest(data)
			second, again = ParseRequest(data)
			if err == nil {
				var c checker
				r := value.(Request)
				c.validRequest(&r)
				if c.fieldFail || c.grantFail {
					t.Fatal("parsed request fails typed validation")
				}
			}
		case 2:
			value, err = ParseGrantRecord(data)
			second, again = ParseGrantRecord(data)
		case 3:
			value, err = ParseResource(data)
			second, again = ParseResource(data)
		}
		if err != again || !reflect.DeepEqual(value, second) {
			t.Fatal("nondeterministic parse")
		}
		if err == nil {
			return
		}
		matched := 0
		for _, s := range sentinels {
			if errors.Is(err, s) {
				matched++
			}
		}
		if matched != 1 || errors.Is(err, ErrEvidence) {
			t.Fatalf("error %v is not exactly one parse sentinel", err)
		}
	})
}
