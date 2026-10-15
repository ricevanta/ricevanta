package admission

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type corpusCase struct {
	Name     string          `json:"name"`
	Evidence json.RawMessage `json:"evidence"`
	Snapshot json.RawMessage `json:"snapshot"`
	Request  json.RawMessage `json:"request"`
	Verdicts json.RawMessage `json:"verdicts"`
	Expected json.RawMessage `json:"expected"`
}

func corpusCases(t testing.TB) []corpusCase {
	t.Helper()
	b, err := os.ReadFile(schemaDir + "admission-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Profile string       `json:"profile"`
		Cases   []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Profile != "extension-admission-v1alpha1" || len(corpus.Cases) != 140 {
		t.Fatalf("unexpected corpus header: %q, %d cases", corpus.Profile, len(corpus.Cases))
	}
	return corpus.Cases
}

func reasonsOf(x expectation) []Reason {
	out := []Reason{}
	for _, r := range x.Reasons {
		out = append(out, Reason{Code: Code(r.Code), Subject: r.Subject})
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func checkDecision(t *testing.T, d Decision, x expectation) {
	t.Helper()
	if string(d.Outcome) != x.Outcome {
		t.Fatalf("outcome %q, want %q (stage %q reasons %v)", d.Outcome, x.Outcome, d.Stage, d.Reasons)
	}
	if string(d.Operation) != x.Operation || string(d.Stage) != x.Stage {
		t.Errorf("operation %q stage %q, want %q %q", d.Operation, d.Stage, x.Operation, x.Stage)
	}
	want := reasonsOf(x)
	if len(d.Reasons) != len(want) {
		t.Fatalf("reasons %v, want %v", d.Reasons, want)
	}
	for i := range want {
		if d.Reasons[i] != want[i] {
			t.Fatalf("reasons %v, want %v", d.Reasons, want)
		}
	}
	if d.ClosureDigest != x.ClosureDigest || d.RequestDigest != x.RequestDigest {
		t.Errorf("digests %s %s, want %s %s", d.ClosureDigest, d.RequestDigest, x.ClosureDigest, x.RequestDigest)
	}
	switch d.Outcome {
	case Reject, IdenticalRetry:
		if d.Operation != "" || d.ClosureDigest != "" || d.RequestDigest != "" || d.Intent != nil {
			t.Error("reject or identical retry carries an operation, digest or intent")
		}
	case ApprovalRequired:
		if d.Stage != "" || d.Intent != nil {
			t.Error("approval_required carries a stage or intent")
		}
	case Admit:
		if d.Stage != "" || len(d.Reasons) != 0 {
			t.Error("admit carries a stage or reasons")
		}
	}
	if (d.Intent == nil) != (x.Intent == nil) {
		t.Fatalf("intent %+v, want %+v", d.Intent, x.Intent)
	}
	if x.Intent == nil {
		return
	}
	in, w := d.Intent, x.Intent
	consume := ""
	if w.ApprovalConsume != nil {
		consume = *w.ApprovalConsume
	}
	if string(in.Operation) != w.Operation || string(in.ApprovalKind) != w.ApprovalKind || in.TombstoneCreate != w.TombstoneCreate ||
		in.OwnershipCreate != w.OwnershipCreate || in.Enabled != w.Enabled || !sameStrings(in.Grants, w.Grants) || in.ApprovalConsume != consume {
		t.Errorf("intent %+v, want %+v", *in, *w)
	}
	if !sameStrings(in.Targets.DeviceGroups, w.Targets.DeviceGroups) || in.Targets.AllDevices != w.Targets.AllDevices ||
		in.Targets.Console != w.Targets.Console || in.Targets.Jobs != w.Targets.Jobs {
		t.Errorf("intent targets %+v, want %+v", in.Targets, w.Targets)
	}
	if len(in.RegistrationBind) != len(w.RegistrationBind) {
		t.Fatalf("bindings %+v, want %+v", in.RegistrationBind, w.RegistrationBind)
	}
	for i, b := range w.RegistrationBind {
		if in.RegistrationBind[i] != (Binding{Registration: b.Registration, Component: b.Component}) {
			t.Errorf("bindings %+v, want %+v", in.RegistrationBind, w.RegistrationBind)
		}
	}
	if in.Operation != d.Operation {
		t.Error("intent operation differs from the decision's")
	}
}

func TestVectors(t *testing.T) {
	outcomes := map[string]int{}
	for _, c := range corpusCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			e, evidenceErr, s, r, v, x := corpusInputs(t, c)
			if evidenceErr != nil {
				// The loader result fails FromPackage; the zero evidence it
				// leaves must be refused at input, never decided.
				e = Evidence{}
			}
			d := Decide(e, s, r, v)
			checkDecision(t, d, x)
			if again := Decide(e, s, r, v); !reflect.DeepEqual(again, d) {
				t.Error("second decision differs")
			}
			outcomes[x.Outcome]++
		})
	}
	want := map[string]int{"approval_required": 27, "admit": 22, "identical_retry": 3, "reject": 88}
	if !reflect.DeepEqual(outcomes, want) {
		t.Errorf("outcomes %v, want %v", outcomes, want)
	}
}
