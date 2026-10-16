package admission

import (
	"slices"
	"testing"
)

// These are supplied journal projections, not executable reducer or crash tests.
func TestReviewRegressions(t *testing.T) {
	names := []string{
		"prepare-first-install-reserves-owner",
		"abort-first-install-retry-needs-approval",
		"abort-first-install-retry-admit",
		"abort-first-install-old-approval-refused",
		"abort-first-install-new-publisher-refused",
		"recovery-registration-old-epoch",
		"rebind-registration-old-epoch",
		"identical-retry-registration-old-epoch",
		"recovery-registration-renewed-admit",
		"registration-renewal-stales-approval",
		"input-snapshot-registration-future-epoch",
		"mixed-version-older-replica-needs-operator",
		"restore-older-image-needs-operator",
		"older-release-operator-admit",
		"rollback-recovery-keeps-higher-floor",
		"global-floor-covers-new-id",
		"release-floor-advance-stales-operator-approval",
		"input-snapshot-floor-missing-history",
		"input-snapshot-floor-below-history",
		"aborted-release-prepare-retains-floor",
		"release-order-numeric-core",
		"release-order-numeric-prerelease",
		"release-order-stable-over-prerelease",
		"release-order-stable-forward",
		"release-order-numeric-before-alpha",
		"release-order-prerelease-prefix",
		"release-order-wide-numeric",
		"older-replica-identical-retry-no-mutation",
		"operator-cannot-renew-stale-registration",
		"global-floor-equality-new-id-needs-operator",
	}
	if len(names) != 30 {
		t.Fatal("review regression inventory changed")
	}
	cases := corpusCases(t)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			index := slices.IndexFunc(cases, func(c corpusCase) bool { return c.Name == name })
			if index < 0 {
				t.Fatal("missing review vector")
			}
			e, err, s, r, v, expected := corpusInputs(t, cases[index])
			if err != nil {
				t.Fatal(err)
			}
			d := Decide(e, s, r, v)
			checkDecision(t, d, expected)
			if name == "older-release-operator-admit" && (d.Intent == nil || d.Intent.ReleaseFloorRaise != "") {
				t.Fatal("operator rollback changed the higher floor")
			}
			if name == "global-floor-covers-new-id" && (d.Intent != nil || !slices.Equal(d.Reasons, []Reason{{CodeApprovalReleaseRollback, ""}})) {
				t.Fatal("below-floor proposal escaped rollback precedence")
			}
			if name == "global-floor-equality-new-id-needs-operator" && !slices.Equal(d.Reasons, []Reason{{CodeApprovalReleaseOperation, ""}}) {
				t.Fatal("floor equality skipped operation checks")
			}
		})
	}
}

func TestIdenticalRetryChecksCurrentAuthority(t *testing.T) {
	for _, stage := range []Stage{StageOwnership, StageInterface, StageComponent} {
		t.Run(string(stage), func(t *testing.T) {
			in := caseInputs(t, "identical-retry-registration-old-epoch")
			for i := range in.s.Registrations {
				in.s.Registrations[i].RecoveryEpoch = in.s.RecoveryEpoch
			}
			if d := decideInputs(in); d.Outcome != IdenticalRetry {
				t.Fatalf("control: %+v", d)
			}
			switch stage {
			case StageOwnership:
				in.s.Ownership.Owner = partnerKey
				in.s.Ownership.PriorOwners = nil
			case StageInterface:
				in.s.ServedInterfaces = nil
			case StageComponent:
				in.v = nil
			}
			if d := decideInputs(in); d.Outcome != Reject || d.Stage != stage {
				t.Fatalf("identical retry skipped %s: %+v", stage, d)
			}
		})
	}
}

// The oracle must reject stale authority even when the decision reports a
// no-mutation retry and skips the later admission invariant checks.
func TestRegistrationAuthorityOracle(t *testing.T) {
	for name, mutate := range map[string]func(*inputs){
		"missing":     func(in *inputs) { in.s.Registrations = nil },
		"epoch":       func(in *inputs) { in.s.Registrations[0].RecoveryEpoch-- },
		"os":          func(in *inputs) { in.s.Registrations[0].OS = OSPolicies{} },
		"names":       func(in *inputs) { in.s.Registrations[0].OS.Windows.PolicyNames = nil },
		"native-host": func(in *inputs) { in.s.Registrations[0].OS.Windows.NativeHost = false },
		"holder": func(in *inputs) {
			in.s.Registrations[0].Bound = &Bound{ID: "org.other.browser", Component: "browser", State: StateActive}
		},
		"duplicate": func(in *inputs) { in.e.Components = append(in.e.Components, in.e.Components[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			in := caseInputs(t, "identical-retry-registration-old-epoch")
			for i := range in.s.Registrations {
				in.s.Registrations[i].RecoveryEpoch = in.s.RecoveryEpoch
			}
			if !registrationAuthority(in.e, in.s) {
				t.Fatal("valid authority rejected")
			}
			mutate(&in)
			if registrationAuthority(in.e, in.s) {
				t.Fatal("oracle accepted invalid registration authority")
			}
		})
	}
}
