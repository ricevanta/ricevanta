package admission

import "sort"

// Decide runs the admission stages in their fixed order over typed inputs.
// It never returns an error and never panics: malformed input is a Reject at
// stage input. It neither retains nor mutates its inputs, and every slice in
// the decision is freshly allocated.
func Decide(e Evidence, s Snapshot, r Request, v []Verdict) Decision {
	d := &decider{e: &e, s: &s, r: &r, v: v}
	if reasons := d.input(); len(reasons) > 0 {
		return reject(StageInput, reasons)
	}
	for _, stage := range []struct {
		name Stage
		run  func() []Reason
	}{
		{StageKey, d.key},
		{StageNamespace, d.namespace},
		{StageRevocation, d.revocation},
		{StageTombstone, d.tombstone},
		{StageOwnership, d.ownership},
		{StageInterface, d.iface},
		{StageComponent, d.component},
	} {
		if reasons := stage.run(); len(reasons) > 0 {
			return reject(stage.name, reasons)
		}
		if d.identical {
			return Decision{Outcome: IdenticalRetry}
		}
	}
	d.op = d.operation()
	if reasons := d.targets(); len(reasons) > 0 {
		return reject(StageTargets, reasons)
	}
	if reasons := d.grants(); len(reasons) > 0 {
		return reject(StageGrant, reasons)
	}
	return d.approval()
}

type decider struct {
	e *Evidence
	s *Snapshot
	r *Request
	v []Verdict

	entry     *TrustEntry
	tomb      *Tombstone
	identical bool
	op        Operation
}

// normalize sorts reasons by code then subject and keeps each pair once, in
// a fresh slice.
func normalize(reasons []Reason) []Reason {
	out := append([]Reason{}, reasons...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Subject < out[j].Subject
	})
	unique := out[:0]
	for i, reason := range out {
		if i == 0 || reason != out[i-1] {
			unique = append(unique, reason)
		}
	}
	return unique
}

func reject(stage Stage, reasons []Reason) Decision {
	return Decision{Outcome: Reject, Stage: stage, Reasons: normalize(reasons)}
}

// operation fixes the operation after the component stage. Versions compare
// by exact string, never by SemVer precedence.
func (d *decider) operation() Operation {
	in := d.s.Install
	switch {
	case d.r.GrantUpdate:
		return OperationGrantUpdate
	case in == nil && d.tomb != nil:
		return OperationReinstall
	case in == nil:
		return OperationInstall
	case in.Version == d.e.Version:
		return OperationReinstall
	}
	return OperationUpgrade
}

// approval computes both digests, then applies the approval rules.
func (d *decider) approval() Decision {
	closure, err := ClosureDigest(*d.e, *d.s, *d.r)
	var request string
	if err == nil {
		request, err = requestDigest(d.e, d.s, d.r, d.op, closure)
	}
	if err != nil {
		// Unreachable after the input stage, which proves every digested
		// string ASCII and every integer within the schema ceilings.
		return reject(StageInput, []Reason{{Code: CodeInputRequest}})
	}
	required := func(reasons []Reason) Decision {
		out := Decision{Outcome: ApprovalRequired, Operation: d.op, ClosureDigest: closure, RequestDigest: request}
		if len(reasons) > 0 {
			out.Reasons = normalize(reasons)
		}
		return out
	}
	a := d.r.Approval
	if a == nil {
		return required(nil)
	}
	var reasons []Reason
	switch a.Kind {
	case ReleaseFixed:
		if !d.releaseFixedPreconditions() {
			return reject(StageApproval, []Reason{{Code: CodeApprovalReleaseFixed}})
		}
		if needs := d.releaseOperation(); len(needs) > 0 {
			return required(needs)
		}
	case Operator, SingleAdministrator:
		if a.RecoveryEpoch != d.s.RecoveryEpoch {
			reasons = append(reasons, Reason{Code: CodeApprovalEpoch})
		}
		if a.RequestDigest != request {
			reasons = append(reasons, Reason{Code: CodeApprovalDigest})
		}
		if contains(d.s.ConsumedApprovals, a.ApprovalUID) {
			reasons = append(reasons, Reason{Code: CodeApprovalConsumed})
		}
		if a.Kind == Operator && a.Approver == d.r.Requester {
			reasons = append(reasons, Reason{Code: CodeApprovalSeparation})
		}
		if a.Kind == SingleAdministrator {
			if !d.s.ApprovalPolicyDisabled {
				reasons = append(reasons, Reason{Code: CodeApprovalExemptUnavailable})
			}
			if a.Principal != d.r.Requester {
				reasons = append(reasons, Reason{Code: CodeApprovalExemptPrincipal})
			}
		}
	}
	if len(reasons) > 0 {
		return reject(StageApproval, reasons)
	}
	return Decision{Outcome: Admit, Operation: d.op, ClosureDigest: closure, RequestDigest: request, Intent: d.intent()}
}

func reservedID(id string) bool { return covers([]string{"io.ricevanta"}, id) }

// releaseFixedPreconditions: the project publisher key, a reserved id, the
// server-image source, and a release version equal to both the running
// release (absent on a build without a verified release manifest) and the
// package version.
func (d *decider) releaseFixedPreconditions() bool {
	a := d.r.Approval
	return d.entry.ProjectPublisher && reservedID(d.e.ID) && d.r.Source == SourceServerImage &&
		d.s.ReleaseVersion != "" && a.ReleaseVersion == d.s.ReleaseVersion && a.ReleaseVersion == d.e.Version
}

// releaseOperation returns nothing when release-fixed authority admits
// without an operator, else the reasons that name what needs one.
func (d *decider) releaseOperation() []Reason {
	in := d.s.Install
	switch d.op {
	case OperationInstall:
		if d.s.FirstStart {
			return nil
		}
	case OperationUpgrade:
		return d.unwidened(in)
	case OperationReinstall:
		if in != nil && in.Version == d.e.Version && in.State == StateRecoveryPending {
			return d.unwidened(in)
		}
	}
	return []Reason{{Code: CodeApprovalReleaseOperation}}
}

// unwidened compares every proposed grant with the current install's grant
// and the proposed targets with the install's targets.
func (d *decider) unwidened(in *Install) []Reason {
	var reasons []Reason
	for i := range d.r.Grants {
		g := &d.r.Grants[i]
		if widened(g, currentGrant(in, g.Component)) {
			reasons = append(reasons, Reason{Code: CodeApprovalWidened, Subject: g.Component})
		}
	}
	if !targetsEqual(&d.r.Targets, &in.Targets) {
		reasons = append(reasons, Reason{Code: CodeApprovalTargetsChanged})
	}
	return reasons
}

func currentGrant(in *Install, component string) *Grant {
	if in == nil {
		return nil
	}
	for i := range in.Grants {
		if in.Grants[i].Grant.Component == component {
			return &in.Grants[i].Grant
		}
	}
	return nil
}

// targetsEqual compares canonical targets: device groups as a set.
func targetsEqual(a, b *Targets) bool {
	return a.AllDevices == b.AllDevices && a.Console == b.Console && a.Jobs == b.Jobs &&
		stringsEqual(sortedStrings(a.DeviceGroups), sortedStrings(b.DeviceGroups))
}

// intent is the exact prepare intent of an admitted decision.
func (d *decider) intent() *Intent {
	a := d.r.Approval
	in := d.s.Install
	enabled := false
	switch d.op {
	case OperationInstall:
		// The first-start release-fixed install is the one admission outcome
		// that turns a component on.
		enabled = a.Kind == ReleaseFixed
	default:
		enabled = in != nil && in.Enabled
	}
	consume := ""
	if a.Kind != ReleaseFixed {
		consume = a.ApprovalUID
	}
	grants := make([]string, len(d.e.Components))
	var bindings []Binding
	for i, c := range d.e.Components {
		grants[i] = c.Name
		if c.Requested.BrowserAdapter != nil {
			bindings = append(bindings, Binding{Registration: c.Requested.BrowserAdapter.Registration, Component: c.Name})
		}
	}
	if bindings == nil {
		bindings = []Binding{}
	}
	return &Intent{
		Operation:        d.op,
		ApprovalKind:     a.Kind,
		TombstoneCreate:  d.tomb == nil,
		OwnershipCreate:  d.s.Ownership == nil,
		Enabled:          enabled,
		Grants:           grants,
		Targets:          Targets{DeviceGroups: sortedStrings(d.r.Targets.DeviceGroups), AllDevices: d.r.Targets.AllDevices, Console: d.r.Targets.Console, Jobs: d.r.Targets.Jobs},
		RegistrationBind: bindings,
		ApprovalConsume:  consume,
	}
}
