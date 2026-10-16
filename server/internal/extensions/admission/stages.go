package admission

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ricevanta/ricevanta/server/internal/signing/ed25519key"
)

// input: well-formed evidence, the snapshot's field rules and its thirteen
// rules, and the request's field rules and its four rules.
func (d *decider) input() []Reason {
	var reasons []Reason
	evidenceOK := checkEvidence(d.e)
	if !evidenceOK {
		reasons = append(reasons, Reason{Code: CodeInputEvidence})
	}
	// The record rules run only on field-valid values, so their pairwise
	// passes see bounded counts.
	var cs checker
	cs.validSnapshot(d.s)
	if cs.fieldFail || cs.grantFail || !d.snapshotRules(evidenceOK) {
		reasons = append(reasons, Reason{Code: CodeInputSnapshot})
	}
	var cr checker
	cr.validRequest(d.r)
	if cr.fieldFail || cr.grantFail || !d.requestRules() {
		reasons = append(reasons, Reason{Code: CodeInputRequest})
	}
	return reasons
}

// snapshotRules checks the thirteen snapshot rules. The comparisons with the
// evidence's id and version (rules 3 to 6) run only on valid evidence, so a
// malformed evidence id is one defect with one reason, input.evidence.
func (d *decider) snapshotRules(evidenceOK bool) bool {
	s, e := d.s, d.e
	fingerprints := make(map[string]bool, len(s.TrustList))
	for i := range s.TrustList {
		t := &s.TrustList[i]
		// Rule 1: unique fingerprints.
		if fingerprints[t.Fingerprint] {
			return false
		}
		fingerprints[t.Fingerprint] = true
		// Rule 2: the fingerprint is the SHA-256 of the raw key.
		sum := sha256.Sum256(t.PublicKey[:])
		if t.Fingerprint != "sha256:"+hex.EncodeToString(sum[:]) {
			return false
		}
		// Rule 11: project_publisher exactly on the compiled project key.
		if t.ProjectPublisher != (t.Fingerprint == s.ProjectKey) {
			return false
		}
	}
	// Rule 3: revocations name the id, and a version revocation the version.
	sameID := func(id string) bool { return !evidenceOK || id == e.ID }
	for _, r := range s.Revocations {
		if !sameID(r.ID) || evidenceOK && r.Version != "" && r.Version != e.Version {
			return false
		}
	}
	// Rule 4: the ownership record names the id; rule 10 for its keys.
	if o := s.Ownership; o != nil {
		if !sameID(o.ID) || !fingerprints[o.Owner] {
			return false
		}
		for _, p := range o.PriorOwners {
			if !fingerprints[p] {
				return false
			}
		}
	}
	// Rule 5: tombstones name the id, at most one per version; rule 10 for
	// their publishers.
	for i, t := range s.Tombstones {
		if !sameID(t.ID) || !fingerprints[t.Publisher] {
			return false
		}
		for j := 0; j < i; j++ {
			if s.Tombstones[j].Version == t.Version {
				return false
			}
		}
	}
	if in := s.Install; in != nil {
		// Rule 6: the install names the id and its version has a tombstone
		// with the same package digest.
		t := findTombstone(s, in.Version)
		if !sameID(in.ID) || t == nil || t.PackageSHA256 != in.PackageSHA256 {
			return false
		}
		for i := range in.Grants {
			g := &in.Grants[i]
			// Rule 7: distinct components carrying the install's identity.
			if g.ExtensionID != in.ID || g.Version != in.Version || g.PackageSHA256 != in.PackageSHA256 {
				return false
			}
			for j := 0; j < i; j++ {
				if in.Grants[j].Grant.Component == g.Grant.Component {
					return false
				}
			}
			// Rule 8: no later epoch; an active install is at the snapshot's.
			if g.RecoveryEpoch > s.RecoveryEpoch || in.State == StateActive && g.RecoveryEpoch != s.RecoveryEpoch {
				return false
			}
		}
	}
	// Rule 12: an install or tombstone exists only beside the ownership record.
	if (s.Install != nil || len(s.Tombstones) > 0) && s.Ownership == nil {
		return false
	}
	// Rule 13: reserved-id history cannot exceed the installation-wide floor.
	for _, t := range s.Tombstones {
		if reservedID(t.ID) && (s.AutomaticReleaseFloor == "" || compareRelease(t.Version, s.AutomaticReleaseFloor) > 0) {
			return false
		}
	}
	// Rule 9: one record per registration id, no future epoch.
	for i := range s.Registrations {
		if s.Registrations[i].RecoveryEpoch > s.RecoveryEpoch {
			return false
		}
		for j := 0; j < i; j++ {
			if s.Registrations[j].ID == s.Registrations[i].ID {
				return false
			}
		}
	}
	return true
}

func (d *decider) requestRules() bool {
	r := d.r
	for i := range r.Grants {
		for j := 0; j < i; j++ {
			if r.Grants[j].Component == r.Grants[i].Component {
				return false
			}
		}
	}
	if (r.Source == SourceServerImage) != (r.Requester == SystemPrincipal) {
		return false
	}
	if a := r.Approval; a != nil && (a.Approver == SystemPrincipal || a.Principal == SystemPrincipal) {
		return false
	}
	return !(r.Source == SourceServerImage && r.GrantUpdate)
}

// key: the fingerprint names an entry whose raw key passes key admission on
// every decision; the entry is not revoked, nor retired unless the request is
// a grant update.
func (d *decider) key() []Reason {
	fp := d.e.PublisherFingerprint
	d.entry = findEntry(d.s, fp)
	if d.entry == nil {
		return []Reason{{Code: CodeKeyUnknown, Subject: fp}}
	}
	var reasons []Reason
	if ed25519key.Validate(d.entry.PublicKey[:]) != nil {
		reasons = append(reasons, Reason{Code: CodeKeyInvalid, Subject: fp})
	}
	if d.entry.Revoked {
		reasons = append(reasons, Reason{Code: CodeKeyRevoked, Subject: fp})
	}
	if d.entry.Retired && !d.r.GrantUpdate {
		reasons = append(reasons, Reason{Code: CodeKeyRetired, Subject: fp})
	}
	return reasons
}

func (d *decider) namespace() []Reason {
	var reasons []Reason
	if reservedID(d.e.ID) && !d.entry.ProjectPublisher {
		reasons = append(reasons, Reason{Code: CodeNamespaceReserved, Subject: d.e.ID})
	}
	if !covers(d.entry.Prefixes, d.e.ID) {
		reasons = append(reasons, Reason{Code: CodeNamespacePrefix, Subject: d.e.ID})
	}
	return reasons
}

func (d *decider) revocation() []Reason {
	var reasons []Reason
	for _, r := range d.s.Revocations {
		switch {
		case r.Version == "":
			reasons = append(reasons, Reason{Code: CodeRevocationID, Subject: d.e.ID})
		case r.Version == d.e.Version:
			reasons = append(reasons, Reason{Code: CodeRevocationVersion, Subject: d.e.Version})
		}
	}
	return reasons
}

// tombstone: a tombstoned pair keeps its publisher and bytes. A grant update
// needs an active install of this version; otherwise an active install of this
// version is an identical retry when grants and targets are equal.
func (d *decider) tombstone() []Reason {
	e, version := d.e, d.e.Version
	var reasons []Reason
	d.tomb = findTombstone(d.s, version)
	if t := d.tomb; t != nil {
		if t.Publisher != e.PublisherFingerprint {
			reasons = append(reasons, Reason{Code: CodeTombstonePublisher, Subject: version})
		}
		if t.ManifestSHA256 != e.ManifestSHA256 {
			reasons = append(reasons, Reason{Code: CodeTombstoneManifest, Subject: version})
		}
		if t.PackageSHA256 != e.PackageSHA256 {
			reasons = append(reasons, Reason{Code: CodeTombstonePackage, Subject: version})
		}
	}
	in := d.s.Install
	activeHere := in != nil && in.Version == version && in.State == StateActive
	switch {
	case d.r.GrantUpdate:
		if !activeHere {
			reasons = append(reasons, Reason{Code: CodeTombstoneNotInstalled, Subject: version})
		}
	case activeHere:
		if !sameGrants(d.r.Grants, in.Grants) {
			reasons = append(reasons, Reason{Code: CodeTombstoneGrants, Subject: version})
		}
		if !targetsEqual(&d.r.Targets, &in.Targets) {
			reasons = append(reasons, Reason{Code: CodeTombstoneTargets, Subject: version})
		}
		d.identical = len(reasons) == 0
	}
	return reasons
}

// sameGrants: one equal grant per stored component, nothing more.
func sameGrants(proposed []Grant, stored []GrantRecord) bool {
	if len(proposed) != len(stored) {
		return false
	}
	for i := range proposed {
		g := &proposed[i]
		current := (*Grant)(nil)
		for j := range stored {
			if stored[j].Grant.Component == g.Component {
				current = &stored[j].Grant
				break
			}
		}
		if current == nil || !grantEqual(g, current) {
			return false
		}
	}
	return true
}

// ownership: the owner publishes; a prior owner only a version whose
// tombstone names it. Without a record exactly one non-retired entry,
// revoked ones included, covers the id and becomes its owner.
func (d *decider) ownership() []Reason {
	fp, id := d.e.PublisherFingerprint, d.e.ID
	if o := d.s.Ownership; o != nil {
		prior := d.tomb != nil && d.tomb.Publisher == fp && contains(o.PriorOwners, fp)
		if o.Owner != fp && !prior {
			return []Reason{{Code: CodeOwnershipOwner, Subject: id}}
		}
		return nil
	}
	covering := coveringEntries(d.s, id)
	switch {
	case len(covering) != 1:
		return []Reason{{Code: CodeOwnershipAssignmentRequired, Subject: id}}
	case covering[0] != fp:
		return []Reason{{Code: CodeOwnershipOwner, Subject: id}}
	}
	return nil
}

func (d *decider) iface() []Reason {
	var reasons []Reason
	for _, interfaces := range d.e.Requires {
		for _, iface := range interfaces {
			if !contains(d.s.ServedInterfaces, iface) {
				reasons = append(reasons, Reason{Code: CodeInterfaceUnserved, Subject: iface})
			}
		}
	}
	return reasons
}

// component: a passing verdict per component; a browser adapter's request
// stays within a stored registration that no other active holder binds.
func (d *decider) component() []Reason {
	var reasons []Reason
	referenced := map[string]bool{}
	for _, c := range d.e.Components {
		seen, failed := false, false
		for _, v := range d.v {
			if v.Component == c.Name {
				seen = true
				failed = failed || !v.OK
			}
		}
		switch {
		case !seen:
			reasons = append(reasons, Reason{Code: CodeComponentVerdictMissing, Subject: c.Name})
		case failed:
			reasons = append(reasons, Reason{Code: CodeComponentVerdictFailed, Subject: c.Name})
		}
		b := c.Requested.BrowserAdapter
		if b == nil {
			continue
		}
		// Components are in name order, so every adapter after the first
		// that names a registration is a duplicate, stored or not.
		if referenced[b.Registration] {
			reasons = append(reasons, Reason{Code: CodeComponentRegistrationDuplicate, Subject: c.Name})
		}
		referenced[b.Registration] = true
		reg := findRegistration(d.s, b.Registration)
		if reg == nil {
			reasons = append(reasons, Reason{Code: CodeComponentRegistrationUnknown, Subject: c.Name})
			continue
		}
		if reg.RecoveryEpoch != d.s.RecoveryEpoch {
			reasons = append(reasons, Reason{Code: CodeComponentRegistrationEpoch, Subject: c.Name})
		}
		for _, pair := range [][2]*OSPolicy{{b.OS.MacOS, reg.OS.MacOS}, {b.OS.Windows, reg.OS.Windows}, {b.OS.Linux, reg.OS.Linux}} {
			requested, registered := pair[0], pair[1]
			switch {
			case requested == nil:
			case registered == nil:
				reasons = append(reasons, Reason{Code: CodeComponentRegistrationOS, Subject: c.Name})
			default:
				if !subset(requested.PolicyNames, registered.PolicyNames) {
					reasons = append(reasons, Reason{Code: CodeComponentRegistrationNames, Subject: c.Name})
				}
				if requested.NativeHost && !registered.NativeHost {
					reasons = append(reasons, Reason{Code: CodeComponentRegistrationNativeHost, Subject: c.Name})
				}
			}
		}
		// A binding this id holds never blocks: the intent's binding set
		// replaces the id's bindings.
		if h := reg.Bound; h != nil && h.State == StateActive && h.ID != d.e.ID {
			reasons = append(reasons, Reason{Code: CodeComponentRegistrationBound, Subject: c.Name})
		}
	}
	return reasons
}

// targets: agent-bound packages target exactly one of device groups or all
// devices; all_devices comes only from the server image or is kept by a grant
// update of an install that already targets all devices; under a retired key
// a grant update never reaches beyond the install's targets.
func (d *decider) targets() []Reason {
	t := &d.r.Targets
	in := d.s.Install
	var reasons []Reason
	agentBound, console, jobs := false, false, false
	for _, c := range d.e.Components {
		switch c.Kind {
		case kindContent, kindBrowserAdapter, kindAgentModule:
			agentBound = true
		case kindConsoleModule:
			console = true
		case kindServiceConnector:
			jobs = true
		}
	}
	groups := len(t.DeviceGroups) > 0
	switch {
	case agentBound && groups && t.AllDevices:
		reasons = append(reasons, Reason{Code: CodeTargetsAllDevices})
	case agentBound && !groups && !t.AllDevices:
		reasons = append(reasons, Reason{Code: CodeTargetsDeviceGroupsRequired})
	case !agentBound && (groups || t.AllDevices):
		reasons = append(reasons, Reason{Code: CodeTargetsDeviceGroupsForbidden})
	}
	kept := d.r.GrantUpdate && in != nil && in.Targets.AllDevices
	if t.AllDevices && d.r.Source != SourceServerImage && !kept {
		reasons = append(reasons, Reason{Code: CodeTargetsAllDevices})
	}
	if d.r.GrantUpdate && d.entry.Retired && in != nil {
		within := !t.AllDevices || in.Targets.AllDevices
		if !in.Targets.AllDevices {
			within = within && subset(t.DeviceGroups, in.Targets.DeviceGroups)
		}
		if !within {
			reasons = append(reasons, Reason{Code: CodeTargetsRetiredKey})
		}
	}
	if t.Console != console {
		reasons = append(reasons, Reason{Code: CodeTargetsConsole})
	}
	if t.Jobs != jobs {
		reasons = append(reasons, Reason{Code: CodeTargetsJobs})
	}
	for _, g := range t.DeviceGroups {
		if !contains(d.s.DeviceGroups, g) {
			reasons = append(reasons, Reason{Code: CodeTargetsUnknownGroup, Subject: g})
		}
	}
	return reasons
}

// grants: one matching grant per component within the manifest request; a
// collector names a reviewed profile and at most max_roots roots. Only when
// those pass does a retired-key grant update check for widening.
func (d *decider) grants() []Reason {
	var reasons []Reason
	byName := make(map[string]*Grant, len(d.r.Grants))
	for i := range d.r.Grants {
		g := &d.r.Grants[i]
		byName[g.Component] = g
		if findComponent(d.e, g.Component) == nil {
			reasons = append(reasons, Reason{Code: CodeGrantExtra, Subject: g.Component})
		}
	}
	for i := range d.e.Components {
		c := &d.e.Components[i]
		g := byName[c.Name]
		switch {
		case g == nil:
			reasons = append(reasons, Reason{Code: CodeGrantMissing, Subject: c.Name})
			continue
		case g.Kind != c.Kind || g.Interface != c.Interface:
			reasons = append(reasons, Reason{Code: CodeGrantKind, Subject: c.Name})
			continue
		}
		if b := g.Values.BrowserAdapter; b != nil && b.Registration != c.Requested.BrowserAdapter.Registration {
			reasons = append(reasons, Reason{Code: CodeGrantRegistration, Subject: c.Name})
		}
		if !bounded(c.Interface, &g.Values, &c.Requested, false) || !slotsDeclared(c, g) {
			reasons = append(reasons, Reason{Code: CodeGrantExceeds, Subject: c.Name})
		}
		if a := g.Values.AgentModule; a != nil && c.Interface == ifaceCollector {
			if !contains(d.s.DisclosureProfiles, a.DisclosureProfile) {
				reasons = append(reasons, Reason{Code: CodeGrantProfile, Subject: c.Name})
			}
			if uint64(len(a.Roots)) > a.MaxRoots {
				reasons = append(reasons, Reason{Code: CodeGrantRoots, Subject: c.Name})
			}
		}
	}
	if len(reasons) > 0 || !d.r.GrantUpdate || !d.entry.Retired {
		return reasons
	}
	for i := range d.r.Grants {
		g := &d.r.Grants[i]
		if widened(g, currentGrant(d.s.Install, g.Component)) {
			reasons = append(reasons, Reason{Code: CodeGrantRetiredKey, Subject: g.Component})
		}
	}
	return reasons
}

// slotsDeclared: console grant slots are among the component's declared slots.
func slotsDeclared(c *Component, g *Grant) bool {
	if g.Values.ConsoleModule == nil {
		return true
	}
	for slot := range g.Values.ConsoleModule.Slots {
		if !contains(c.Slots, slot) {
			return false
		}
	}
	return true
}

func findComponent(e *Evidence, name string) *Component {
	for i := range e.Components {
		if e.Components[i].Name == name {
			return &e.Components[i]
		}
	}
	return nil
}
