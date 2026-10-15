package admission

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
)

// errDigestInput reports a value outside the closed digest types: a
// non-ASCII string, a duplicate member name or an integer JCS cannot carry
// exactly. The schemas exclude all three, so Decide treats it as malformed
// input.
var errDigestInput = errors.New("extension admission digest input")

type jvKind uint8

const (
	jvNull jvKind = iota
	jvBool
	jvInt
	jvString
	jvArray
	jvObject
)

// jv is the closed value model of the digest objects. encode emits RFC 8785
// JCS: compact, members sorted by name (ASCII names, so UTF-16 code-unit
// order is byte order), integers as plain decimals and strings escaped per
// section 3.2.2.2. It never uses encoding/json.
type jv struct {
	kind  jvKind
	s     string
	n     uint64
	b     bool
	keys  []string
	items []jv
}

func jnull() jv           { return jv{kind: jvNull} }
func jbool(b bool) jv     { return jv{kind: jvBool, b: b} }
func jint(n uint64) jv    { return jv{kind: jvInt, n: n} }
func jstr(s string) jv    { return jv{kind: jvString, s: s} }
func jarr(items ...jv) jv { return jv{kind: jvArray, items: items} }

// jobj takes alternating member names and values.
func jobj(pairs ...any) jv {
	o := jv{kind: jvObject}
	for i := 0; i+1 < len(pairs); i += 2 {
		o.keys = append(o.keys, pairs[i].(string))
		o.items = append(o.items, pairs[i+1].(jv))
	}
	return o
}

func jstrs(values []string) jv {
	items := make([]jv, len(values))
	for i, v := range values {
		items[i] = jstr(v)
	}
	return jarr(items...)
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func (v jv) encode(out []byte) ([]byte, error) {
	switch v.kind {
	case jvNull:
		return append(out, "null"...), nil
	case jvBool:
		if v.b {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case jvInt:
		// JCS serializes numbers as IEEE 754 doubles; larger integers lose
		// their exact value, so the digest types never carry them.
		if v.n > 1<<53 {
			return nil, errDigestInput
		}
		return strconv.AppendUint(out, v.n, 10), nil
	case jvString:
		return appendString(out, v.s)
	case jvArray:
		out = append(out, '[')
		for i, item := range v.items {
			if i > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = item.encode(out); err != nil {
				return nil, err
			}
		}
		return append(out, ']'), nil
	case jvObject:
		order := make([]int, len(v.keys))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return v.keys[order[a]] < v.keys[order[b]] })
		out = append(out, '{')
		for i, index := range order {
			if i > 0 {
				if v.keys[order[i-1]] == v.keys[index] {
					return nil, errDigestInput
				}
				out = append(out, ',')
			}
			var err error
			if out, err = appendString(out, v.keys[index]); err != nil {
				return nil, err
			}
			out = append(out, ':')
			if out, err = v.items[index].encode(out); err != nil {
				return nil, err
			}
		}
		return append(out, '}'), nil
	}
	return nil, errDigestInput
}

const lowerHexDigits = "0123456789abcdef"

func appendString(out []byte, s string) ([]byte, error) {
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80:
			return nil, errDigestInput
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
		case c == '\b':
			out = append(out, '\\', 'b')
		case c == '\f':
			out = append(out, '\\', 'f')
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c < 0x20:
			out = append(out, '\\', 'u', '0', '0', lowerHexDigits[c>>4], lowerHexDigits[c&15])
		default:
			out = append(out, c)
		}
	}
	return append(out, '"'), nil
}

func digestOf(v jv) (string, error) {
	b, err := v.encode(nil)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func u64(n uint64) jv { return jstr(strconv.FormatUint(n, 10)) }

func hexJV(d [32]byte) jv { return jstr(hex.EncodeToString(d[:])) }

func optionalString(s string) jv {
	if s == "" {
		return jnull()
	}
	return jstr(s)
}

func targetsJV(t *Targets) jv {
	return jobj("device_groups", jstrs(sortedStrings(t.DeviceGroups)), "all_devices", jbool(t.AllDevices), "console", jbool(t.Console), "jobs", jbool(t.Jobs))
}

func osPoliciesJV(p *OSPolicies) jv {
	o := jobj()
	for _, e := range []struct {
		name   string
		policy *OSPolicy
	}{{"macos", p.MacOS}, {"windows", p.Windows}, {"linux", p.Linux}} {
		if e.policy != nil {
			o.keys = append(o.keys, e.name)
			o.items = append(o.items, jobj("policy_names", jstrs(e.policy.PolicyNames), "native_host", jbool(e.policy.NativeHost)))
		}
	}
	return o
}

// valuesJV encodes grant values with exactly the members the interface's
// schema branch defines. Arrays keep the proposal's order.
func valuesJV(iface string, v *Values) (jv, error) {
	switch {
	case v.Content != nil:
		return jobj(), nil
	case v.BrowserAdapter != nil:
		return jobj("registration", jstr(v.BrowserAdapter.Registration), "os", osPoliciesJV(&v.BrowserAdapter.OS)), nil
	case v.AgentModule != nil:
		a := v.AgentModule
		o := jobj()
		for _, f := range numericFields(iface) {
			o.keys = append(o.keys, f.name)
			o.items = append(o.items, jint(*f.get(a)))
		}
		switch iface {
		case ifaceParser:
			o.keys = append(o.keys, "mime_types")
			o.items = append(o.items, jstrs(a.MIMETypes))
		case ifaceCollector:
			roots := make([]jv, len(a.Roots))
			for i, r := range a.Roots {
				roots[i] = jobj("os", jstr(r.OS), "path", jstr(r.Path))
			}
			o.keys = append(o.keys, "roots", "disclosure_profile")
			o.items = append(o.items, jarr(roots...), jstr(a.DisclosureProfile))
		case ifaceResponder:
			o.keys = append(o.keys, "actions")
			o.items = append(o.items, jstrs(a.Actions))
		}
		return o, nil
	case v.ConsoleModule != nil:
		slots := jobj()
		for _, name := range sortedKeys(v.ConsoleModule.Slots) {
			slots.keys = append(slots.keys, name)
			slots.items = append(slots.items, jstrs(v.ConsoleModule.Slots[name]))
		}
		return jobj("slots", slots), nil
	case v.ServiceConnector != nil:
		out := make([]jv, len(v.ServiceConnector.Outbound))
		for i, o := range v.ServiceConnector.Outbound {
			out[i] = jobj("host", jstr(o.Host), "port", jint(o.Port), "transport", jstr(o.Transport))
		}
		return jobj("outbound", jarr(out...)), nil
	}
	return jv{}, errDigestInput
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func findEntry(s *Snapshot, fingerprint string) *TrustEntry {
	for i := range s.TrustList {
		if s.TrustList[i].Fingerprint == fingerprint {
			return &s.TrustList[i]
		}
	}
	return nil
}

// covers: the id equals a prefix or lies under one at a label boundary.
func covers(prefixes []string, id string) bool {
	for _, p := range prefixes {
		if id == p || len(id) > len(p) && id[:len(p)] == p && id[len(p)] == '.' {
			return true
		}
	}
	return false
}

// coveringEntries are the non-retired entries, revoked ones included, whose
// prefixes cover the id.
func coveringEntries(s *Snapshot, id string) []string {
	var out []string
	for i := range s.TrustList {
		if t := &s.TrustList[i]; !t.Retired && covers(t.Prefixes, id) {
			out = append(out, t.Fingerprint)
		}
	}
	return sortedStrings(out)
}

func findTombstone(s *Snapshot, version string) *Tombstone {
	for i := range s.Tombstones {
		if s.Tombstones[i].Version == version {
			return &s.Tombstones[i]
		}
	}
	return nil
}

func findRegistration(s *Snapshot, id string) *Registration {
	for i := range s.Registrations {
		if s.Registrations[i].ID == id {
			return &s.Registrations[i]
		}
	}
	return nil
}

func sortedGrants(grants []Grant) []Grant {
	out := append([]Grant{}, grants...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Component < out[j].Component })
	return out
}

// closureObject is the dependency closure of contracts section 3.
func closureObject(e *Evidence, s *Snapshot, r *Request) (jv, error) {
	entry := findEntry(s, e.PublisherFingerprint)
	if entry == nil {
		return jv{}, errDigestInput
	}
	release := jnull()
	if r.Source == SourceServerImage {
		release = jobj("first_start", jbool(s.FirstStart), "release_version", optionalString(s.ReleaseVersion))
	}
	revocations := make([]jv, len(s.Revocations))
	keys := make([]string, len(s.Revocations))
	for i, rv := range s.Revocations {
		revocations[i] = jobj("id", jstr(rv.ID))
		if rv.Version != "" {
			revocations[i] = jobj("id", jstr(rv.ID), "version", jstr(rv.Version))
		}
		b, err := revocations[i].encode(nil)
		if err != nil {
			return jv{}, err
		}
		keys[i] = string(b)
	}
	order := make([]int, len(revocations))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return keys[order[a]] < keys[order[b]] })
	sortedRevocations := make([]jv, len(order))
	for i, index := range order {
		sortedRevocations[i] = revocations[index]
	}
	ownership := jnull()
	if o := s.Ownership; o != nil {
		ownership = jobj("id", jstr(o.ID), "owner", jstr(o.Owner), "prior_owners", jstrs(sortedStrings(o.PriorOwners)), "ownership_generation", u64(o.OwnershipGeneration))
	}
	tombstone := jnull()
	if t := findTombstone(s, e.Version); t != nil {
		tombstone = jobj("id", jstr(t.ID), "version", jstr(t.Version), "publisher", jstr(t.Publisher), "manifest_sha256", hexJV(t.ManifestSHA256), "package_sha256", hexJV(t.PackageSHA256))
	}
	install := jnull()
	if in := s.Install; in != nil {
		records := make([]GrantRecord, len(in.Grants))
		copy(records, in.Grants)
		sort.SliceStable(records, func(i, j int) bool { return records[i].Grant.Component < records[j].Grant.Component })
		grants := make([]jv, len(records))
		for i := range records {
			values, err := valuesJV(records[i].Grant.Interface, &records[i].Grant.Values)
			if err != nil {
				return jv{}, err
			}
			grants[i] = jobj("component", jstr(records[i].Grant.Component), "recovery_epoch", u64(records[i].RecoveryEpoch), "grant_generation", u64(records[i].GrantGeneration), "values", values)
		}
		install = jobj("version", jstr(in.Version), "package_sha256", hexJV(in.PackageSHA256), "state", jstr(string(in.State)), "enabled", jbool(in.Enabled),
			"generation", u64(in.Generation), "targets", targetsJV(&in.Targets), "grants", jarr(grants...))
	}
	var referenced []string
	for _, c := range e.Components {
		if c.Requested.BrowserAdapter != nil && !contains(referenced, c.Requested.BrowserAdapter.Registration) {
			referenced = append(referenced, c.Requested.BrowserAdapter.Registration)
		}
	}
	var registrations []jv
	for _, id := range sortedStrings(referenced) {
		reg := findRegistration(s, id)
		if reg == nil {
			return jv{}, errDigestInput
		}
		bound := jnull()
		if b := reg.Bound; b != nil {
			bound = jobj("id", jstr(b.ID), "component", jstr(b.Component), "state", jstr(string(b.State)))
		}
		registrations = append(registrations, jobj("id", jstr(reg.ID), "registration_generation", u64(reg.RegistrationGeneration), "os", osPoliciesJV(&reg.OS), "bound", bound))
	}
	var required []string
	for _, interfaces := range e.Requires {
		for _, iface := range interfaces {
			if !contains(required, iface) {
				required = append(required, iface)
			}
		}
	}
	var profiles []string
	for _, g := range r.Grants {
		if a := g.Values.AgentModule; a != nil && g.Interface == ifaceCollector && !contains(profiles, a.DisclosureProfile) {
			profiles = append(profiles, a.DisclosureProfile)
		}
	}
	return jobj(
		"profile", jstr("ricevanta-extension-admission-closure-v1"),
		"recovery_epoch", u64(s.RecoveryEpoch),
		"approval_policy_disabled", jbool(s.ApprovalPolicyDisabled),
		"approval_policy_generation", u64(s.ApprovalPolicyGeneration),
		"release", release,
		"id", jstr(e.ID),
		"version", jstr(e.Version),
		"trust_entry", jobj("fingerprint", jstr(entry.Fingerprint), "generation", u64(entry.Generation), "prefixes", jstrs(sortedStrings(entry.Prefixes)),
			"project_publisher", jbool(entry.ProjectPublisher), "revoked", jbool(entry.Revoked), "retired", jbool(entry.Retired)),
		"covering", jstrs(coveringEntries(s, e.ID)),
		"revocations", jarr(sortedRevocations...),
		"revocation_generation", u64(s.RevocationGeneration),
		"ownership", ownership,
		"tombstone", tombstone,
		"install", install,
		"registrations", jarr(registrations...),
		"served_interfaces", jstrs(sortedStrings(required)),
		"disclosure_profiles", jstrs(sortedStrings(profiles)),
		"device_groups", jstrs(sortedStrings(r.Targets.DeviceGroups)),
	), nil
}

// ClosureDigest hashes the dependency closure: every fact the decision read,
// with the generation of every fact that can be reverted.
func ClosureDigest(e Evidence, s Snapshot, r Request) (string, error) {
	v, err := closureObject(&e, &s, &r)
	if err != nil {
		return "", err
	}
	return digestOf(v)
}

// RequestDigest hashes the frozen request for operation op; an approval
// binds it together with the recovery epoch.
func RequestDigest(e Evidence, s Snapshot, r Request, op Operation) (string, error) {
	closure, err := ClosureDigest(e, s, r)
	if err != nil {
		return "", err
	}
	return requestDigest(&e, &s, &r, op, closure)
}

func requestDigest(e *Evidence, s *Snapshot, r *Request, op Operation, closure string) (string, error) {
	switch op {
	case OperationInstall, OperationUpgrade, OperationReinstall, OperationGrantUpdate:
	default:
		return "", errDigestInput
	}
	grants := sortedGrants(r.Grants)
	items := make([]jv, len(grants))
	for i := range grants {
		values, err := valuesJV(grants[i].Interface, &grants[i].Values)
		if err != nil {
			return "", err
		}
		items[i] = jobj("component", jstr(grants[i].Component), "kind", jstr(grants[i].Kind), "interface", jstr(grants[i].Interface), "values", values)
	}
	return digestOf(jobj(
		"profile", jstr("ricevanta-extension-admission-request-v1"),
		"id", jstr(e.ID),
		"version", jstr(e.Version),
		"publisher", jstr(e.PublisherFingerprint),
		"package_sha256", hexJV(e.PackageSHA256),
		"manifest_sha256", hexJV(e.ManifestSHA256),
		"envelope_sha256", hexJV(e.EnvelopeSHA256),
		"recovery_epoch", u64(s.RecoveryEpoch),
		"operation", jstr(string(op)),
		"source", jstr(string(r.Source)),
		"requester", jstr(r.Requester),
		"grants", jarr(items...),
		"targets", targetsJV(&r.Targets),
		"closure", jstr(closure),
	))
}
