package admission

import (
	"regexp"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Input bounds over bytes, checked before decoding.
const (
	MaxSnapshotBytes    = 16 << 20
	MaxRequestBytes     = 2 << 20
	MaxResourceBytes    = 2 << 20
	MaxGrantRecordBytes = 1 << 20
	MaxDepth            = 16

	// Value caps count every JSON value (objects, arrays and scalars, not
	// member names). The lexer refuses the first value past the cap before
	// allocating it, so allocation is proportional to the cap.
	MaxSnapshotValues    = 65536
	MaxRequestValues     = 32768
	MaxResourceValues    = 32768
	MaxGrantRecordValues = 1024
)

type nodeKind uint8

const (
	nodeNull nodeKind = iota
	nodeBool
	nodeNumber
	nodeString
	nodeArray
	nodeObject
)

// node is a decoded JSON value. Object members keep input order; keys are
// unique because the lexer rejects decoded duplicates.
type node struct {
	kind  nodeKind
	text  string // string value or integer lexeme
	flag  bool
	keys  []string
	items []*node // array items, or object values parallel to keys
}

func (n *node) member(key string) *node {
	for i, k := range n.keys {
		if k == key {
			return n.items[i]
		}
	}
	return nil
}

// lexer implements the strict profile: bounded depth, decoded duplicate-key
// rejection, valid UTF-8 without lone surrogates, and integer tokens without
// sign, fraction or exponent. Every failure is ErrJSON.
type lexer struct {
	data   []byte
	pos    int
	values int // values still allowed
}

func decodeJSON(data []byte, limit, values int) (*node, error) {
	if len(data) > limit {
		return nil, ErrJSON
	}
	l := lexer{data: data, values: values}
	n, ok := l.value(0)
	if !ok {
		return nil, ErrJSON
	}
	l.space()
	if l.pos != len(l.data) {
		return nil, ErrJSON
	}
	return n, nil
}

func (l *lexer) space() {
	for l.pos < len(l.data) {
		switch l.data[l.pos] {
		case ' ', '\t', '\r', '\n':
			l.pos++
		default:
			return
		}
	}
}

func (l *lexer) take(b byte) bool {
	if l.pos < len(l.data) && l.data[l.pos] == b {
		l.pos++
		return true
	}
	return false
}

func (l *lexer) value(depth int) (*node, bool) {
	l.space()
	if l.pos >= len(l.data) || l.values == 0 {
		return nil, false
	}
	l.values--
	switch c := l.data[l.pos]; {
	case c == '{' || c == '[':
		if depth == MaxDepth {
			return nil, false
		}
		l.pos++
		object := c == '{'
		n := &node{kind: nodeArray}
		end := byte(']')
		if object {
			n.kind = nodeObject
			end = '}'
		}
		l.space()
		if l.take(end) {
			return n, true
		}
		var seen map[string]struct{}
		for {
			if object {
				l.space()
				if l.pos >= len(l.data) || l.data[l.pos] != '"' {
					return nil, false
				}
				key, ok := l.text()
				if !ok {
					return nil, false
				}
				if len(n.keys) >= 8 && seen == nil {
					seen = make(map[string]struct{}, 16)
					for _, k := range n.keys {
						seen[k] = struct{}{}
					}
				}
				if seen != nil {
					if _, dup := seen[key]; dup {
						return nil, false
					}
					seen[key] = struct{}{}
				} else {
					for _, k := range n.keys {
						if k == key {
							return nil, false
						}
					}
				}
				n.keys = append(n.keys, key)
				l.space()
				if !l.take(':') {
					return nil, false
				}
			}
			item, ok := l.value(depth + 1)
			if !ok {
				return nil, false
			}
			n.items = append(n.items, item)
			l.space()
			if l.take(end) {
				return n, true
			}
			if !l.take(',') {
				return nil, false
			}
		}
	case c == '"':
		s, ok := l.text()
		return &node{kind: nodeString, text: s}, ok
	case c == 't':
		return &node{kind: nodeBool, flag: true}, l.literal("true")
	case c == 'f':
		return &node{kind: nodeBool}, l.literal("false")
	case c == 'n':
		return &node{kind: nodeNull}, l.literal("null")
	case c >= '0' && c <= '9':
		start := l.pos
		l.pos++
		if c != '0' {
			for l.pos < len(l.data) && l.data[l.pos] >= '0' && l.data[l.pos] <= '9' {
				l.pos++
			}
		}
		if l.pos < len(l.data) {
			switch l.data[l.pos] {
			case '.', 'e', 'E', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				return nil, false
			}
		}
		return &node{kind: nodeNumber, text: string(l.data[start:l.pos])}, true
	default:
		return nil, false
	}
}

func (l *lexer) literal(word string) bool {
	if len(l.data)-l.pos < len(word) || string(l.data[l.pos:l.pos+len(word)]) != word {
		return false
	}
	l.pos += len(word)
	return true
}

func hexValue(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return r, true
}

func (l *lexer) escape() (rune, bool) {
	if len(l.data)-l.pos < 6 || l.data[l.pos] != '\\' || l.data[l.pos+1] != 'u' {
		return 0, false
	}
	r, ok := hexValue(l.data[l.pos+2 : l.pos+6])
	l.pos += 6
	return r, ok
}

func (l *lexer) text() (string, bool) {
	l.pos++ // opening quote
	var out []byte
	for {
		if l.pos >= len(l.data) {
			return "", false
		}
		c := l.data[l.pos]
		switch {
		case c == '"':
			l.pos++
			return string(out), true
		case c < 0x20:
			return "", false
		case c == '\\':
			if l.pos+1 >= len(l.data) {
				return "", false
			}
			switch e := l.data[l.pos+1]; e {
			case '"', '\\', '/':
				out = append(out, e)
				l.pos += 2
			case 'b':
				out = append(out, '\b')
				l.pos += 2
			case 'f':
				out = append(out, '\f')
				l.pos += 2
			case 'n':
				out = append(out, '\n')
				l.pos += 2
			case 'r':
				out = append(out, '\r')
				l.pos += 2
			case 't':
				out = append(out, '\t')
				l.pos += 2
			case 'u':
				r, ok := l.escape()
				if !ok {
					return "", false
				}
				switch {
				case utf16.IsSurrogate(r):
					if r >= 0xdc00 {
						return "", false
					}
					low, ok := l.escape()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return "", false
					}
					r = utf16.DecodeRune(r, low)
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", false
			}
		default:
			r, size := utf8.DecodeRune(l.data[l.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", false
			}
			out = append(out, l.data[l.pos:l.pos+size]...)
			l.pos += size
		}
	}
}

// checker records the earliest failing phase after lexing. A shape failure
// stops decoding at once; field and grant failures let decoding continue so
// that a later shape failure still wins.
type checker struct {
	fieldFail, grantFail bool
}

func (c *checker) check(ok bool) {
	if !ok {
		c.fieldFail = true
	}
}

func (c *checker) agree(ok bool) {
	if !ok {
		c.grantFail = true
	}
}

func (c *checker) result(shapeOK bool) error {
	switch {
	case !shapeOK:
		return ErrShape
	case c.fieldFail:
		return ErrField
	case c.grantFail:
		return ErrGrant
	}
	return nil
}

// fields reports whether n is an object whose members are exactly the
// required names plus any of the optional names.
func fields(n *node, required []string, optional ...string) bool {
	if n == nil || n.kind != nodeObject {
		return false
	}
	present := 0
	for _, k := range n.keys {
		found := false
		for _, r := range required {
			if k == r {
				found = true
				present++
				break
			}
		}
		if !found {
			for _, o := range optional {
				if k == o {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return present == len(required)
}

func asString(n *node) (string, bool) {
	if n == nil || n.kind != nodeString {
		return "", false
	}
	return n.text, true
}

func asBool(n *node) (bool, bool) {
	if n == nil || n.kind != nodeBool {
		return false, false
	}
	return n.flag, true
}

func asArray(n *node) ([]*node, bool) {
	if n == nil || n.kind != nodeArray {
		return nil, false
	}
	return n.items, true
}

func asStrings(n *node) ([]string, bool) {
	items, ok := asArray(n)
	if !ok {
		return nil, false
	}
	out := make([]string, len(items))
	for i, item := range items {
		if out[i], ok = asString(item); !ok {
			return nil, false
		}
	}
	return out, true
}

// uint64Lexeme decodes the decimal-string form: 0 to MaxUint64 without
// leading zeros. A string of another form is a field failure.
func (c *checker) uint64Lexeme(n *node) (uint64, bool) {
	s, ok := asString(n)
	if !ok {
		return 0, false
	}
	v, valid := parseUint64(s)
	c.check(valid)
	return v, true
}

func parseUint64(s string) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// hexDigest decodes 64 lowercase hex characters.
func (c *checker) hexDigest(n *node) ([32]byte, bool) {
	s, ok := asString(n)
	if !ok {
		return [32]byte{}, false
	}
	d, valid := parseDigest(s)
	c.check(valid)
	return d, true
}

func parseDigest(s string) ([32]byte, bool) {
	var d [32]byte
	if len(s) != 64 {
		return d, false
	}
	for i := 0; i < 64; i++ {
		v, ok := lowerHex(s[i])
		if !ok {
			return [32]byte{}, false
		}
		d[i/2] |= v << (4 * (1 - i%2))
	}
	return d, true
}

func lowerHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func pattern(p string) *regexp.Regexp { return regexp.MustCompile("^(?:" + p + ")$") }

var (
	idPattern          = pattern(`[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,15}`)
	namePattern        = pattern(`[a-z][a-z0-9]*(?:-[a-z0-9]+)*`)
	versionPattern     = pattern(`(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[a-z-][0-9a-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-z-][0-9a-z-]*))*)?`)
	fingerprintPattern = pattern(`sha256:[0-9a-f]{64}`)
	uuidPattern        = pattern(`[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`)
	policyNamePattern  = pattern(`[A-Za-z][A-Za-z0-9]{0,63}`)
	mimePattern        = pattern(`[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*`)
	posixRootPattern   = pattern(`(?:/(?:[A-Za-z0-9_-]|\.[A-Za-z0-9_-]|\.\.[A-Za-z0-9._-])(?:[A-Za-z0-9._ -]*[A-Za-z0-9._-])?)+`)
	windowsRootPattern = pattern(`[A-Z]:(?:\\(?:(?:[A-Za-z0-9_-]|\.[A-Za-z0-9_-])(?:[A-Za-z0-9._ -]*[A-Za-z0-9_-])?|\.\.(?:[A-Za-z0-9_-]|[A-Za-z0-9._-][A-Za-z0-9._ -]*[A-Za-z0-9_-])))+`)
	profilePattern     = pattern(`[a-z0-9][a-z0-9.-]{0,127}`)
	hostPattern        = pattern(`[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+`)
	urlPattern         = pattern(`https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?`)
)

// lengthIn counts code points, as JSON Schema minLength and maxLength do.
func lengthIn(s string, min, max int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}

func matches(s string, min, max int, p *regexp.Regexp) bool {
	return lengthIn(s, min, max) && p.MatchString(s)
}

func validID(s string) bool          { return matches(s, 3, 253, idPattern) }
func validName(s string) bool        { return matches(s, 1, 63, namePattern) }
func validVersion(s string) bool     { return matches(s, 5, 128, versionPattern) }
func validFingerprint(s string) bool { return matches(s, 71, 71, fingerprintPattern) }
func validUUID(s string) bool        { return matches(s, 36, 36, uuidPattern) }

// validDisplayName excludes C0 and C1 controls and DEL.
func validDisplayName(s string) bool {
	if !lengthIn(s, 1, 128) {
		return false
	}
	for _, r := range s {
		if r <= 0x1f || r >= 0x7f && r <= 0x9f {
			return false
		}
	}
	return true
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if _, dup := seen[v]; dup {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}

// stringSet checks a JSON set of strings: bounded count, unique items and a
// per-item rule.
func stringSet(values []string, min, max int, item func(string) bool) bool {
	if len(values) < min || len(values) > max || !uniqueStrings(values) {
		return false
	}
	for _, v := range values {
		if !item(v) {
			return false
		}
	}
	return true
}

var servedInterfaceNames = func() []string {
	out := make([]string, len(componentPairs))
	for i, p := range componentPairs {
		out[i] = p.iface
	}
	return out
}()

func knownInterface(s string) bool { return oneOf(s, servedInterfaceNames...) }

// ParseSnapshot decodes the decision-scoped snapshot. A parsed value proves
// shape, never authority.
func ParseSnapshot(data []byte) (Snapshot, error) {
	root, err := decodeJSON(data, MaxSnapshotBytes, MaxSnapshotValues)
	if err != nil {
		return Snapshot{}, err
	}
	var c checker
	s, ok := c.snapshot(root)
	if ok {
		c.validSnapshot(&s)
	}
	if err := c.result(ok); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

// ParseRequest decodes an admission request.
func ParseRequest(data []byte) (Request, error) {
	root, err := decodeJSON(data, MaxRequestBytes, MaxRequestValues)
	if err != nil {
		return Request{}, err
	}
	var c checker
	r, ok := c.request(root)
	if ok {
		c.validRequest(&r)
	}
	if err := c.result(ok); err != nil {
		return Request{}, err
	}
	return r, nil
}

func (c *checker) snapshot(n *node) (Snapshot, bool) {
	var s Snapshot
	if !fields(n, []string{"recovery_epoch", "approval_policy_disabled", "approval_policy_generation", "first_start", "automatic_release_floor", "release_version", "project_key", "served_interfaces", "trust_list", "revocations", "revocation_generation", "ownership", "tombstones", "install", "registrations", "disclosure_profiles", "device_groups", "consumed_approvals"}) {
		return s, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	s.RecoveryEpoch, b = c.uint64Lexeme(n.member("recovery_epoch"))
	step(b)
	s.ApprovalPolicyDisabled, b = asBool(n.member("approval_policy_disabled"))
	step(b)
	s.ApprovalPolicyGeneration, b = c.uint64Lexeme(n.member("approval_policy_generation"))
	step(b)
	s.FirstStart, b = asBool(n.member("first_start"))
	step(b)
	if rv := n.member("release_version"); rv.kind != nodeNull {
		s.ReleaseVersion, b = asString(rv)
		step(b)
		// An empty string is not a version; null is the absent release.
		c.check(s.ReleaseVersion != "")
	}
	if floor := n.member("automatic_release_floor"); floor.kind != nodeNull {
		s.AutomaticReleaseFloor, b = asString(floor)
		step(b)
		c.check(s.AutomaticReleaseFloor != "")
	}
	s.ProjectKey, b = asString(n.member("project_key"))
	step(b)
	s.ServedInterfaces, b = asStrings(n.member("served_interfaces"))
	step(b)
	s.RevocationGeneration, b = c.uint64Lexeme(n.member("revocation_generation"))
	step(b)
	s.DisclosureProfiles, b = asStrings(n.member("disclosure_profiles"))
	step(b)
	s.DeviceGroups, b = asStrings(n.member("device_groups"))
	step(b)
	s.ConsumedApprovals, b = asStrings(n.member("consumed_approvals"))
	step(b)
	if !ok {
		return s, false
	}
	trust, ok := asArray(n.member("trust_list"))
	if !ok {
		return s, false
	}
	s.TrustList = make([]TrustEntry, len(trust))
	for i, t := range trust {
		if s.TrustList[i], ok = c.trustEntry(t); !ok {
			return s, false
		}
	}
	revocations, ok := asArray(n.member("revocations"))
	if !ok {
		return s, false
	}
	s.Revocations = make([]Revocation, len(revocations))
	for i, r := range revocations {
		if !fields(r, []string{"id"}, "version") {
			return s, false
		}
		if s.Revocations[i].ID, ok = asString(r.member("id")); !ok {
			return s, false
		}
		if v := r.member("version"); v != nil {
			if s.Revocations[i].Version, ok = asString(v); !ok {
				return s, false
			}
			c.check(s.Revocations[i].Version != "")
		}
	}
	if o := n.member("ownership"); o.kind != nodeNull {
		if !fields(o, []string{"id", "owner", "prior_owners", "ownership_generation"}) {
			return s, false
		}
		w := &Ownership{}
		w.ID, b = asString(o.member("id"))
		step(b)
		w.Owner, b = asString(o.member("owner"))
		step(b)
		w.PriorOwners, b = asStrings(o.member("prior_owners"))
		step(b)
		w.OwnershipGeneration, b = c.uint64Lexeme(o.member("ownership_generation"))
		step(b)
		if !ok {
			return s, false
		}
		s.Ownership = w
	}
	tombstones, ok := asArray(n.member("tombstones"))
	if !ok {
		return s, false
	}
	s.Tombstones = make([]Tombstone, len(tombstones))
	for i, t := range tombstones {
		if s.Tombstones[i], ok = c.tombstone(t); !ok {
			return s, false
		}
	}
	if in := n.member("install"); in.kind != nodeNull {
		install, ok := c.install(in)
		if !ok {
			return s, false
		}
		s.Install = &install
	}
	registrations, ok := asArray(n.member("registrations"))
	if !ok {
		return s, false
	}
	s.Registrations = make([]Registration, len(registrations))
	for i, r := range registrations {
		if s.Registrations[i], ok = c.registration(r); !ok {
			return s, false
		}
	}
	return s, true
}

func (c *checker) trustEntry(n *node) (TrustEntry, bool) {
	var t TrustEntry
	if !fields(n, []string{"fingerprint", "public_key_hex", "name", "prefixes", "project_publisher", "revoked", "retired", "generation"}) {
		return t, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	t.Fingerprint, b = asString(n.member("fingerprint"))
	step(b)
	t.PublicKey, b = c.hexDigest(n.member("public_key_hex"))
	step(b)
	t.Name, b = asString(n.member("name"))
	step(b)
	t.Prefixes, b = asStrings(n.member("prefixes"))
	step(b)
	t.ProjectPublisher, b = asBool(n.member("project_publisher"))
	step(b)
	t.Revoked, b = asBool(n.member("revoked"))
	step(b)
	t.Retired, b = asBool(n.member("retired"))
	step(b)
	t.Generation, b = c.uint64Lexeme(n.member("generation"))
	step(b)
	return t, ok
}

func (c *checker) tombstone(n *node) (Tombstone, bool) {
	var t Tombstone
	if !fields(n, []string{"id", "version", "publisher", "manifest_sha256", "package_sha256"}) {
		return t, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	t.ID, b = asString(n.member("id"))
	step(b)
	t.Version, b = asString(n.member("version"))
	step(b)
	t.Publisher, b = asString(n.member("publisher"))
	step(b)
	t.ManifestSHA256, b = c.hexDigest(n.member("manifest_sha256"))
	step(b)
	t.PackageSHA256, b = c.hexDigest(n.member("package_sha256"))
	step(b)
	return t, ok
}

func (c *checker) install(n *node) (Install, bool) {
	var in Install
	if !fields(n, []string{"id", "version", "package_sha256", "state", "enabled", "generation", "targets", "grants"}) {
		return in, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	var state string
	in.ID, b = asString(n.member("id"))
	step(b)
	in.Version, b = asString(n.member("version"))
	step(b)
	in.PackageSHA256, b = c.hexDigest(n.member("package_sha256"))
	step(b)
	state, b = asString(n.member("state"))
	in.State = InstallState(state)
	step(b)
	in.Enabled, b = asBool(n.member("enabled"))
	step(b)
	in.Generation, b = c.uint64Lexeme(n.member("generation"))
	step(b)
	in.Targets, b = c.targets(n.member("targets"))
	step(b)
	if !ok {
		return in, false
	}
	records, ok := asArray(n.member("grants"))
	if !ok {
		return in, false
	}
	in.Grants = make([]GrantRecord, len(records))
	for i, r := range records {
		if in.Grants[i], ok = c.grantRecord(r); !ok {
			return in, false
		}
	}
	return in, true
}

func (c *checker) registration(n *node) (Registration, bool) {
	var r Registration
	if !fields(n, []string{"id", "browser", "recovery_epoch", "registration_generation", "os"}, "bound") {
		return r, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	r.ID, b = asString(n.member("id"))
	step(b)
	r.Browser, b = asString(n.member("browser"))
	step(b)
	r.RecoveryEpoch, b = c.uint64Lexeme(n.member("recovery_epoch"))
	step(b)
	r.RegistrationGeneration, b = c.uint64Lexeme(n.member("registration_generation"))
	step(b)
	var known bool
	r.OS, known, b = osPolicies(n.member("os"))
	step(b && known)
	if bn := n.member("bound"); bn != nil {
		if !fields(bn, []string{"id", "component", "state"}) {
			return r, false
		}
		bound := &Bound{}
		var state string
		bound.ID, b = asString(bn.member("id"))
		step(b)
		bound.Component, b = asString(bn.member("component"))
		step(b)
		state, b = asString(bn.member("state"))
		bound.State = InstallState(state)
		step(b)
		r.Bound = bound
	}
	return r, ok
}

// osPolicies decodes an os object. known is false when a member is not an OS
// name; ok is false for any other shape failure.
func osPolicies(n *node) (p OSPolicies, known, ok bool) {
	if n == nil || n.kind != nodeObject {
		return p, true, false
	}
	known = true
	for i, k := range n.keys {
		entry := n.items[i]
		if !fields(entry, []string{"policy_names", "native_host"}) {
			return p, known, false
		}
		names, ok := asStrings(entry.member("policy_names"))
		if !ok {
			return p, known, false
		}
		native, ok := asBool(entry.member("native_host"))
		if !ok {
			return p, known, false
		}
		policy := &OSPolicy{PolicyNames: names, NativeHost: native}
		switch k {
		case "macos":
			p.MacOS = policy
		case "windows":
			p.Windows = policy
		case "linux":
			p.Linux = policy
		default:
			known = false
		}
	}
	return p, known, true
}

func (c *checker) targets(n *node) (Targets, bool) {
	var t Targets
	if !fields(n, []string{"device_groups", "all_devices", "console", "jobs"}) {
		return t, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	t.DeviceGroups, b = asStrings(n.member("device_groups"))
	step(b)
	t.AllDevices, b = asBool(n.member("all_devices"))
	step(b)
	t.Console, b = asBool(n.member("console"))
	step(b)
	t.Jobs, b = asBool(n.member("jobs"))
	step(b)
	return t, ok
}

func (c *checker) request(n *node) (Request, bool) {
	var r Request
	if !fields(n, []string{"source", "requester", "grant_update", "grants", "targets", "approval"}) {
		return r, false
	}
	ok := true
	step := func(b bool) { ok = ok && b }
	var b bool
	var source string
	source, b = asString(n.member("source"))
	r.Source = Source(source)
	step(b)
	r.Requester, b = asString(n.member("requester"))
	step(b)
	r.GrantUpdate, b = asBool(n.member("grant_update"))
	step(b)
	r.Targets, b = c.targets(n.member("targets"))
	step(b)
	if !ok {
		return r, false
	}
	grants, ok := asArray(n.member("grants"))
	if !ok {
		return r, false
	}
	r.Grants = make([]Grant, len(grants))
	for i, g := range grants {
		if r.Grants[i], ok = c.grant(g); !ok {
			return r, false
		}
	}
	if a := n.member("approval"); a.kind != nodeNull {
		approval, ok := c.approval(a)
		if !ok {
			return r, false
		}
		r.Approval = &approval
	}
	return r, true
}

// validSnapshot applies every schema string, enum, bound and uniqueness rule
// to a typed snapshot.
func (c *checker) validSnapshot(s *Snapshot) {
	c.check(stringSet(s.ServedInterfaces, 0, 11, knownInterface))
	c.check(s.ReleaseVersion == "" || validVersion(s.ReleaseVersion))
	c.check(s.AutomaticReleaseFloor == "" || validVersion(s.AutomaticReleaseFloor))
	c.check(validFingerprint(s.ProjectKey))
	// Once an array's count fails, the result is ErrField whatever its items
	// hold, so its item and uniqueness passes are skipped; the remaining
	// uniqueness checks are map lookups on exact equality keys. Work stays
	// linear in the input.
	if c.within(len(s.TrustList), 0, 1024) {
		seen := make(map[string]struct{}, len(s.TrustList))
		for i := range s.TrustList {
			t := &s.TrustList[i]
			c.check(validFingerprint(t.Fingerprint) && validDisplayName(t.Name) && stringSet(t.Prefixes, 1, 16, validID))
			c.check(firstSeen(seen, trustEntryKey(t)))
		}
	}
	if c.within(len(s.Revocations), 0, 2) {
		seen := make(map[Revocation]struct{}, len(s.Revocations))
		for _, r := range s.Revocations {
			c.check(validID(r.ID) && (r.Version == "" || validVersion(r.Version)))
			_, dup := seen[r]
			c.check(!dup)
			seen[r] = struct{}{}
		}
	}
	if o := s.Ownership; o != nil {
		c.check(validID(o.ID) && validFingerprint(o.Owner) && stringSet(o.PriorOwners, 0, 1023, validFingerprint))
	}
	if c.within(len(s.Tombstones), 0, 2) {
		seen := make(map[Tombstone]struct{}, len(s.Tombstones))
		for _, t := range s.Tombstones {
			c.check(validID(t.ID) && validVersion(t.Version) && validFingerprint(t.Publisher))
			_, dup := seen[t]
			c.check(!dup)
			seen[t] = struct{}{}
		}
	}
	if in := s.Install; in != nil {
		c.check(validID(in.ID) && validVersion(in.Version) && (in.State == StateActive || in.State == StateRecoveryPending))
		c.validTargets(&in.Targets)
		if c.within(len(in.Grants), 1, 64) {
			for i := range in.Grants {
				c.validGrantRecord(&in.Grants[i])
			}
		}
	}
	if c.within(len(s.Registrations), 0, 64) {
		seen := make(map[string]struct{}, len(s.Registrations))
		for i := range s.Registrations {
			r := &s.Registrations[i]
			c.check(validID(r.ID) && validName(r.Browser))
			c.validOSPolicies(&r.OS)
			if b := r.Bound; b != nil {
				c.check(validID(b.ID) && validName(b.Component) && (b.State == StateActive || b.State == StateRecoveryPending))
			}
			c.check(firstSeen(seen, registrationKey(r)))
		}
	}
	c.check(stringSet(s.DisclosureProfiles, 0, 64, validProfile))
	c.check(stringSet(s.DeviceGroups, 0, 1024, validUUID))
	c.check(stringSet(s.ConsumedApprovals, 0, 1, validUUID))
}

// within records a count failure and reports whether the count is in bounds.
func (c *checker) within(n, min, max int) bool {
	ok := n >= min && n <= max
	c.check(ok)
	return ok
}

// firstSeen adds key to seen and reports whether it was absent.
func firstSeen(seen map[string]struct{}, key string) bool {
	if _, dup := seen[key]; dup {
		return false
	}
	seen[key] = struct{}{}
	return true
}

func (c *checker) validOSPolicies(p *OSPolicies) {
	present := 0
	for _, e := range []*OSPolicy{p.MacOS, p.Windows, p.Linux} {
		if e != nil {
			present++
			c.check(stringSet(e.PolicyNames, 0, 64, validPolicyName))
		}
	}
	c.check(present >= 1)
}

func validPolicyName(s string) bool { return matches(s, 1, 64, policyNamePattern) }
func validProfile(s string) bool    { return matches(s, 1, 128, profilePattern) }

func (c *checker) validTargets(t *Targets) {
	c.check(stringSet(t.DeviceGroups, 0, 1024, validUUID))
}

func (c *checker) validRequest(r *Request) {
	c.check(oneOf(string(r.Source), "upload", "api", "gitops", "index", "server-image"))
	c.check(validUUID(r.Requester))
	if c.within(len(r.Grants), 0, 64) {
		for i := range r.Grants {
			c.validGrant(&r.Grants[i])
		}
	}
	c.validTargets(&r.Targets)
	if r.Approval != nil {
		c.validApproval(r.Approval)
	}
}

// trustEntryKey and registrationKey are injective encodings: equal keys
// exactly when the JSON objects are equal.
func trustEntryKey(t *TrustEntry) string {
	var k equalityKey
	k.str(t.Fingerprint)
	k.bytes(t.PublicKey[:])
	k.str(t.Name)
	k.strs(t.Prefixes)
	k.flags(t.ProjectPublisher, t.Revoked, t.Retired)
	k.u64(t.Generation)
	return string(k)
}

func registrationKey(r *Registration) string {
	var k equalityKey
	k.str(r.ID)
	k.str(r.Browser)
	k.u64(r.RecoveryEpoch)
	k.u64(r.RegistrationGeneration)
	k.osPolicies(&r.OS, false)
	k.flags(r.Bound != nil)
	if b := r.Bound; b != nil {
		k.str(b.ID)
		k.str(b.Component)
		k.str(string(b.State))
	}
	return string(k)
}

func stringsEqual(a, b []string) bool {
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
