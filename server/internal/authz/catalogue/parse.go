package catalogue

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 1 << 20
const MaxEntries = 2048
const MaxDepth = 12

// Parse validates whole-document phases and retains only successful input.
func Parse(data []byte) (*Catalogue, error) {
	if len(data) > MaxBytes {
		return nil, ErrLimit
	}
	scan := wireScanner{data: data}
	if err := scan.value(0); err != nil {
		return nil, err
	}
	scan.space()
	if scan.pos != len(data) {
		return nil, ErrJSON
	}
	root, ok := fields(data, []string{"format_version", "revision", "permissions"}, "")
	if !ok {
		return nil, ErrShape
	}
	version, ok := uintToken(root["format_version"])
	if !ok {
		return nil, ErrShape
	}
	revision, ok := uintToken(root["revision"])
	if !ok || revision == 0 {
		return nil, ErrShape
	}
	raw := bytes.TrimSpace(root["permissions"])
	if len(raw) == 0 || raw[0] != '[' {
		return nil, ErrShape
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil {
		return nil, ErrShape
	}
	// Bound the entry count before allocating any per-entry metadata.
	entries := make([]json.RawMessage, 0)
	for decoder.More() {
		if len(entries) == MaxEntries {
			return nil, ErrShape
		}
		var entry json.RawMessage
		if err := decoder.Decode(&entry); err != nil {
			return nil, ErrShape
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		return nil, ErrShape
	}
	permissions := make([]Permission, len(entries))
	retiredPresent := make([]bool, len(entries))
	usesOverflow := make([]bool, len(entries))
	for i, raw := range entries {
		p, present, overflow, ok := decodeEntry(raw)
		if !ok {
			return nil, ErrShape
		}
		permissions[i] = p
		retiredPresent[i] = present
		usesOverflow[i] = overflow
	}
	if version != 1 {
		return nil, ErrVersion
	}
	for _, p := range permissions {
		if err := ValidateName(p.Name); err != nil {
			return nil, err
		}
	}
	for i, p := range permissions {
		if usesOverflow[i] || !validEntry(p, retiredPresent[i]) {
			return nil, ErrEntry
		}
	}
	seen := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		if seen[p.Name] {
			return nil, ErrDuplicate
		}
		seen[p.Name] = true
	}
	for i := 1; i < len(permissions); i++ {
		if permissions[i-1].Name >= permissions[i].Name {
			return nil, ErrOrder
		}
	}
	for _, p := range permissions {
		if p.Introduced > revision || p.Status == "retired" && (p.RetiredIn <= p.Introduced || p.RetiredIn > revision) {
			return nil, ErrRevision
		}
	}
	return &Catalogue{revision: revision, entries: permissions, data: bytes.Clone(data)}, nil
}

// wireScanner checks lexical order before shape decoding. Only object keys are
// retained during the scan; every allocation is bounded by MaxBytes and MaxDepth.
type wireScanner struct {
	data []byte
	pos  int
}

func (s *wireScanner) space() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\r', '\n':
			s.pos++
		default:
			return
		}
	}
}
func (s *wireScanner) take(b byte) bool {
	if s.pos < len(s.data) && s.data[s.pos] == b {
		s.pos++
		return true
	}
	return false
}
func (s *wireScanner) value(depth int) error {
	s.space()
	if s.pos >= len(s.data) {
		return ErrJSON
	}
	switch s.data[s.pos] {
	case '{', '[':
		depth++
		if depth > MaxDepth {
			return ErrLimit
		}
		object := s.data[s.pos] == '{'
		s.pos++
		s.space()
		end := byte(']')
		if object {
			end = '}'
		}
		if s.take(end) {
			return nil
		}
		var keys map[string]bool
		if object {
			keys = make(map[string]bool)
		}
		for {
			if object {
				key, err := s.text(true)
				if err != nil {
					return err
				}
				if keys[key] {
					return ErrJSON
				}
				keys[key] = true
				s.space()
				if !s.take(':') {
					return ErrJSON
				}
			}
			if err := s.value(depth); err != nil {
				return err
			}
			s.space()
			if s.take(end) {
				return nil
			}
			if !s.take(',') {
				return ErrJSON
			}
			s.space()
		}
	case '"':
		_, err := s.text(false)
		return err
	case 't':
		return s.literal("true")
	case 'f':
		return s.literal("false")
	case 'n':
		return s.literal("null")
	default:
		return s.number()
	}
}
func (s *wireScanner) literal(word string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		return ErrJSON
	}
	s.pos += len(word)
	return nil
}
func (s *wireScanner) number() error {
	start := s.pos
	s.take('-')
	if !s.take('0') {
		if s.pos >= len(s.data) || s.data[s.pos] < '1' || s.data[s.pos] > '9' {
			return ErrJSON
		}
		s.digits()
	}
	if s.take('.') {
		n := s.pos
		s.digits()
		if n == s.pos {
			return ErrJSON
		}
	}
	if s.take('e') || s.take('E') {
		if !s.take('+') {
			s.take('-')
		}
		n := s.pos
		s.digits()
		if n == s.pos {
			return ErrJSON
		}
	}
	if s.pos == start {
		return ErrJSON
	}
	return nil
}
func (s *wireScanner) digits() {
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
	}
}
func (s *wireScanner) hex() (uint64, bool) {
	if len(s.data)-s.pos < 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(s.data[s.pos:s.pos+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	s.pos += 4
	return n, true
}
func (s *wireScanner) text(decode bool) (string, error) {
	start := s.pos
	if !s.take('"') {
		return "", ErrJSON
	}
	for s.pos < len(s.data) {
		b := s.data[s.pos]
		s.pos++
		switch {
		case b == '"':
			if !decode {
				return "", nil
			}
			var decoded string
			if json.Unmarshal(s.data[start:s.pos], &decoded) != nil {
				return "", ErrJSON
			}
			return decoded, nil
		case b < 0x20:
			return "", ErrJSON
		case b == '\\':
			if s.pos == len(s.data) {
				return "", ErrJSON
			}
			esc := s.data[s.pos]
			s.pos++
			switch esc {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				n, ok := s.hex()
				if !ok || n >= 0xdc00 && n <= 0xdfff {
					return "", ErrJSON
				}
				if n >= 0xd800 && n <= 0xdbff {
					if !s.take('\\') || !s.take('u') {
						return "", ErrJSON
					}
					low, ok := s.hex()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return "", ErrJSON
					}
				}
			default:
				return "", ErrJSON
			}
		case b >= utf8.RuneSelf:
			_, size := utf8.DecodeRune(s.data[s.pos-1:])
			if size == 1 {
				return "", ErrJSON
			}
			s.pos += size - 1
		}
	}
	return "", ErrJSON
}
func fields(data []byte, required []string, optional string) (map[string]json.RawMessage, bool) {
	raw := bytes.TrimSpace(data)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, false
		}
	}
	for k := range m {
		known := k == optional && optional != ""
		for _, r := range required {
			known = known || k == r
		}
		if !known {
			return nil, false
		}
	}
	return m, true
}
func uintToken(raw []byte) (uint32, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 10 {
		return 0, false
	}
	for _, b := range raw {
		if b < '0' || b > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(string(raw), 10, 32)
	return uint32(n), err == nil
}
func decodeEntry(raw []byte) (Permission, bool, bool, bool) {
	m, ok := fields(raw, []string{"name", "owner", "scope", "protection", "approval", "rule", "grant", "status", "introduced", "uses", "source", "note"}, "retired_in")
	if !ok {
		return Permission{}, false, false, false
	}
	p := Permission{}
	for _, field := range []struct {
		key string
		dst *string
	}{{"name", &p.Name}, {"owner", &p.Owner}, {"scope", &p.Scope}, {"protection", &p.Protection}, {"approval", &p.Approval}, {"rule", &p.Rule}, {"grant", &p.Grant}, {"status", &p.Status}, {"source", &p.Source}, {"note", &p.Note}} {
		b := bytes.TrimSpace(m[field.key])
		if len(b) == 0 || b[0] != '"' || json.Unmarshal(b, field.dst) != nil {
			return Permission{}, false, false, false
		}
	}
	p.Introduced, ok = uintToken(m["introduced"])
	if !ok {
		return Permission{}, false, false, false
	}
	_, present := m["retired_in"]
	if present {
		p.RetiredIn, ok = uintToken(m["retired_in"])
		if !ok {
			return Permission{}, false, false, false
		}
	}
	b := bytes.TrimSpace(m["uses"])
	if len(b) == 0 || b[0] != '[' {
		return Permission{}, false, false, false
	}
	// Scan every item for shape errors, but retain at most 32 strings.
	// Overflow remains an entry defect after whole-document shape/version/name checks.
	scan := wireScanner{data: b, pos: 1}
	overflow := false
	for {
		scan.space()
		if scan.take(']') {
			break
		}
		start := scan.pos
		if _, err := scan.text(false); err != nil {
			return Permission{}, false, false, false
		}
		if len(p.Uses) == 32 {
			overflow = true
		} else {
			var v string
			if json.Unmarshal(b[start:scan.pos], &v) != nil {
				return Permission{}, false, false, false
			}
			p.Uses = append(p.Uses, v)
		}
		scan.space()
		if scan.take(']') {
			break
		}
		if !scan.take(',') {
			return Permission{}, false, false, false
		}
	}
	return p, present, overflow, true
}
func ascii(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func member(s, vocabulary string) bool {
	for _, v := range strings.Fields(vocabulary) {
		if s == v {
			return true
		}
	}
	return false
}
func validEntry(p Permission, retiredPresent bool) bool {
	tokens := strings.Split(p.Name, ".")
	namespace, verb := tokens[0], tokens[2]
	owner := namespace
	if namespace == "edr" {
		owner = "detection"
	}
	if !member(namespace, "audit authz dlp edr events extensions identity lineage mdm pki platform policy radius") || !(p.Owner == owner || namespace == "mdm" && p.Owner == "devices") {
		return false
	}
	if !member(verb, "advance approve assign backfill cancel capture collect complete confirm create delete diagnose disable disconnect enable execute export import install isolate_host key_operation kill_and_ban kill_process lock manage message override pause pin preflight promote publish quarantine_file read reclassify reconcile reject release remove replace replace_factor replay reset restart restore_file resume retire revoke rotate run run_script scan script shutdown simulate suspend test transfer unban uninstall unisolate_host unpin update update_os upgrade upload validate wipe withdraw") {
		return false
	}
	if !member(p.Scope, "organization device_group") || !member(p.Status, "active retired") || p.Introduced == 0 {
		return false
	}
	if retiredPresent != (p.Status == "retired") || retiredPresent && p.RetiredIn < 2 {
		return false
	}
	grant := "role"
	switch p.Name {
	case "identity.authority.approve":
		grant = "direct"
	case "extensions.ca_callback.complete":
		grant = "connector"
	}
	if p.Grant != grant {
		return false
	}
	if !member(p.Rule, "always audit_retention child_union destination_change extension_dependency fleet_gt_10 gateway_widen grant_sensitive group_change hold_narrow identity_authority none policy_change published_content") {
		return false
	}
	protection, approval := "conditional", "access_policy"
	switch p.Rule {
	case "none":
		protection, approval = "none", "none"
	case "always":
		protection = "always"
	case "identity_authority":
		protection, approval = "always", "identity_authority"
	}
	if p.Protection != protection || p.Approval != approval {
		return false
	}
	if !ascii(p.Source, 160) || !ascii(p.Note, 512) || len(p.Uses) < 1 || len(p.Uses) > 32 {
		return false
	}
	seen := make(map[string]bool, len(p.Uses))
	for _, u := range p.Uses {
		if !ascii(u, 160) || seen[u] {
			return false
		}
		seen[u] = true
	}
	return true
}
