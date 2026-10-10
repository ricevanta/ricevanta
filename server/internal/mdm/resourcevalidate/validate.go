// Package resourcevalidate validates decoded MDM authoring resources. Acceptance
// grants no publication, execution, membership or evidence authority.
package resourcevalidate

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInput    = errors.New("mdm resource input")
	ErrLimit    = errors.New("mdm resource limit")
	ErrEnvelope = errors.New("mdm resource envelope")
	ErrSchema   = errors.New("mdm resource schema")
	ErrSemantic = errors.New("mdm resource semantic")
)

type Result struct {
	Kind                    string
	Name                    string
	RequiresContentApproval bool
	ApplyItemIDs            []string
}

type Error struct {
	Path  string
	Rule  string
	Cause error
}

func (e *Error) Error() string { return "mdm validation " + e.Rule + " at " + e.Path }
func (e *Error) Unwrap() error { return e.Cause }

type location []any

func (p location) child(k any) location {
	q := make(location, len(p)+1)
	copy(q, p)
	q[len(p)] = k
	return q
}
func (p location) pointer() string {
	var b strings.Builder
	for _, k := range p {
		var s string
		switch x := k.(type) {
		case string:
			s = x
		case int:
			s = strconv.Itoa(x)
		}
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1"))
	}
	return b.String()
}
func before(a, b location) bool {
	for i := 0; i < min(len(a), len(b)); i++ {
		switch x := a[i].(type) {
		case string:
			y, ok := b[i].(string)
			if !ok {
				return true
			}
			if x != y {
				return x < y
			}
		case int:
			y, ok := b[i].(int)
			if !ok {
				return false
			}
			if x != y {
				return x < y
			}
		}
	}
	return len(a) < len(b)
}
func failure(cause error, p location, rule string) *Error {
	return &Error{Path: p.pointer(), Rule: rule, Cause: cause}
}

type defect struct {
	path location
	rank int
}
type checker struct {
	path location
	best **defect
}

func (c checker) at(k any) checker { return checker{c.path.child(k), c.best} }
func (c checker) bad(rank int) {
	d := &defect{c.path, rank}
	old := *c.best
	if old == nil || before(d.path, old.path) || !before(old.path, d.path) && rank < old.rank {
		*c.best = d
	}
}
func (c checker) obj(v any, required, optional string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return nil
	}
	allowed := map[string]bool{}
	for _, k := range strings.Fields(required) {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			c.at(k).bad(0)
		}
	}
	for _, k := range strings.Fields(optional) {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			c.at(k).bad(1)
		}
	}
	return m
}
func (c checker) field(m map[string]any, k string, fn func(checker, any)) {
	if v, ok := m[k]; ok {
		fn(c.at(k), v)
	}
}
func (c checker) nonempty(m map[string]any) {
	if len(m) == 0 {
		c.bad(4)
	}
}
func (c checker) boolean(v any) {
	if _, ok := v.(bool); !ok {
		c.bad(2)
	}
}
func (c checker) integer(v any, lo, hi float64) {
	x, ok := v.(float64)
	if !ok || math.Trunc(x) != x {
		c.bad(2)
		return
	}
	if x < lo || x > hi {
		c.bad(4)
	}
}
func (c checker) one(v any, choices ...any) bool {
	for _, x := range choices {
		switch y := x.(type) {
		case string:
			if s, ok := v.(string); ok && s == y {
				return true
			}
		case bool:
			if b, ok := v.(bool); ok && b == y {
				return true
			}
		case float64:
			if n, ok := v.(float64); ok && n == y {
				return true
			}
		}
	}
	c.bad(3)
	return false
}
func (c checker) enum(v any, choices string) bool {
	a := strings.Fields(choices)
	for _, x := range a {
		if s, ok := v.(string); ok && s == x {
			return true
		}
	}
	c.bad(3)
	return false
}
func (c checker) text(v any, lo, hi int, multiline bool) string {
	s, ok := v.(string)
	if !ok {
		c.bad(2)
		return ""
	}
	n := utf8.RuneCountInString(s)
	if n < lo || n > hi {
		c.bad(4)
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			if !multiline || r != '\t' && r != '\r' && r != '\n' {
				c.bad(5)
				break
			}
		}
	}
	return s
}
func (c checker) pattern(v any, lo, hi int, re *regexp.Regexp) {
	s := c.text(v, lo, hi, false)
	if _, ok := v.(string); ok && !re.MatchString(s) {
		c.bad(5)
	}
}

var (
	namePattern        = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$`)
	appleTypePattern   = regexp.MustCompile(`^com\.apple\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$`)
	fingerprintPattern = regexp.MustCompile(`^(?:[A-F0-9]{40}|[A-F0-9]{64})$`)
	base64Pattern      = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	durationPattern    = regexp.MustCompile(`^[1-9][0-9]{0,5}[smhd]$`)
	posixPattern       = regexp.MustCompile(`^/[\x21-\x2e\x30-\x5b\x5d-\x7e]+(?:/[\x21-\x2e\x30-\x5b\x5d-\x7e]+)*$`)
	blobPattern        = regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)
)

func (c checker) name(v any)        { c.pattern(v, 1, 63, namePattern) }
func (c checker) hash(v any)        { c.pattern(v, 1, 64, hashPattern) }
func (c checker) identifier(v any)  { c.pattern(v, 1, 255, identifierPattern) }
func (c checker) fingerprint(v any) { c.pattern(v, 1, 64, fingerprintPattern) }
func (c checker) version(v any) {
	s := c.text(v, 1, 128, false)
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == 0x85 || r == 0xa0 || r == 0x1680 || r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000 || r == 0xfeff {
			c.bad(5)
			return
		}
	}
}
func (c checker) duration(v any) {
	if n, ok := v.(float64); ok {
		c.one(n, float64(0))
		return
	}
	c.pattern(v, 1, 7, durationPattern)
}
func (c checker) packageName(v any, n int) {
	s := c.text(v, 1, n, false)
	if strings.HasPrefix(s, "-") || strings.ContainsFunc(s, unicode.IsSpace) {
		c.bad(5)
	}
}
func (c checker) basename(v any, n int) {
	s := c.text(v, 1, n, false)
	if strings.ContainsAny(s, "/\\") {
		c.bad(5)
	}
}
func (c checker) array(v any, lo, hi int, set bool, fn func(checker, any)) []any {
	a, ok := v.([]any)
	if !ok {
		c.bad(2)
		return nil
	}
	if len(a) < lo || len(a) > hi {
		c.bad(4)
	}
	// Bounded canonical comparison preserves JSON structural equality without
	// calling marshalers. All elements already passed the decoded-input scan.
	if set {
		seen := map[string]bool{}
		for _, x := range a {
			s := comparisonKey(x)
			if seen[s] {
				c.bad(4)
			}
			seen[s] = true
		}
	}
	for i, x := range a {
		fn(c.at(i), x)
	}
	return a
}
func comparisonKey(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == 0 {
			return "0"
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case string:
		return strconv.Quote(x)
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for _, y := range x {
			b.WriteString(comparisonKey(y))
			b.WriteByte(',')
		}
		b.WriteByte(']')
		return b.String()
	case map[string]any:
		var b strings.Builder
		b.WriteByte('{')
		for _, k := range keys(x) {
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			b.WriteString(comparisonKey(x[k]))
			b.WriteByte(',')
		}
		b.WriteByte('}')
		return b.String()
	}
	return ""
}
func (c checker) groups(v any) { c.array(v, 1, 64, true, func(q checker, x any) { q.name(x) }) }
func (c checker) native(v any) {
	switch x := v.(type) {
	case string:
		if utf8.RuneCountInString(x) > 16384 {
			c.bad(4)
		}
	case []any:
		if len(x) > 256 {
			c.bad(4)
		}
		for i, y := range x {
			c.at(i).native(y)
		}
	case map[string]any:
		if len(x) > 256 {
			c.bad(4)
		}
		for k, y := range x {
			if utf8.RuneCountInString(k) > 16384 {
				c.bad(4)
			}
			c.at(k).native(y)
		}
	}
}
func (c checker) nativeObject(v any) {
	if _, ok := v.(map[string]any); !ok {
		c.bad(2)
	}
	c.native(v)
}
func (c checker) metadata(v any) {
	m := c.obj(v, "name", "labels annotations description")
	if m == nil {
		return
	}
	c.field(m, "name", func(q checker, x any) { q.name(x) })
	c.field(m, "description", func(q checker, x any) { q.text(x, 0, 1024, false) })
	for _, k := range []string{"labels", "annotations"} {
		c.field(m, k, func(q checker, x any) {
			a, ok := x.(map[string]any)
			if !ok {
				q.bad(2)
				return
			}
			if len(a) > 32 {
				q.bad(4)
			}
			cap := 63
			if k == "annotations" {
				cap = 4096
			}
			for key, v := range a {
				q.text(key, 0, 256, false)
				q.at(key).text(v, 0, cap, false)
			}
		})
	}
}
func envelope(m map[string]any) *Error {
	if m == nil {
		return failure(ErrEnvelope, nil, "envelope")
	}
	var best *defect
	c := checker{best: &best}
	c.obj(m, "apiVersion kind metadata spec", "")
	c.field(m, "apiVersion", func(q checker, x any) { q.one(x, "ricevanta.io/v1alpha1") })
	c.field(m, "kind", func(q checker, x any) { q.enum(x, "Baseline SoftwarePackage DeviceGroup") })
	c.field(m, "metadata", func(q checker, x any) { q.metadata(x) })
	c.field(m, "spec", func(q checker, x any) {
		if _, ok := x.(map[string]any); !ok {
			q.bad(2)
		}
	})
	if best != nil {
		return failure(ErrEnvelope, best.path, "envelope")
	}
	return nil
}
func structural(m map[string]any) *Error {
	var best *defect
	c := checker{path: location{"spec"}, best: &best}
	s := m["spec"].(map[string]any)
	switch m["kind"] {
	case "Baseline":
		c.baseline(s)
	case "SoftwarePackage":
		c.software(s)
	case "DeviceGroup":
		c.group(s)
	}
	if best != nil {
		return failure(ErrSchema, best.path, "schema")
	}
	return nil
}

// Validate checks the decoded domain, budgets, envelope, structure and semantic
// rules in that order. The caller must not mutate resource during the call.
func Validate(resource map[string]any) (Result, error) {
	if err := scan(resource); err != nil {
		return Result{}, err
	}
	if charge(resource) > 1048576 {
		return Result{}, failure(ErrLimit, nil, "bytes")
	}
	if resource["kind"] == "Baseline" {
		if s, ok := resource["spec"].(map[string]any); ok {
			if a, ok := s["items"].([]any); ok {
				for i, x := range a {
					if m, ok := x.(map[string]any); ok {
						if v, ok := m["settings"]; ok && charge(v) > 65536 {
							return Result{}, failure(ErrLimit, location{"spec", "items", i, "settings"}, "bytes")
						}
					}
				}
			}
		}
	}
	if err := envelope(resource); err != nil {
		return Result{}, err
	}
	if err := structural(resource); err != nil {
		return Result{}, err
	}
	if err := semantic(resource); err != nil {
		return Result{}, err
	}
	r := Result{Kind: resource["kind"].(string), Name: resource["metadata"].(map[string]any)["name"].(string)}
	if r.Kind == "SoftwarePackage" {
		r.RequiresContentApproval = true
	}
	if r.Kind == "Baseline" {
		for _, x := range resource["spec"].(map[string]any)["items"].([]any) {
			m := x.(map[string]any)
			_, apply := kindClass(m["kind"].(string))
			if apply {
				r.ApplyItemIDs = append(r.ApplyItemIDs, m["id"].(string))
				r.RequiresContentApproval = true
			}
		}
	}
	return r, nil
}
