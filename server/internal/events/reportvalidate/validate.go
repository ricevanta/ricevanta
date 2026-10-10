// Package reportvalidate checks decoded report authoring resources.
// Acceptance grants no execution rights or access to source rows.
package reportvalidate

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrCatalogue = errors.New("report catalogue unavailable")
	ErrInput     = errors.New("report input")
	ErrLimit     = errors.New("report limit")
	ErrEnvelope  = errors.New("report envelope")
	ErrSchema    = errors.New("report schema")
	ErrSemantic  = errors.New("report semantic")
)

type ConditionalRead struct{ Condition, Permission, Scope string }
type SourceRequirement struct {
	Source, Permission, Scope, Footprint string
	ConditionalReads                     []ConditionalRead
}
type Result struct {
	Name              string
	CatalogueRevision uint32
	Sources           []SourceRequirement
}
type Error struct {
	Path, Rule string
	Cause      error
}

func (e *Error) Error() string { return "report validation " + e.Rule }
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

var namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
var sourcePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
var fieldPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*/[a-z][a-z0-9_]{0,31}$`)
var timestampPattern = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$`)

func (c checker) name(v any)       { c.pattern(v, 1, 63, namePattern) }
func (c checker) identifier(v any) { c.pattern(v, 1, 32, identifierPattern) }
func envelope(m map[string]any) *Error {
	if m == nil {
		return failure(ErrEnvelope, nil, "envelope")
	}
	var best *defect
	c := checker{best: &best}
	c.obj(m, "apiVersion kind metadata spec", "")
	c.field(m, "apiVersion", func(q checker, x any) { q.one(x, "ricevanta.io/v1alpha1") })
	c.field(m, "kind", func(q checker, x any) { q.one(x, "ReportTemplate") })
	c.field(m, "metadata", func(q checker, x any) {
		a := q.obj(x, "name", "description")
		if a == nil {
			return
		}
		q.field(a, "name", func(r checker, y any) { r.name(y) })
		q.field(a, "description", func(r checker, y any) { r.text(y, 0, 1024, false) })
	})
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

// Validate checks catalogue availability before inspecting the decoded tree.
// Callers must not mutate resource during validation.
func Validate(resource map[string]any, catalogue *Catalogue) (Result, error) {
	if catalogue == nil || catalogue.revision == 0 {
		return Result{}, failure(ErrCatalogue, nil, "catalogue")
	}
	if e := scan(resource); e != nil {
		return Result{}, e
	}
	if charge(resource) > 65536 {
		return Result{}, failure(ErrLimit, nil, "bytes")
	}
	if e := envelope(resource); e != nil {
		return Result{}, e
	}
	if e := structural(resource); e != nil {
		return Result{}, e
	}
	if e := semantic(resource, catalogue); e != nil {
		return Result{}, e
	}
	r := Result{Name: resource["metadata"].(map[string]any)["name"].(string), CatalogueRevision: catalogue.revision}
	used := map[string]any{}
	for _, x := range objects(resource["spec"].(map[string]any)["datasets"]) {
		used[x["source"].(string)] = nil
	}
	for _, id := range keys(used) {
		req := catalogue.sources[id].requirement
		req.ConditionalReads = append([]ConditionalRead(nil), req.ConditionalReads...)
		r.Sources = append(r.Sources, req)
	}
	return r, nil
}
