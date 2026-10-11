package ocsf

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

//go:embed schema/*.json
var schemas embed.FS
var errArtifact = errors.New("ocsf embedded schema")
var ruleOrder = []string{"type_uid", "bundle_state", "coverage", "sequence_range", "health_identity", "pipeline_activity", "policy_activity", "certificate_activity", "unmapped", "truncation"}
var keywords = strings.Fields("$schema $id $defs $ref title description type properties required additionalProperties items minItems maxItems minLength maxLength minimum maximum enum const pattern allOf anyOf oneOf not if then else x-source x-restriction x-maxBytes x-integer x-sourceKind x-rule")
var patterns = map[string]bool{
	`^[^\x00-\x1f\x7f]+$`: true, `^[a-z][a-z0-9_.-]*$`: true,
	`^[0-9a-f]{64}$`: true, `^([0-9a-f]{2}){1,20}$`: true,
	`^[A-Za-z0-9_.:-]+$`: true, `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`: true,
	`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`: true,
}

type schemaNode struct {
	kind                                               string
	properties                                         map[string]*schemaNode
	required                                           []string
	closed                                             bool
	ref, items, not, condition, then, otherwise        *schemaNode
	all, any, one                                      []*schemaNode
	minimum, maximum                                   *big.Rat
	minItems, maxItems, minLength, maxLength, maxBytes int
	enum                                               []any
	constant                                           any
	hasConst                                           bool
	pattern                                            *regexp.Regexp
	integer                                            string
	source                                             Source
	rules                                              []string
}
type compiler struct {
	definitions map[string]any
	cache       map[string]*schemaNode
	active      map[string]bool
	nodes       int
}

func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
func closed(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func schemaStrings(v any) ([]string, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, errArtifact
	}
	r := make([]string, 0, len(a))
	seen := map[string]bool{}
	for _, x := range a {
		s, ok := x.(string)
		if !ok || seen[s] {
			return nil, errArtifact
		}
		seen[s] = true
		r = append(r, s)
	}
	return r, nil
}
func rational(v any) (*big.Rat, bool) {
	n, ok := v.(json.Number)
	if !ok || len(n) > 64 || (!signed.MatchString(string(n)) && !decimal.MatchString(string(n))) {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(string(n))
	return r, ok
}
func natural(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok || !unsigned.MatchString(string(n)) {
		return 0, errArtifact
	}
	i, err := strconv.ParseUint(string(n), 10, 31)
	if err != nil {
		return 0, errArtifact
	}
	return int(i), nil
}

// compileSchema accepts bounded private loader inputs only; no public override exists.
func compileSchema(value any, _ map[string]*schemaNode, _ int) (*schemaNode, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errArtifact
	}
	defs := map[string]any{}
	if d, exists := m["$defs"]; exists {
		var ok bool
		defs, ok = d.(map[string]any)
		if !ok || len(defs) > 256 {
			return nil, errArtifact
		}
	}
	c := compiler{definitions: defs, cache: map[string]*schemaNode{}, active: map[string]bool{}}
	for name := range defs {
		if _, err := c.definition(name, 1); err != nil {
			return nil, err
		}
	}
	return c.node(value, 1)
}
func (c *compiler) definition(name string, depth int) (*schemaNode, error) {
	if c.active[name] {
		return nil, errArtifact
	}
	if s, ok := c.cache[name]; ok {
		return s, nil
	}
	v, ok := c.definitions[name]
	if !ok {
		return nil, errArtifact
	}
	c.active[name] = true
	s, err := c.node(v, depth+1)
	delete(c.active, name)
	if err != nil {
		return nil, err
	}
	c.cache[name] = s
	return s, nil
}
func (c *compiler) node(value any, depth int) (*schemaNode, error) {
	c.nodes++
	if depth > 64 || c.nodes > 4096 {
		return nil, errArtifact
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errArtifact
	}
	if _, exists := m["$defs"]; exists && depth != 1 {
		return nil, errArtifact
	}
	for k := range m {
		if !contains(keywords, k) {
			return nil, errArtifact
		}
	}
	s := &schemaNode{minItems: 0, maxItems: -1, minLength: 0, maxLength: -1}
	for _, k := range []string{"$schema", "$id", "title", "description", "x-source", "x-restriction"} {
		if v, exists := m[k]; exists {
			if _, ok := v.(string); !ok {
				return nil, errArtifact
			}
		}
	}
	if v, exists := m["type"]; exists {
		s.kind, ok = v.(string)
		if !ok || !contains([]string{"object", "array", "string", "integer", "number", "boolean"}, s.kind) {
			return nil, errArtifact
		}
	}
	if v, exists := m["additionalProperties"]; exists {
		if v != false {
			return nil, errArtifact
		}
		s.closed = true
	}
	if v, exists := m["required"]; exists {
		var err error
		s.required, err = schemaStrings(v)
		if err != nil {
			return nil, err
		}
	}
	for k, p := range map[string]*int{"minItems": &s.minItems, "maxItems": &s.maxItems, "minLength": &s.minLength, "maxLength": &s.maxLength, "x-maxBytes": &s.maxBytes} {
		if v, exists := m[k]; exists {
			n, err := natural(v)
			if err != nil || k == "x-maxBytes" && n == 0 {
				return nil, errArtifact
			}
			*p = n
		}
	}
	for k, p := range map[string]**big.Rat{"minimum": &s.minimum, "maximum": &s.maximum} {
		if v, exists := m[k]; exists {
			r, ok := rational(v)
			if !ok {
				return nil, errArtifact
			}
			*p = r
		}
	}
	if v, exists := m["pattern"]; exists {
		p, ok := v.(string)
		if !ok || !patterns[p] {
			return nil, errArtifact
		}
		var err error
		s.pattern, err = regexp.Compile(p)
		if err != nil {
			return nil, errArtifact
		}
	}
	if v, exists := m["x-integer"]; exists {
		s.integer, ok = v.(string)
		if !ok || !contains([]string{"uint64", "int64"}, s.integer) {
			return nil, errArtifact
		}
	}
	if v, exists := m["x-sourceKind"]; exists {
		switch v {
		case "agent":
			s.source = Agent
		case "server":
			s.source = Server
		default:
			return nil, errArtifact
		}
	}
	if v, exists := m["x-rule"]; exists {
		if depth != 1 {
			return nil, errArtifact
		}
		var err error
		s.rules, err = schemaStrings(v)
		if err != nil {
			return nil, err
		}
		last := -1
		for _, r := range s.rules {
			index := -1
			for i, n := range ruleOrder {
				if n == r {
					index = i
				}
			}
			if index <= last {
				return nil, errArtifact
			}
			last = index
		}
	}
	if v, exists := m["enum"]; exists {
		s.enum, ok = v.([]any)
		if !ok || len(s.enum) == 0 {
			return nil, errArtifact
		}
		for _, x := range s.enum {
			if !schemaLiteral(x) {
				return nil, errArtifact
			}
		}
	}
	if v, exists := m["const"]; exists {
		if !schemaLiteral(v) {
			return nil, errArtifact
		}
		s.constant = v
		s.hasConst = true
	}
	if v, exists := m["$ref"]; exists {
		p, ok := v.(string)
		if !ok || !strings.HasPrefix(p, "#/$defs/") {
			return nil, errArtifact
		}
		var err error
		s.ref, err = c.definition(p[8:], depth)
		if err != nil {
			return nil, err
		}
	}
	if v, exists := m["properties"]; exists {
		p, ok := v.(map[string]any)
		if !ok {
			return nil, errArtifact
		}
		s.properties = map[string]*schemaNode{}
		for k, v := range p {
			node, err := c.node(v, depth+1)
			if err != nil {
				return nil, err
			}
			s.properties[k] = node
		}
	}
	for k, p := range map[string]**schemaNode{"items": &s.items, "not": &s.not, "if": &s.condition, "then": &s.then, "else": &s.otherwise} {
		if v, exists := m[k]; exists {
			node, err := c.node(v, depth+1)
			if err != nil {
				return nil, err
			}
			*p = node
		}
	}
	for k, p := range map[string]*[]*schemaNode{"allOf": &s.all, "anyOf": &s.any, "oneOf": &s.one} {
		if v, exists := m[k]; exists {
			a, ok := v.([]any)
			if !ok || len(a) == 0 {
				return nil, errArtifact
			}
			for _, v := range a {
				node, err := c.node(v, depth+1)
				if err != nil {
					return nil, err
				}
				*p = append(*p, node)
			}
		}
	}
	return s, nil
}
func schemaLiteral(v any) bool {
	switch x := v.(type) {
	case string, bool:
		return true
	case json.Number:
		_, ok := rational(x)
		return ok
	case []any:
		for _, v := range x {
			if !schemaLiteral(v) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, v := range x {
			if !schemaLiteral(v) {
				return false
			}
		}
		return true
	}
	return false
}
func equal(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		r, ok := rational(x)
		if !ok {
			return false
		}
		s, ok := rational(y)
		return ok && r.Cmp(s) == 0
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i, v := range x {
			if !equal(v, y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !equal(v, w) {
				return false
			}
		}
		return true
	}
	return false
}
func (s *schemaNode) matches(v any, source Source) bool {
	if s.source != 0 && s.source != source {
		return false
	}
	if s.ref != nil && !s.ref.matches(v, source) {
		return false
	}
	switch s.kind {
	case "object":
		if _, ok := v.(map[string]any); !ok {
			return false
		}
	case "array":
		if _, ok := v.([]any); !ok {
			return false
		}
	case "string":
		if _, ok := v.(string); !ok {
			return false
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return false
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok || !signed.MatchString(string(n)) {
			return false
		}
	case "number":
		n, ok := v.(json.Number)
		if !ok || !decimal.MatchString(string(n)) {
			return false
		}
	}
	if s.hasConst && !equal(v, s.constant) {
		return false
	}
	if s.enum != nil {
		found := false
		for _, x := range s.enum {
			found = found || equal(v, x)
		}
		if !found {
			return false
		}
	}
	if s.integer != "" {
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		if s.integer == "uint64" {
			if !unsigned.MatchString(string(n)) {
				return false
			}
			if _, err := strconv.ParseUint(string(n), 10, 64); err != nil {
				return false
			}
		} else {
			if !signed.MatchString(string(n)) {
				return false
			}
			if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
				return false
			}
		}
	}
	if s.minimum != nil || s.maximum != nil {
		if _, ok := v.(json.Number); ok {
			r, ok := rational(v)
			if !ok || s.minimum != nil && r.Cmp(s.minimum) < 0 || s.maximum != nil && r.Cmp(s.maximum) > 0 {
				return false
			}
		}
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range s.required {
			if _, ok := x[k]; !ok {
				return false
			}
		}
		for k, v := range x {
			p, ok := s.properties[k]
			if ok {
				if !p.matches(v, source) {
					return false
				}
			} else if s.closed {
				return false
			}
		}
	case []any:
		if len(x) < s.minItems || s.maxItems >= 0 && len(x) > s.maxItems {
			return false
		}
		if s.items != nil {
			for _, v := range x {
				if !s.items.matches(v, source) {
					return false
				}
			}
		}
	case string:
		n := utf8.RuneCountInString(x)
		if n < s.minLength || s.maxLength >= 0 && n > s.maxLength || s.maxBytes > 0 && len(x) > s.maxBytes || s.pattern != nil && !s.pattern.MatchString(x) {
			return false
		}
	}
	for _, b := range s.all {
		if !b.matches(v, source) {
			return false
		}
	}
	if len(s.any) > 0 {
		found := false
		for _, b := range s.any {
			if b.matches(v, source) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(s.one) > 0 {
		count := 0
		for _, b := range s.one {
			if b.matches(v, source) {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	if s.not != nil && s.not.matches(v, source) {
		return false
	}
	if s.condition != nil {
		if s.condition.matches(v, source) {
			if s.then != nil && !s.then.matches(v, source) {
				return false
			}
		} else if s.otherwise != nil && !s.otherwise.matches(v, source) {
			return false
		}
	}
	return true
}

// artifactJSON rejects duplicates before building the private schema tree.
func artifactJSON(data []byte) (any, error) {
	if len(data) > 1048576 || !utf8.Valid(data) {
		return nil, errArtifact
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		nodes++
		if depth > 64 || nodes > 32768 {
			return nil, errArtifact
		}
		tok, err := d.Token()
		if err != nil {
			return nil, errArtifact
		}
		switch tok {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, errArtifact
				}
				key, ok := k.(string)
				if !ok {
					return nil, errArtifact
				}
				if _, ok = m[key]; ok {
					return nil, errArtifact
				}
				v, err := walk(depth + 1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			_, err = d.Token()
			if err != nil {
				return nil, errArtifact
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := walk(depth + 1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err = d.Token()
			if err != nil {
				return nil, errArtifact
			}
			return a, nil
		default:
			return tok, nil
		}
	}
	v, err := walk(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errArtifact
	}
	return v, nil
}
func readArtifact(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, errArtifact
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1048576 {
		return nil, errArtifact
	}
	b, err := io.ReadAll(io.LimitReader(f, 1048577))
	if err != nil || len(b) > 1048576 {
		return nil, errArtifact
	}
	return b, nil
}
func loadSchemas(fsys fs.FS) (map[uint64]*schemaNode, error) {
	fail := func() (map[uint64]*schemaNode, error) { return nil, fmt.Errorf("ocsf build defect: %w", errArtifact) }
	entries, err := fs.ReadDir(fsys, "schema")
	if err != nil || len(entries) != 5 {
		return fail()
	}
	manifest, err := readArtifact(fsys, "schema/manifest.json")
	if err != nil {
		return fail()
	}
	v, err := artifactJSON(manifest)
	if err != nil {
		return fail()
	}
	m, ok := v.(map[string]any)
	if !ok || !closed(m, "format", "profile", "upstream_commit", "inputs_sha256", "classes") || !equal(m["format"], json.Number("1")) || m["profile"] != "ricevanta-ocsf-1" || m["upstream_commit"] != "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba" {
		return fail()
	}
	digest, ok := m["inputs_sha256"].(string)
	if !ok || !hexDigest(digest) {
		return fail()
	}
	classes, ok := m["classes"].([]any)
	if !ok || len(classes) != 4 {
		return fail()
	}
	out := map[uint64]*schemaNode{}
	total := len(manifest)
	for i, id := range []uint64{99901001, 99901002, 99901003, 99903001} {
		c, ok := classes[i].(map[string]any)
		name := strconv.FormatUint(id, 10) + ".schema.json"
		if !ok || !closed(c, "class_uid", "path", "sha256") || !equal(c["class_uid"], json.Number(strconv.FormatUint(id, 10))) || c["path"] != name {
			return fail()
		}
		hash, ok := c["sha256"].(string)
		if !ok || !hexDigest(hash) {
			return fail()
		}
		data, err := readArtifact(fsys, "schema/"+name)
		if err != nil {
			return fail()
		}
		total += len(data)
		if total > 8388608 {
			return fail()
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != hash {
			return fail()
		}
		v, err := artifactJSON(data)
		if err != nil {
			return fail()
		}
		raw, ok := v.(map[string]any)
		if !ok || raw["$schema"] != "https://json-schema.org/draft/2020-12/schema" || raw["$id"] != "https://ricevanta.io/schemas/ocsf/compiled/"+name {
			return fail()
		}
		s, err := compileSchema(v, nil, 0)
		if err != nil {
			return fail()
		}
		if s.kind != "object" || !s.closed || s.properties["class_uid"] == nil || !equal(s.properties["class_uid"].constant, json.Number(strconv.FormatUint(id, 10))) {
			return fail()
		}
		expected := expectedRules(id)
		if len(expected) != len(s.rules) {
			return fail()
		}
		for j, r := range expected {
			if r != s.rules[j] {
				return fail()
			}
		}
		out[id] = s
	}
	return out, nil
}
func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func expectedRules(id uint64) []string {
	r := []string{"type_uid", "bundle_state"}
	switch id {
	case 99901001:
		r = append(r, "coverage", "health_identity")
	case 99901002:
		r = append(r, "policy_activity")
	case 99901003:
		r = append(r, "sequence_range", "pipeline_activity")
	case 99903001:
		r = append(r, "certificate_activity")
	}
	return append(r, "unmapped", "truncation")
}
