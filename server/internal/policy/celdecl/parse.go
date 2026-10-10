package celdecl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// Load reads a bounded declaration without closing the caller's reader.
func Load(r io.Reader) (*Document, error) {
	if r == nil {
		return nil, ErrRead
	}
	data := make([]byte, 0, MaxBytes+1)
	var buf [4096]byte
	empty := 0
	for len(data) <= MaxBytes {
		budget := MaxBytes + 1 - len(data)
		if budget > len(buf) {
			budget = len(buf)
		}
		n, err := r.Read(buf[:budget])
		data = append(data, buf[:n]...)
		if len(data) > MaxBytes {
			return nil, ErrSize
		}
		if err != nil {
			if err == io.EOF {
				return Parse(data)
			}
			return nil, fmt.Errorf("%w: %w", ErrRead, err)
		}
		if n > 0 {
			empty = 0
		} else {
			empty++
			if empty == 100 {
				return nil, fmt.Errorf("%w: %w", ErrRead, io.ErrNoProgress)
			}
		}
	}
	return nil, ErrSize
}

// Parse checks declaration phases in their specified precedence order.
func Parse(data []byte) (*Document, error) {
	root, err := parseShape(data)
	if err != nil {
		return nil, err
	}
	c, err := validateCatalogue(root)
	if err != nil {
		return nil, err
	}
	if !matchesTrusted(c) {
		return nil, ErrCatalogue
	}
	return &Document{catalogue: &c}, nil
}

type tokenParser struct {
	decoder   *json.Decoder
	tokens    int
	duplicate bool
	badNumber bool
}

func (p *tokenParser) token() (json.Token, error) {
	t, err := p.decoder.Token()
	if err != nil {
		return nil, ErrJSON
	}
	p.tokens++
	if p.tokens > 32768 {
		return nil, ErrSize
	}
	if n, ok := t.(json.Number); ok && !decimal(string(n)) {
		p.badNumber = true
	}
	return t, nil
}
func (p *tokenParser) value(depth int) (any, error) {
	t, err := p.token()
	if err != nil {
		return nil, err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	if delim != '{' && delim != '[' {
		return nil, ErrJSON
	}
	depth++
	if depth > 64 {
		return nil, ErrSize
	}
	if delim == '{' {
		m := make(map[string]any)
		for p.decoder.More() {
			key, err := p.token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrJSON
			}
			v, err := p.value(depth)
			if err != nil {
				return nil, err
			}
			if _, exists := m[name]; exists {
				p.duplicate = true
			}
			m[name] = v
		}
		end, err := p.token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim('}') {
			return nil, ErrJSON
		}
		return m, nil
	}
	a := make([]any, 0)
	for p.decoder.More() {
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
	}
	end, err := p.token()
	if err != nil {
		return nil, err
	}
	if end != json.Delim(']') {
		return nil, ErrJSON
	}
	return a, nil
}
func decimal(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) == 0 || s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Decoder tokens bound the tree before strict string checks and duplicate errors.
func parseShape(data []byte) (map[string]any, error) {
	if len(data) > MaxBytes {
		return nil, ErrSize
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	p := tokenParser{decoder: d}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	// Scan additional values for caps, but never accept more than one root value.
	trailing := false
	for {
		// InputOffset advances after each value. Scan only the following whitespace.
		cursor := int(d.InputOffset())
		for cursor < len(data) {
			c := data[cursor]
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				break
			}
			cursor++
		}
		if cursor == len(data) {
			break
		}
		trailing = true
		if _, err := p.value(0); err != nil {
			return nil, err
		}
	}
	if trailing || p.badNumber || !strictStrings(data) {
		return nil, ErrJSON
	}
	if p.duplicate {
		return nil, ErrDuplicateKey
	}
	root, ok := v.(map[string]any)
	if !ok || !shape(root) {
		return nil, ErrShape
	}
	return root, nil
}

func strictStrings(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	in := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			in = !in
			continue
		}
		if !in || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func object(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func exact(m map[string]any, required []string, optional ...string) bool {
	if len(m) < len(required) || len(m) > len(required)+len(optional) {
		return false
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	for k := range m {
		found := false
		for _, r := range required {
			if k == r {
				found = true
			}
		}
		for _, r := range optional {
			if k == r {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func isString(v any) bool { _, ok := v.(string); return ok }
func isNumber(v any) bool { _, ok := v.(json.Number); return ok }
func docShape(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func entryShape(v any) bool {
	m, ok := object(v)
	if !ok || !exact(m, []string{"type", "presence", "doc"}, "values") || !docShape(m["doc"]) {
		return false
	}
	switch m["presence"] {
	case "required", "optional", "network", "exact":
	default:
		return false
	}
	if values, exists := m["values"]; exists {
		a, ok := values.([]any)
		if !ok {
			return false
		}
		seen := make(map[string]bool)
		for _, v := range a {
			s, ok := v.(string)
			if !ok || seen[s] {
				return false
			}
			seen[s] = true
		}
	}
	return true
}
func shape(root map[string]any) bool {
	if !exact(root, []string{"format_version", "profile", "declaration_version", "ocsf_version", "objects", "variables", "domains"}) || !isNumber(root["format_version"]) || !isNumber(root["declaration_version"]) || !isString(root["ocsf_version"]) {
		return false
	}
	profile, ok := object(root["profile"])
	if !ok || !exact(profile, []string{"id", "version"}) || !isString(profile["id"]) || !isNumber(profile["version"]) {
		return false
	}
	objects, ok := object(root["objects"])
	if !ok || len(objects) == 0 {
		return false
	}
	for _, v := range objects {
		o, ok := object(v)
		if !ok || !exact(o, []string{"doc", "fields"}) || !docShape(o["doc"]) {
			return false
		}
		fields, ok := object(o["fields"])
		if !ok || len(fields) == 0 {
			return false
		}
		for _, e := range fields {
			if !entryShape(e) {
				return false
			}
		}
	}
	variables, ok := object(root["variables"])
	if !ok || len(variables) == 0 {
		return false
	}
	for _, e := range variables {
		if !entryShape(e) {
			return false
		}
	}
	_, ok = object(root["domains"])
	return ok
}

type rawEntry struct {
	value    map[string]any
	variable bool
}

func catalogueEntries(root map[string]any) []rawEntry {
	entries := make([]rawEntry, 0)
	for _, o := range root["objects"].(map[string]any) {
		for _, e := range o.(map[string]any)["fields"].(map[string]any) {
			entries = append(entries, rawEntry{value: e.(map[string]any)})
		}
	}
	for _, e := range root["variables"].(map[string]any) {
		entries = append(entries, rawEntry{value: e.(map[string]any), variable: true})
	}
	return entries
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func referenceNames(v any) bool {
	m, ok := object(v)
	if !ok {
		return true
	}
	switch m["kind"] {
	case "object":
		name, ok := m["name"].(string)
		return !ok || identifier(name)
	case "list":
		return referenceNames(m["element"])
	case "map":
		return referenceNames(m["value"])
	}
	return true
}
func typeGrammar(v any) bool {
	m, ok := object(v)
	if !ok {
		return false
	}
	kind, ok := m["kind"].(string)
	if !ok {
		return false
	}
	switch kind {
	case "bool", "int", "double", "null", "timestamp", "duration", "json":
		return exact(m, []string{"kind"})
	case "string":
		return exact(m, []string{"kind", "max_length"}) && isNumber(m["max_length"])
	case "list":
		return exact(m, []string{"kind", "element", "max_items"}) && isNumber(m["max_items"]) && typeGrammar(m["element"])
	case "map":
		return exact(m, []string{"kind", "key", "value", "max_entries"}) && m["key"] == "string" && isNumber(m["max_entries"]) && typeGrammar(m["value"])
	case "object":
		return exact(m, []string{"kind", "name"}) && isString(m["name"])
	}
	return false
}
func bound(v any, max uint64) bool {
	n, err := strconv.ParseUint(string(v.(json.Number)), 10, 64)
	return err == nil && n >= 1 && n <= max
}
func typeLimits(v any, depth int) bool {
	if depth > 16 {
		return false
	}
	m := v.(map[string]any)
	switch m["kind"] {
	case "string":
		return bound(m["max_length"], 32768)
	case "list":
		return bound(m["max_items"], 10000) && typeLimits(m["element"], depth+1)
	case "map":
		return bound(m["max_entries"], 1024) && typeLimits(m["value"], depth+1)
	}
	return true
}
func textLimit(v any, max int) bool {
	n := utf8.RuneCountInString(v.(string))
	return n >= 1 && n <= max
}
func typeReferences(v any) []string {
	m := v.(map[string]any)
	switch m["kind"] {
	case "object":
		return []string{m["name"].(string)}
	case "list":
		return typeReferences(m["element"])
	case "map":
		return typeReferences(m["value"])
	}
	return nil
}

// validateCatalogue completes semantic phases without trusted-catalogue comparison.
func validateCatalogue(root map[string]any) (Catalogue, error) {
	fail := func(err error) (Catalogue, error) { return Catalogue{}, err }
	if root["format_version"] != json.Number("1") || root["declaration_version"] != json.Number("1") {
		return fail(ErrVersion)
	}
	profile := root["profile"].(map[string]any)
	if profile["id"] != "ricevanta-cel-1" || profile["version"] != json.Number("1") {
		return fail(ErrProfile)
	}
	if root["ocsf_version"] != "1.9.0" {
		return fail(ErrOCSF)
	}
	objects := root["objects"].(map[string]any)
	variables := root["variables"].(map[string]any)
	entries := catalogueEntries(root)
	for name, o := range objects {
		if !identifier(name) {
			return fail(ErrName)
		}
		for field := range o.(map[string]any)["fields"].(map[string]any) {
			if !identifier(field) {
				return fail(ErrName)
			}
		}
	}
	for name := range variables {
		if !identifier(name) {
			return fail(ErrName)
		}
	}
	for _, e := range entries {
		if !referenceNames(e.value["type"]) {
			return fail(ErrName)
		}
	}
	for _, e := range entries {
		if !typeGrammar(e.value["type"]) {
			return fail(ErrType)
		}
		if _, exists := e.value["values"]; exists && e.value["type"].(map[string]any)["kind"] != "string" {
			return fail(ErrType)
		}
		if e.variable && e.value["presence"] != "required" && e.value["presence"] != "optional" {
			return fail(ErrType)
		}
	}
	if len(objects) > 64 || len(variables) > 64 {
		return fail(ErrLimit)
	}
	for _, o := range objects {
		m := o.(map[string]any)
		if len(m["fields"].(map[string]any)) > 64 || !textLimit(m["doc"], 1024) {
			return fail(ErrLimit)
		}
	}
	for _, e := range entries {
		if !textLimit(e.value["doc"], 1024) || !typeLimits(e.value["type"], 1) {
			return fail(ErrLimit)
		}
		if values, exists := e.value["values"]; exists {
			a := values.([]any)
			if len(a) < 1 || len(a) > 32 {
				return fail(ErrLimit)
			}
			for _, s := range a {
				if !textLimit(s, 64) {
					return fail(ErrLimit)
				}
			}
		}
	}
	domains := root["domains"].(map[string]any)
	if !exact(domains, []string{"mdm", "edr", "dlp", "lineage", "pki", "network"}) {
		return fail(ErrDomain)
	}
	for name, value := range domains {
		contexts, ok := object(value)
		if !ok {
			return fail(ErrDomain)
		}
		keys := []string{"condition", "exception"}
		if name == "mdm" {
			keys = append(keys, "query", "collector")
		}
		if !exact(contexts, keys) {
			return fail(ErrDomain)
		}
		for _, v := range contexts {
			a, ok := v.([]any)
			if !ok || len(a) < 1 || len(a) > 64 {
				return fail(ErrDomain)
			}
			previous := ""
			for _, v := range a {
				s, ok := v.(string)
				if !ok || !identifier(s) || s <= previous {
					return fail(ErrDomain)
				}
				previous = s
			}
		}
	}
	for _, e := range entries {
		for _, ref := range typeReferences(e.value["type"]) {
			if _, exists := objects[ref]; !exists {
				return fail(ErrReference)
			}
		}
	}
	for _, value := range domains {
		for _, v := range value.(map[string]any) {
			for _, name := range v.([]any) {
				if _, exists := variables[name.(string)]; !exists {
					return fail(ErrReference)
				}
			}
		}
	}
	graph := make(map[string][]string, len(objects))
	for name, o := range objects {
		for _, e := range o.(map[string]any)["fields"].(map[string]any) {
			graph[name] = append(graph[name], typeReferences(e.(map[string]any)["type"])...)
		}
	}
	marks := make(map[string]uint8, len(objects))
	var visit func(string) bool
	visit = func(name string) bool {
		if marks[name] == 1 {
			return false
		}
		if marks[name] == 2 {
			return true
		}
		marks[name] = 1
		for _, ref := range graph[name] {
			if !visit(ref) {
				return false
			}
		}
		marks[name] = 2
		return true
	}
	for name := range objects {
		if !visit(name) {
			return fail(ErrCycle)
		}
	}
	// All numbers now fit their exported integer fields.
	data, err := json.Marshal(root)
	if err != nil {
		return fail(ErrCatalogue)
	}
	var c Catalogue
	if err := json.Unmarshal(data, &c); err != nil {
		return fail(ErrCatalogue)
	}
	return c, nil
}
