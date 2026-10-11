package ocsf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

type fixture struct {
	Name          string  `json:"name"`
	Source        string  `json:"source"`
	EventJSON     string  `json:"event_json"`
	ExpectedError *string `json:"expected_error"`
}
type fixtureSet struct {
	Format int       `json:"format"`
	Events []fixture `json:"events"`
	Parser []fixture `json:"parser"`
}

func fixtures(t testing.TB, name string) fixtureSet {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../../../schemas/ocsf", name))
	if err != nil {
		t.Fatal(err)
	}
	value, err := decode(string(data))
	if err != nil {
		t.Fatal(err)
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 3 || !equal(root["format"], json.Number("1")) {
		t.Fatal("fixture envelope")
	}
	f := fixtureSet{Format: 1}
	seen := map[string]bool{}
	for _, kind := range []string{"events", "parser"} {
		cases, ok := root[kind].([]any)
		if !ok || len(cases) > 2048 {
			t.Fatal("fixture list")
		}
		for _, raw := range cases {
			c, ok := raw.(map[string]any)
			fields := 3
			if kind == "events" {
				fields = 4
			}
			if !ok || len(c) != fields {
				t.Fatal("fixture fields")
			}
			name, ok := c["name"].(string)
			if !ok || len(name) > 128 || !regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`).MatchString(name) || seen[name] {
				t.Fatal("fixture name")
			}
			seen[name] = true
			event, ok := c["event_json"].(string)
			if !ok || len(event) > 2<<20 {
				t.Fatal("fixture event text")
			}
			expected, present := c["expected_error"]
			if !present {
				t.Fatal("fixture expected result")
			}
			entry := fixture{Name: name, EventJSON: event}
			if expected != nil {
				code, ok := expected.(string)
				if !ok {
					t.Fatal("fixture expected type")
				}
				entry.ExpectedError = &code
			}
			if kind == "events" {
				s, ok := c["source"].(string)
				if !ok || (s != "agent" && s != "server") {
					t.Fatal("fixture source")
				}
				entry.Source = s
				if entry.ExpectedError != nil && !contains([]string{"ErrSource", "ErrBudget", "ErrDecoded", "ErrVersion", "ErrClass", "ErrShape", "ErrConstraint"}, *entry.ExpectedError) {
					t.Fatal("fixture sentinel")
				}
				f.Events = append(f.Events, entry)
			} else {
				if entry.ExpectedError == nil || *entry.ExpectedError != "parse.invalid" {
					t.Fatal("parser expected error")
				}
				f.Parser = append(f.Parser, entry)
			}
		}
	}
	return f
}

func decode(text string) (any, error) {
	if !utf8.ValidString(text) || !validEscapes(text) {
		return nil, errors.New("strict encoding")
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 128 {
			return nil, errors.New("decoder depth")
		}
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch tok {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				k, ok := key.(string)
				if !ok {
					return nil, errors.New("key")
				}
				if _, ok = m[k]; ok {
					return nil, errors.New("duplicate")
				}
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			_, err = d.Token()
			return m, err
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err = d.Token()
			return a, err
		default:
			return tok, nil
		}
	}
	v, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing")
	}
	return v, nil
}

// The test decoder rejects lone surrogate escapes which encoding/json repairs.
func validEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		i++
		for i < len(s) && s[i] != '"' {
			if s[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(s) {
				return false
			}
			if s[i] != 'u' {
				i++
				continue
			}
			if i+4 >= len(s) {
				return false
			}
			n, ok := hex4(s[i+1 : i+5])
			if !ok {
				return false
			}
			i += 5
			if n >= 0xD800 && n <= 0xDBFF {
				if i+5 >= len(s) || s[i:i+2] != "\\u" {
					return false
				}
				low, ok := hex4(s[i+2 : i+6])
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return false
				}
				i += 6
			} else if n >= 0xDC00 && n <= 0xDFFF {
				return false
			}
		}
	}
	return true
}
func hex4(s string) (int, bool) {
	n := 0
	for _, c := range s {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += int(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}
func source(s string) Source {
	if s == "agent" {
		return Agent
	}
	if s == "server" {
		return Server
	}
	return 0
}
func assertError(t testing.TB, err error, want string) {
	t.Helper()
	sentinels := map[string]error{"ErrSource": ErrSource, "ErrBudget": ErrBudget, "ErrDecoded": ErrDecoded, "ErrVersion": ErrVersion, "ErrClass": ErrClass, "ErrShape": ErrShape, "ErrConstraint": ErrConstraint}
	if want == "" && err != nil {
		t.Fatalf("unexpected %v", err)
	}
	for name, e := range sentinels {
		if errors.Is(err, e) != (name == want) {
			t.Fatalf("error %v matches %s, want %s", err, name, want)
		}
	}
}
func example(t testing.TB, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../../../schemas/ocsf/examples/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := decode(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}
func TestExamples(t *testing.T) {
	for _, n := range []string{"health", "policy", "pipeline", "certificate"} {
		s := Agent
		if n == "certificate" {
			s = Server
		}
		assertError(t, Validate(example(t, n), s), "")
	}
}
func TestSharedFixtures(t *testing.T) {
	for _, path := range []string{"examples/vectors.json", "fixtures/events.json"} {
		f := fixtures(t, path)
		for _, c := range f.Events {
			t.Run(c.Name, func(t *testing.T) {
				v, err := decode(c.EventJSON)
				if err != nil {
					t.Fatal(err)
				}
				want := ""
				if c.ExpectedError != nil {
					want = *c.ExpectedError
				}
				assertError(t, Validate(v, source(c.Source)), want)
			})
		}
		for _, p := range f.Parser {
			if _, err := decode(p.EventJSON); err == nil {
				t.Fatalf("parser accepted %s", p.Name)
			}
		}
	}
}
func TestErrorPrecedence(t *testing.T) {
	e := example(t, "policy")
	m := e["metadata"].(map[string]any)
	m["version"] = "2.0.0"
	e["class_uid"] = json.Number("1")
	assertError(t, Validate(e, Agent), "ErrVersion")
	m["version"] = "1.9.0"
	e["unknown"] = true
	assertError(t, Validate(e, Agent), "ErrClass")
	e["class_uid"] = json.Number("99901002")
	e["type_uid"] = json.Number("1")
	assertError(t, Validate(e, Agent), "ErrShape")
	e["message"] = strings.Repeat("a", MaxStringBytes+1)
	m["version"] = "2.0.0"
	assertError(t, Validate(e, Agent), "ErrBudget")
	cycle := map[string]any{}
	cycle["self"] = cycle
	assertError(t, Validate(cycle, 0), "ErrSource")
	assertError(t, Validate(cycle, Agent), "ErrBudget")
}
func TestDecodedTypes(t *testing.T) {
	type aliasMap map[string]any
	type aliasNumber json.Number
	type aliasString string
	for _, v := range []any{map[string]any(nil), []any(nil), float64(1), int64(1), 1, aliasMap{}, aliasNumber("1"), aliasString("s"), new(int), struct{}{}, string([]byte{255}), json.Number("01"), json.Number("NaN"), json.Number("-"), json.Number("+1")} {
		assertError(t, Validate(v, Agent), "ErrDecoded")
	}
	for _, n := range []string{strings.Repeat("x", 65), "1" + strings.Repeat("0", 64)} {
		e := example(t, "policy")
		e["metadata"].(map[string]any)["sequence"] = json.Number(n)
		assertError(t, Validate(e, Agent), "ErrBudget")
	}
	assertError(t, Validate(nil, Agent), "ErrShape")
}
func TestBudgets(t *testing.T) {
	for _, n := range []int{MaxStringBytes - 1, MaxStringBytes, MaxStringBytes + 1} {
		want := "ErrShape"
		if n > MaxStringBytes {
			want = "ErrBudget"
		}
		assertError(t, Validate(strings.Repeat("x", n), Agent), want)
	}
	for _, n := range []int{MaxArrayItems - 1, MaxArrayItems, MaxArrayItems + 1} {
		want := "ErrShape"
		if n > MaxArrayItems {
			want = "ErrBudget"
		}
		assertError(t, Validate(make([]any, n), Agent), want)
	}
	for _, n := range []int{MaxObjectFields - 1, MaxObjectFields, MaxObjectFields + 1} {
		m := map[string]any{}
		for i := 0; i < n; i++ {
			m[strings.Repeat("x", i+1)] = nil
		}
		want := "ErrShape"
		if n > MaxObjectFields {
			want = "ErrBudget"
		}
		assertError(t, Validate(m, Agent), want)
	}
	for _, depth := range []int{MaxDepth - 1, MaxDepth, MaxDepth + 1} {
		var v any = nil
		for i := 0; i < depth; i++ {
			v = []any{v}
		}
		want := "ErrShape"
		if depth > MaxDepth {
			want = "ErrBudget"
		}
		assertError(t, Validate(v, Agent), want)
	}
	m := map[string]any{strings.Repeat("x", MaxStringBytes+1): nil}
	assertError(t, Validate(m, Agent), "ErrBudget")
}
func snapshot(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestNoMutation(t *testing.T) {
	e := example(t, "health")
	before := snapshot(t, e)
	assertError(t, Validate(e, Agent), "")
	if !bytes.Equal(before, snapshot(t, e)) {
		t.Fatal("mutated input")
	}
	shared := map[string]any{"a": json.Number("0")}
	e = map[string]any{"a": shared, "b": shared}
	before = snapshot(t, e)
	assertError(t, Validate(e, Agent), "ErrShape")
	if !bytes.Equal(before, snapshot(t, e)) {
		t.Fatal("mutated aliases")
	}
}
func TestSourceContext(t *testing.T) {
	assertError(t, Validate(example(t, "certificate"), Agent), "ErrShape")
	e := example(t, "policy")
	e["source"] = "server"
	assertError(t, Validate(e, Agent), "ErrShape")
	e = example(t, "policy")
	e["metadata"].(map[string]any)["sequence"] = json.Number("1")
	assertError(t, Validate(e, Agent), "") /* A decoded map cannot reveal a duplicate discarded before this API. */
}
func TestCoverage(t *testing.T) {
	e := example(t, "health")
	e["processes"].([]any)[0].(map[string]any)["cpu_pct"] = json.Number("0")
	assertError(t, Validate(e, Agent), "ErrConstraint")
}
func TestConcurrentValidate(t *testing.T) {
	e := example(t, "health")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			for j := 0; j < 10; j++ {
				if err := Validate(e, Agent); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}

func TestWorkBoundaries(t *testing.T) {
	for _, count := range []int{MaxNodes - 1, MaxNodes, MaxNodes + 1} {
		m := map[string]any{}
		remaining := count - 17
		for i := 0; i < 16; i++ {
			n := min(remaining, 1024)
			m[strconv.Itoa(i)] = make([]any, n)
			remaining -= n
		}
		want := "ErrShape"
		if count > MaxNodes {
			want = "ErrBudget"
		}
		assertError(t, Validate(m, Agent), want)
	}
	for _, total := range []int{MaxTotalBytes - 1, MaxTotalBytes, MaxTotalBytes + 1} {
		a := make([]any, 32)
		for i := 0; i < 31; i++ {
			a[i] = strings.Repeat("a", MaxStringBytes)
		}
		a[31] = strings.Repeat("a", total-2-31*MaxStringBytes)
		want := "ErrShape"
		if total > MaxTotalBytes {
			want = "ErrBudget"
		}
		assertError(t, Validate(a, Agent), want)
	}
	shared := make([]any, 1024)
	a := make([]any, 32)
	for i := range a {
		a[i] = shared
	}
	assertError(t, Validate(a, Agent), "ErrBudget")
	m := map[string]any{string([]byte{255}): nil}
	assertError(t, Validate(m, Agent), "ErrDecoded")
}

func TestKeyAtNodeBoundary(t *testing.T) {
	root := make([]any, 16)
	for i := 0; i < 15; i++ {
		root[i] = make([]any, 1024)
	}
	final := make([]any, 1007)
	final[1006] = map[string]any{string([]byte{255}): nil}
	root[15] = final
	assertError(t, Validate(root, Agent), "ErrDecoded")
}
