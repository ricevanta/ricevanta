package reportvalidate

import (
	"strings"
	"testing"
)

func TestChargeVectors(t *testing.T) {
	for _, x := range []struct {
		v any
		n int
	}{{nil, 4}, {true, 4}, {float64(0), 24}, {map[string]any{}, 2}, {"", 2}, {"ế", 5}, {[]any{float64(0)}, 26}, {map[string]any{"a": float64(0)}, 30}, {"\"\\\n", 12}} {
		if got := charge(x.v); got != x.n {
			t.Fatalf("charge got %d want %d", got, x.n)
		}
	}
}
func TestBudgetBoundaries(t *testing.T) {
	c, _ := Builtin()
	for _, x := range []any{make([]any, 8192), strings.Repeat("\xff", 131073)} {
		_, e := Validate(map[string]any{"x": x}, c)
		assertError(t, e, ErrLimit, "/x", "budget")
	}
	cycle := map[string]any{}
	cycle["x"] = cycle
	if e := scan(cycle); e == nil {
		t.Fatal("cycle")
	}
	m := map[string]any{}
	for i := 0; i < 4096; i++ {
		m[strings.Repeat("a", i+1)] = nil
	}
	if e := scan(m); e == nil {
		t.Fatal("oversized immediate keys")
	}
}

// oracleCharge uses byte substitution rather than the production rune switch.
func oracleCharge(v any) int {
	switch x := v.(type) {
	case nil:
		return 4
	case bool:
		if x {
			return 4
		}
		return 5
	case float64:
		return 24
	case string:
		n := 2
		for _, b := range []byte(x) {
			if b < 32 {
				n += 6
			} else if b == '"' || b == '\\' {
				n += 2
			} else {
				n++
			}
		}
		return n
	case []any:
		n := 2
		for i, y := range x {
			if i > 0 {
				n++
			}
			n += oracleCharge(y)
		}
		return n
	case map[string]any:
		n := 2
		for k, y := range x {
			n += oracleCharge(k) + 1 + oracleCharge(y) + 1
		}
		if len(x) > 0 {
			n--
		}
		return n
	}
	panic("outside decoded domain")
}
func TestEncodedBoundary(t *testing.T) {
	c, _ := Builtin()
	for _, n := range []int{65536, 65537} {
		d := base("devices")
		blocks := []any{}
		for i := 0; i < 9; i++ {
			blocks = append(blocks, map[string]any{"type": "text", "text": map[string]any{"en": "a", "vi": "a"}})
		}
		d["spec"].(map[string]any)["layout"] = blocks
		remaining := n - oracleCharge(d)
		for _, b := range blocks {
			for _, lang := range []string{"en", "vi"} {
				text := b.(map[string]any)["text"].(map[string]any)
				take := min(4095, remaining)
				text[lang] = text[lang].(string) + strings.Repeat("a", take)
				remaining -= take
			}
		}
		if remaining != 0 || oracleCharge(d) != n || charge(d) != n {
			t.Fatal("boundary construction")
		}
		_, e := Validate(d, c)
		if n == 65536 && e != nil {
			t.Fatal(e)
		}
		if n == 65537 {
			assertError(t, e, ErrLimit, "", "bytes")
			d["kind"] = "WrongTemplate!"
			_, e = Validate(d, c)
			assertError(t, e, ErrLimit, "", "bytes")
		}
	}
}
func TestPreflightCaps(t *testing.T) {
	for _, n := range []int{8191, 8192} {
		a := make([]any, n)
		root := map[string]any{"a": a}
		e := scan(root)
		if e == nil {
			t.Fatal("node cap")
		}
	}
	for _, n := range []int{131071, 131072} {
		m := map[string]any{"a": strings.Repeat("x", n)}
		e := scan(m)
		if (e == nil) != (n == 131071) {
			t.Fatalf("raw cap %d: %v", n, e)
		}
	}
	for _, n := range []int{16, 17} {
		m := map[string]any{}
		root := m
		for i := 1; i < n; i++ {
			child := map[string]any{}
			m["a"] = child
			m = child
		}
		e := scan(root)
		if (e == nil) != (n == 16) {
			t.Fatalf("depth %d %v", n, e)
		}
	}
}

func TestExactNodeBudget(t *testing.T) {
	for _, n := range []int{8189, 8190} {
		root := map[string]any{"a": make([]any, n)}
		e := scan(root)
		if (e == nil) != (n == 8189) {
			t.Fatalf("nodes %d: %v", n+3, e)
		}
	}
	shared := []any{nil}
	if e := scan(map[string]any{"a": shared, "b": shared}); e != nil {
		t.Fatal(e)
	}
	if charge(map[string]any{"a": shared, "b": shared}) != oracleCharge(map[string]any{"a": shared, "b": shared}) {
		t.Fatal("shared subtree charge")
	}
}
