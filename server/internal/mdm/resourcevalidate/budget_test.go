package resourcevalidate

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Encode valid JSON independently, then adjust the short escapes and numeric tokens.
func chargeOracle(t testing.TB, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	total := len(b)
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch x := tok.(type) {
		case json.Number:
			total += 24 - len(x)
		case string:
			encoded, _ := json.Marshal(x)
			plain := 2
			for _, r := range x {
				switch {
				case r < 32:
					plain += 6
				case r == '"' || r == '\\':
					plain += 2
				default:
					plain += len(string(r))
				}
			}
			total += plain - len(encoded)
		}
	}
	return total
}
func budgetSettings(t testing.TB, n int, ch string) map[string]any {
	t.Helper()
	payload := map[string]any{}
	for i := range 8 {
		payload[fmt.Sprint(i)] = ""
	}
	s := map[string]any{"identifier": "io.test.item", "type": "com.apple.configuration", "payload": payload}
	left := n - chargeOracle(t, s)
	unit := len(ch)
	if ch == "\n" {
		unit = 6
	}
	for i := range 8 {
		k := fmt.Sprint(i)
		count := min(16384, left/unit)
		payload[k] = strings.Repeat(ch, count)
		left -= count * unit
	}
	payload["7"] = payload["7"].(string) + strings.Repeat("a", left)
	if chargeOracle(t, s) != n {
		t.Fatal("oracle construction")
	}
	return s
}
func TestValidateBudgetBoundaries(t *testing.T) {
	for _, v := range []struct {
		v any
		n int
	}{{map[string]any{}, 2}, {map[string]any{"a": float64(0)}, 30}, {map[string]any{"x": "é"}, 10}, {map[string]any{"x": "\n"}, 14}} {
		if charge(v.v) != v.n || chargeOracle(t, v.v) != v.n {
			t.Fatalf("charge vector %+v", v)
		}
	}
	for _, ch := range []string{"a", "😀", "\n"} {
		for _, n := range []int{65536, 65537} {
			m := baseline("macos", "apple.declaration", budgetSettings(t, n, ch))
			if n == 65536 {
				accept(t, m)
			} else {
				checkError(t, m, ErrLimit, "/spec/items/0/settings", "bytes")
			}
		}
		for _, n := range []int{1048576, 1048577} {
			m := baseline("macos", "apple.declaration", budgetSettings(t, 60000, ch))
			items := []any{}
			for i := range 17 {
				it := item(clone(t, m))
				it["id"] = fmt.Sprintf("item-%d", i)
				items = append(items, it)
			}
			pad := item(clone(t, m))
			pad["id"] = "padding"
			pad["settings"] = budgetSettings(t, 500, "a")
			items = append(items, pad)
			m["spec"].(map[string]any)["items"] = items
			pad["settings"] = budgetSettings(t, n-chargeOracle(t, m)+500, ch)
			if chargeOracle(t, m) != n {
				t.Fatal("whole budget oracle")
			}
			if n == 1048576 {
				accept(t, m)
			} else {
				checkError(t, m, ErrLimit, "", "bytes")
				m["kind"] = "UnknownKind"
				checkError(t, m, ErrLimit, "", "bytes")
			}
		}
	}
	for _, n := range []int{0, 1, 2000, 2001} {
		m := queryBaseline()
		a := []any{}
		for i := range n {
			it := item(queryBaseline())
			it["id"] = fmt.Sprintf("item-%d", i)
			a = append(a, it)
		}
		m["spec"].(map[string]any)["items"] = a
		if n == 1 || n == 2000 {
			accept(t, m)
		} else {
			checkError(t, m, ErrSchema, "/spec/items", "schema")
		}
	}
	for _, n := range []int{0, 1, 20000, 20001} {
		m := map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "DeviceGroup", "metadata": map[string]any{"name": "group"}, "spec": map[string]any{}}
		a := []any{}
		for i := range n {
			a = append(a, fmt.Sprintf("device-%d", i))
		}
		m["spec"].(map[string]any)["members"] = a
		if n == 1 || n == 20000 {
			accept(t, m)
		} else {
			checkError(t, m, ErrSchema, "/spec/members", "schema")
		}
	}
	for _, n := range []int{31, 32} {
		m := map[string]any{}
		child := m
		for range n {
			next := map[string]any{}
			child["x"] = next
			child = next
		}
		if n == 31 {
			checkError(t, m, ErrEnvelope, "/apiVersion", "envelope")
		} else {
			checkError(t, m, ErrLimit, strings.Repeat("/x", 32), "budget")
		}
	}
	m := map[string]any{"x": strings.Repeat("a", 2097152)}
	checkError(t, m, ErrLimit, "/x", "budget")
	m = map[string]any{"x": make([]any, 100000)}
	checkError(t, m, ErrLimit, "/x/99997", "budget")
}

func TestUpdateNumericBoundaries(t *testing.T) {
	for _, c := range []struct {
		field string
		max   float64
	}{
		{"qualityDeferralDays", 30}, {"featureDeferralDays", 365}, {"qualityDeadlineDays", 30}, {"featureDeadlineDays", 30}, {"graceDays", 7},
	} {
		for _, n := range []float64{0, c.max, c.max + 1, -1, 0.5} {
			m := readFixture(t, "valid/mdm-os-update-windows-populated.json")
			item(m)["settings"].(map[string]any)[c.field] = n
			if n == 0 || n == c.max {
				accept(t, m)
			} else {
				checkError(t, m, ErrSchema, "/spec/items/0/settings/"+c.field, "schema")
			}
		}
	}
}

func TestNativeBoundaries(t *testing.T) {
	for _, ch := range []string{"a", "😀"} {
		for _, n := range []int{0, 1, 16384, 16385} {
			m := baseline("macos", "apple.declaration", map[string]any{"identifier": "io.test.item", "type": "com.apple.configuration", "payload": map[string]any{"text": strings.Repeat(ch, n)}})
			if ch == "😀" && n >= 16384 {
				checkError(t, m, ErrLimit, "/spec/items/0/settings", "bytes")
			} else if n == 16385 {
				checkError(t, m, ErrSchema, "/spec/items/0/settings/payload/text", "schema")
			} else {
				accept(t, m)
			}
		}
	}
	for _, n := range []int{0, 1, 256, 257} {
		array := []any{}
		object := map[string]any{}
		for i := range n {
			array = append(array, nil)
			object[fmt.Sprint(i)] = nil
		}
		for _, v := range []any{array, object} {
			m := baseline("macos", "apple.declaration", map[string]any{"identifier": "io.test.item", "type": "com.apple.configuration", "payload": map[string]any{"value": v}})
			if n <= 256 {
				accept(t, m)
			} else {
				checkError(t, m, ErrSchema, "/spec/items/0/settings/payload/value", "schema")
			}
		}
	}
	for _, n := range []float64{-9007199254740991, 9007199254740991, 0.5} {
		m := baseline("macos", "apple.declaration", map[string]any{"identifier": "io.test.item", "type": "com.apple.configuration", "payload": map[string]any{"value": n}})
		accept(t, m)
	}
}
func TestPreflightExactCaps(t *testing.T) {
	m := map[string]any{"x": strings.Repeat("a", 2097151)}
	if err := scan(m); err != nil {
		t.Fatal(err)
	}
	checkError(t, m, ErrLimit, "", "bytes")
	m["x"] = strings.Repeat("a", 2097152)
	checkError(t, m, ErrLimit, "/x", "budget")
	m = map[string]any{"x": make([]any, 99997)}
	if err := scan(m); err != nil {
		t.Fatal(err)
	}
	m["x"] = make([]any, 99998)
	checkError(t, m, ErrLimit, "/x/99997", "budget")
	// Traversal order controls preflight failures, before later invalid types.
	m = map[string]any{"a": strings.Repeat("a", 2097152), "z": int(1)}
	checkError(t, m, ErrLimit, "/a", "budget")
	m = map[string]any{"a": int(1), "z": strings.Repeat("a", 2097152)}
	checkError(t, m, ErrInput, "/a", "input")
}

// Input construction is outside the measurement. Key storage must not grow with
// the rejected object's size, including when the first value repeats the object.
func TestPreflightAllocationBound(t *testing.T) {
	m := map[string]any{"a": strings.Repeat("x", 2097153)}
	for i := 0; i < 100000; i++ {
		m[fmt.Sprintf("z%08d", i)] = nil
	}
	for _, cyclic := range []bool{false, true} {
		t.Run(fmt.Sprint(cyclic), func(t *testing.T) {
			path := "/a"
			if cyclic {
				m["a"] = m
				path = strings.Repeat("/a", 32)
			}
			// Warm stack growth before measuring heap allocations.
			checkError(t, m, ErrLimit, path, "budget")
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			checkError(t, m, ErrLimit, path, "budget")
			runtime.ReadMemStats(&after)
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("allocated %d bytes", allocated)
			if allocated > 131072 {
				t.Fatalf("allocated %d bytes, cap 131072", allocated)
			}
		})
	}
}

func TestCSPIntegerBoundaries(t *testing.T) {
	for _, scope := range []string{"Device", "User"} {
		for _, n := range []float64{-2147483649, -2147483648, 2147483647, 2147483648} {
			t.Run(fmt.Sprintf("%s/%.0f", scope, n), func(t *testing.T) {
				m := baseline("windows", "windows.csp", map[string]any{"locUri": "./" + scope + "/Vendor/MSFT/Test/Value", "format": "int", "value": n})
				if n == -2147483648 || n == 2147483647 {
					accept(t, m)
				} else {
					checkError(t, m, ErrSchema, "/spec/items/0/settings/value", "schema")
				}
			})
		}
	}
}

func TestPreflightKeyBatchOrder(t *testing.T) {
	for _, bad := range []int{0, 127, 128, 129, 299} {
		m := map[string]any{"": nil}
		for i := range 300 {
			m[fmt.Sprintf("k%03d", i)] = nil
		}
		key := fmt.Sprintf("k%03d", bad)
		m[key] = int(1)
		m["z"] = strings.Repeat("x", 2097153)
		checkError(t, m, ErrInput, "/"+key, "input")
	}
	m := map[string]any{}
	for i := range 50000 {
		m[fmt.Sprintf("k%05d", i)] = nil
	}
	checkError(t, m, ErrLimit, "/k49999", "budget")
}
