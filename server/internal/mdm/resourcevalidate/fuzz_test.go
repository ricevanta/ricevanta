package resourcevalidate

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzValidate(f *testing.F) {
	for _, r := range fixtureRecords(f) {
		b, err := os.ReadFile(filepath.Join(fixtureDir(), r.File))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, b := range [][]byte{nil, []byte("!"), []byte(`{"a":null}`), []byte(`{"x":"\ud800"}`)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return
		}
		before := clone(t, m)
		r, err := Validate(m)
		r2, err2 := Validate(m)
		if !reflect.DeepEqual(m, before) || !reflect.DeepEqual(r, r2) {
			t.Fatal("mutation or nonrepeatable result")
		}
		var e, e2 *Error
		if errors.As(err, &e) != errors.As(err2, &e2) || !reflect.DeepEqual(e, e2) {
			t.Fatal("nonrepeatable error")
		}
		if err != nil {
			if !reflect.DeepEqual(r, Result{}) {
				t.Fatal("result on failure")
			}
		} else if !reflect.DeepEqual(r, expectedResult(m)) {
			t.Fatal("classification")
		}
	})
}
func FuzzBudget(f *testing.F) {
	for _, b := range [][]byte{
		nil, {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7},
		append([]byte{5}, make([]byte, 31)...),
		append([]byte{5}, make([]byte, 32)...),
		{0, 255}, {7, 255},
		append([]byte{5}, append(make([]byte, 30), 255)...),
		append([]byte{5}, append(make([]byte, 31), 255)...),
		[]byte("é\n\"\\😀"),
	} {
		f.Add(b)
	}
	for _, r := range fixtureRecords(f) {
		b, err := os.ReadFile(filepath.Join(fixtureDir(), r.File))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append([]byte{0}, b...))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var selector byte
		if len(b) > 0 {
			selector = b[0]
			b = b[1:]
		}
		if len(b) > 4096 {
			b = b[:4096]
		}
		m := map[string]any{"a": string(b)}
		switch selector % 8 {
		case 1:
			m["a"] = math.NaN()
		case 2:
			m["a"] = int(1)
		case 3:
			m["a"] = m
		case 4:
			a := make([]any, 1)
			a[0] = a
			m["a"] = a
		case 5:
			for i := range min(len(b), 34) {
				m = map[string]any{"a": m}
				_ = i
			}
		case 6:
			m["a"] = []any(nil)
		case 7:
			m["a"] = []any{nil, true, false, float64(1.5), string(b)}
		}
		// Expectations come from the generated case, never from the scanner.
		path, rule := "/a", "input"
		cause := ErrInput
		switch selector % 8 {
		case 3:
			cause, path, rule = ErrLimit, strings.Repeat("/a", 32), "budget"
		case 4:
			cause, path, rule = ErrLimit, "/a"+strings.Repeat("/0", 31), "budget"
		case 5:
			wrappers := min(len(b), 34)
			if wrappers >= 32 {
				cause, path, rule = ErrLimit, strings.Repeat("/a", 32), "budget"
			} else if !utf8.Valid(b) {
				path = strings.Repeat("/a", wrappers+1)
			} else {
				cause = nil
			}
		case 0, 7:
			if utf8.Valid(b) {
				cause = nil
			}
			if selector%8 == 7 {
				path = "/a/4"
			}
		}
		if cause != nil {
			checkError(t, m, cause, path, rule)
			return
		}
		if err := scan(m); err != nil {
			t.Fatalf("valid preflight: %v", err)
		}
		if got, want := charge(m), chargeOracle(t, m); got != want {
			t.Fatalf("charge %d want %d", got, want)
		}
	})
}
