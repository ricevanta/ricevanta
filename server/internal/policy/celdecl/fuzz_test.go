package celdecl

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type fuzzSeed struct {
	data []byte
	want error
}

func fuzzSeeds(t testing.TB) []fuzzSeed {
	t.Helper()
	seeds := []fuzzSeed{
		{nil, ErrJSON}, {[]byte("!"), ErrJSON}, {[]byte{'"', 255, '"'}, ErrJSON},
		{[]byte(`"\ud800"`), ErrJSON}, {[]byte(`{"name":1,"na\u006de":2}`), ErrDuplicateKey},
		{bytes.Repeat([]byte("!"), MaxBytes+1), ErrSize},
		{[]byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)), ErrSize},
		{arrayTokens(32769), ErrSize},
		{[]byte(strings.Repeat("0 ", 32768)), ErrJSON},
		{[]byte(strings.Repeat("0 ", 32769)), ErrSize},
		{[]byte("0 " + strings.Repeat("[", 65) + "!"), ErrSize},
		{[]byte("0 !" + strings.Repeat("[", 65)), ErrJSON},
		{[]byte(`{"x":1,"x":2} !`), ErrJSON},
		{[]byte("-0 " + strings.Repeat("0 ", 32768)), ErrSize},
		{[]byte("0 " + string(arrayTokens(32769))), ErrSize},
	}
	for _, c := range fixtureCases(t) {
		b, err := os.ReadFile(assetDir + c.File)
		if err != nil {
			t.Fatal(err)
		}
		var want error
		if c.Error != nil {
			var ok bool
			want, ok = fixtureSentinels()[*c.Error]
			if !ok {
				t.Fatalf("unknown fixture error: %s", *c.Error)
			}
		}
		seeds = append(seeds, fuzzSeed{b, want})
	}
	return seeds
}

func seedExpectations(seeds []fuzzSeed) map[string]error {
	expected := make(map[string]error, len(seeds))
	for _, seed := range seeds {
		expected[string(seed.data)] = seed.want
	}
	return expected
}

func checkFuzzOutcome(t testing.TB, d *Document, err, want error, catalogue Catalogue) {
	t.Helper()
	if err != want {
		t.Fatalf("error %v, want %v", err, want)
	}
	if want != nil {
		if d != nil {
			t.Fatal("document on error")
		}
	} else if d == nil || !reflect.DeepEqual(d.Snapshot(), catalogue) {
		t.Fatal("successful catalogue differs")
	}
}

// Generate equivalent encodings from trusted fixture data, without using Parse.
func validEncoding(t testing.TB, catalogue Catalogue, entropy []byte) []byte {
	t.Helper()
	var selector byte
	for _, b := range entropy {
		selector ^= b
	}
	b, err := json.MarshalIndent(catalogue, "", strings.Repeat(" ", int(selector%4)))
	if err != nil {
		t.Fatal(err)
	}
	if selector&4 != 0 {
		b = bytes.ReplaceAll(b, []byte(`"device"`), []byte(`"devi\u0063e"`))
	}
	if selector&8 != 0 {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		b = reverseJSON(t, v)
	}
	return append(append([]byte(" \t\r\n"), b...), []byte("\n\r\t ")...)
}
func trustedExpectation(t testing.TB) Catalogue {
	t.Helper()
	var c Catalogue
	if err := json.Unmarshal(canonical(t), &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func FuzzParse(f *testing.F) {
	want := trustedExpectation(f)
	seeds := fuzzSeeds(f)
	expected := seedExpectations(seeds)
	for _, seed := range seeds {
		f.Add(seed.data)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Parse(b)
		if seedWant, known := expected[string(b)]; known {
			checkFuzzOutcome(t, d, err, seedWant, want)
		}
		generated := validEncoding(t, want, b)
		valid, validErr := Parse(generated)
		checkFuzzOutcome(t, valid, validErr, nil, want)
		if err != nil {
			if d != nil {
				t.Fatal("document on error")
			}
			return
		}
		if d == nil || !reflect.DeepEqual(d.Snapshot(), want) {
			t.Fatal("successful catalogue differs")
		}
		roundTrip, err := json.Marshal(d.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(roundTrip)
		if err != nil || parsed == nil || !reflect.DeepEqual(parsed.Snapshot(), want) {
			t.Fatalf("round trip: %v", err)
		}
	})
}

var fuzzReadCause = errors.New("fuzz reader cause")

type fuzzReader struct {
	data      []byte
	chunk     int
	failAt    int
	fail      bool
	total     int
	badBudget bool
}

func (r *fuzzReader) Read(p []byte) (int, error) {
	if r.total+len(p) > MaxBytes+1 {
		r.badBudget = true
	}
	if r.fail && r.total == r.failAt {
		return 0, fuzzReadCause
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	if r.fail && r.failAt >= r.total && len(p) > r.failAt-r.total {
		p = p[:r.failAt-r.total]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.total += n
	if r.fail && r.total == r.failAt {
		return n, fuzzReadCause
	}
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func FuzzLoad(f *testing.F) {
	want := trustedExpectation(f)
	seeds := fuzzSeeds(f)
	expected := seedExpectations(seeds)
	for _, seed := range seeds {
		f.Add(seed.data, uint16(1023), uint32(0), false)
	}
	for _, position := range []uint32{0, 1, uint32(len(canonical(f))), MaxBytes, MaxBytes + 1} {
		f.Add(bytes.Repeat([]byte(" "), MaxBytes+1), uint16(4095), position, true)
	}
	f.Fuzz(func(t *testing.T, b []byte, chunk uint16, position uint32, fail bool) {
		// Limit the failure position to one beyond the admitted read budget.
		at := int(position % uint32(MaxBytes+2))
		r := &fuzzReader{data: b, chunk: int(chunk%4096) + 1, failAt: at, fail: fail}
		d, err := Load(r)
		if r.total > MaxBytes+1 || r.badBudget {
			t.Fatal("read budget exceeded")
		}
		if err != nil && d != nil {
			t.Fatal("document on error")
		}
		switch {
		case len(b) > MaxBytes && (!fail || at > MaxBytes):
			if !errors.Is(err, ErrSize) || errors.Is(err, ErrRead) || r.total != MaxBytes+1 {
				t.Fatalf("size precedence: %v read %d", err, r.total)
			}
		case fail && at <= len(b):
			if !errors.Is(err, ErrRead) || !errors.Is(err, fuzzReadCause) || errors.Is(err, ErrSize) {
				t.Fatalf("read precedence: %v", err)
			}
		default:
			if seedWant, known := expected[string(b)]; known {
				checkFuzzOutcome(t, d, err, seedWant, want)
			}
			parsed, parseErr := Parse(b)
			if parseErr != err || (d == nil) != (parsed == nil) {
				t.Fatalf("clean reader differs: %v / %v", err, parseErr)
			}
			if d != nil && !reflect.DeepEqual(d.Snapshot(), want) {
				t.Fatal("clean catalogue differs")
			}
		}
		generated := validEncoding(t, want, b)
		clean := &fuzzReader{data: generated, chunk: int(chunk%4096) + 1}
		valid, validErr := Load(clean)
		checkFuzzOutcome(t, valid, validErr, nil, want)
		if clean.badBudget || clean.total != len(generated) {
			t.Fatal("generated read budget")
		}
	})
}
func TestConcurrentViews(t *testing.T) {
	d := document(t)
	want := trustedExpectation(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				c := d.Snapshot()
				c.Objects["device"].Fields["labels"].Type.Element.Kind = "int"
				c.Objects["certificate"].Fields["binding"].Values[0] = "bad"
				c.Domains["mdm"]["query"][0] = "bad"
				delete(c.Variables, "now")
				env, err := d.Environment("mdm", "query")
				if err != nil {
					t.Error(err)
					return
				}
				for i := range env {
					if env[i].Name == "rows" {
						env[i].Entry.Type.Element.Value.Kind = "int"
					}
					env[i].Name = "bad"
				}
				if !reflect.DeepEqual(d.Snapshot(), want) {
					t.Error("concurrent mutation reached document")
					return
				}
			}
		})
	}
	wg.Wait()
}
