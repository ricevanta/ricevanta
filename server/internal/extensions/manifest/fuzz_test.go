package manifest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	m "github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func errorClass(t testing.TB, err error) string {
	t.Helper()
	if err == nil {
		return "ok"
	}
	found := ""
	for name, s := range sentinels() {
		if s != nil && errors.Is(err, s) {
			if found != "" {
				t.Fatal("multiple error sentinels")
			}
			found = name
		}
	}
	if found == "" {
		t.Fatalf("unlisted sentinel: %v", err)
	}
	return found
}
func reordered(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		out := make(map[string]any, len(x))
		for _, k := range keys {
			out[k] = reordered(x[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = reordered(v)
		}
		return out
	default:
		return v
	}
}
func invariants(t testing.TB, v any, o m.Options) {
	t.Helper()
	before, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	first := errorClass(t, m.Validate(v, o))
	if next := errorClass(t, m.Validate(v, o)); next != first {
		t.Fatalf("nondeterministic sentinel: %s / %s", first, next)
	}
	if next := errorClass(t, m.Validate(reordered(v), o)); next != first {
		t.Fatalf("map order changes sentinel: %s / %s", first, next)
	}
	after, e := json.Marshal(v)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("input changed")
	}
}
func TestFuzzInvariants(t *testing.T) {
	for _, c := range cases(t) {
		invariants(t, c.Manifest, m.Options{AllowReservedID: c.Options.Allow, MaxTotalFileBytes: c.Options.Max})
	}
	type object map[string]any
	type sequence []any
	type text string
	type boolean bool
	type numeric json.Number
	for _, v := range []any{nil, map[string]any(nil), []any(nil), int(1), int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1), uintptr(1), float32(1), float64(1), math.NaN(), math.Inf(1), math.Inf(-1), object{}, sequence{}, text("x"), boolean(true), numeric("1"), "\xff", json.Number("-0"), json.Number("01"), json.Number("1.0"), json.Number("1e0"), json.Number("+1"), json.Number(strings.Repeat("1", 1000000))} {
		check(t, v, m.Options{}, m.ErrTree)
		check(t, v, m.Options{}, m.ErrTree)
		check(t, v, m.Options{MaxTotalFileBytes: math.MaxUint64}, m.ErrOptions)
	}
	graph := map[string]any{}
	graph["self"] = graph
	expected := map[string]any{}
	expected["self"] = expected
	check(t, graph, m.Options{}, m.ErrTree)
	check(t, graph, m.Options{}, m.ErrTree)
	if !reflect.DeepEqual(graph, expected) {
		t.Fatal("map cycle changed")
	}
	cycle := make([]any, 1)
	cycle[0] = cycle
	expectedCycle := make([]any, 1)
	expectedCycle[0] = expectedCycle
	check(t, cycle, m.Options{}, m.ErrTree)
	check(t, cycle, m.Options{}, m.ErrTree)
	if !reflect.DeepEqual(cycle, expectedCycle) {
		t.Fatal("slice cycle changed")
	}
	v := base(t)
	v["metadata"].(map[string]any)["id"] = "io.ricevanta"
	v["unknown"] = true
	invariants(t, v, m.Options{})
	check(t, v, m.Options{}, m.ErrShape)
}
func TestFuzzConcurrentTrees(t *testing.T) {
	trees := make([]map[string]any, 8)
	for i := range trees {
		trees[i] = base(t)
	}
	var wg sync.WaitGroup
	for _, v := range trees {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				invariants(t, v, m.Options{})
			}
		}()
	}
	wg.Wait()
}
func FuzzValidate(f *testing.F) {
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/fixtures.json")
	if e != nil {
		f.Fatal(e)
	}
	var corpus struct{ Cases []corpusCase }
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&corpus); e != nil {
		f.Fatal(e)
	}
	for _, c := range corpus.Cases {
		seed, e := json.Marshal(c.Manifest)
		if e != nil {
			f.Fatal(e)
		}
		if len(seed) <= m.MaxManifestBytes {
			f.Add(seed, c.Options.Max, c.Options.Allow)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, max uint64, allow bool) {
		if len(data) > m.MaxManifestBytes {
			return
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		var v any
		if d.Decode(&v) != nil {
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return
		}
		invariants(t, v, m.Options{AllowReservedID: allow, MaxTotalFileBytes: max})
	})
}
