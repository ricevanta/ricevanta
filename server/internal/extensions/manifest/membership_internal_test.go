package manifest

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
	"unsafe"
)

func TestMembershipSort(t *testing.T) {
	cases := [][]string{nil, {}, {"a"}, {"a", "b", "c"}, {"c", "b", "a"}, {"a", "a", "a"}, {"a/b", "a", "a-b", "a/ba", "z", "é", "aa"}}
	for _, n := range []int{8, 9, 448, 449, 896, 897, 4096} {
		values := make([]string, n)
		for i := range values {
			values[i] = fmt.Sprintf("prefix/%04d", i)
		}
		cases = append(cases, slices.Clone(values))
		slices.Reverse(values)
		cases = append(cases, slices.Clone(values))
		rng := rand.New(rand.NewPCG(17, uint64(n)))
		rng.Shuffle(n, func(i, j int) { values[i], values[j] = values[j], values[i] })
		cases = append(cases, values)
	}
	for i, values := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			want := slices.Clone(values)
			slices.Sort(want)
			got := slices.Clone(values)
			sortStrings(got)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("sort/multiset mismatch: length %d", len(got))
			}
		})
	}
}

func TestMembershipSearch(t *testing.T) {
	for _, n := range []int{0, 1, 8, 9, 448, 449, 896, 897, 4096} {
		values := make([]string, n)
		for i := range values {
			values[i] = fmt.Sprintf("prefix/%04d", i*2)
		}
		before := slices.Clone(values)
		keys := []string{"", "prefix/0001", "zz"}
		if n > 0 {
			keys = append(keys, values[0], values[n/2], values[n-1])
		}
		for _, key := range keys {
			want, found := slices.BinarySearch(values, key)
			got, ok := findString(values, key)
			if got != want || ok != found {
				t.Fatalf("n=%d key=%q: %d/%t want %d/%t", n, key, got, ok, want, found)
			}
		}
		if !slices.Equal(values, before) {
			t.Fatal("search changed backing")
		}
	}
	values := []string{"a", "a", "a-b", "a/b", "a/ba", "z"}
	for _, key := range []string{"a", "a/", "a/b", "a/bb", "z", "zz"} {
		want, found := slices.BinarySearch(values, key)
		got, ok := findString(values, key)
		if got != want || ok != found {
			t.Fatalf("duplicate/prefix search %q: %d/%t want %d/%t", key, got, ok, want, found)
		}
	}
}

func TestMembershipHelpersNoAllocation(t *testing.T) {
	values := make([]string, 4096)
	for i := range values {
		values[i] = fmt.Sprintf("p%04d", i)
	}
	if got := testing.AllocsPerRun(20, func() {
		slices.Reverse(values)
		sortStrings(values)
		for _, key := range []string{"p0000", "p2048", "p4095", "missing"} {
			findString(values, key)
		}
	}); got != 0 {
		t.Fatalf("helper allocations: %g", got)
	}
}

// These independently calculated transitions check the audit arithmetic, not
// cold complete-loader allocations or allocator size classes.
func TestMembershipStorageArithmetic(t *testing.T) {
	if unsafe.Sizeof("") != 16 || unsafe.Sizeof([]string{}) != 24 || unsafe.Sizeof(byte(0)) != 1 {
		t.Fatal("audit requires 64-bit layouts")
	}
	for _, tc := range []struct{ n, slots, roundedUpper int }{
		{0, 0, 0}, {8, 128, 288}, {9, 144, 320}, {448, 7168, 14368}, {449, 7184, 14400},
		{896, 14336, 28704}, {897, 14352, 28736}, {2047, 32752, 65536}, {2048, 32768, 40960}, {4096, 65536, 73728},
	} {
		slots := int(unsafe.Sizeof("")) * tc.n
		upper := 0
		if tc.n != 0 {
			upper = 2*slots + 32
			if slots >= 32768 {
				upper = slots + 8192
			}
		}
		if slots != tc.slots || upper != tc.roundedUpper {
			t.Fatalf("n=%d: %d/%d", tc.n, slots, upper)
		}
	}
	// R(16K)+R(16M)+R(M)+3*R(24), K=64, M=4096.
	fixed := (32*64 + 32) + (16*4096 + 8192) + (2*4096 + 32) + 3*80
	if fixed != 84272 {
		t.Fatalf("separately rounded fixed bound: %d", fixed)
	}
	if 144*MaxTreeNodes+84272 != 9521456 {
		t.Fatal("spec aggregate bound changed")
	}
	if 2*(MaxTreeNodes+3) != 131078 {
		t.Fatal("object bound changed")
	}
}
