package yamltokens

import (
	"sync"
	"testing"
)

func TestDecodeAccounted(t *testing.T) {
	for _, input := range []string{"a: b", "", "\xff", "a: ! x", "a: [", "a: b\n...\n["} {
		t.Run(input, func(t *testing.T) {
			n, b, err := DecodeAccounted([]byte(input))
			if b == nil {
				t.Fatal("accounted decode lost ledger")
			}
			bytes, objects := b.Usage()
			if bytes == 0 || objects == 0 {
				t.Fatal("missing entry charges")
			}
			oldN, oldB, oldErr := Decode([]byte(input))
			if oldErr != err || (oldN == nil) != (n == nil) {
				t.Fatal("legacy result changed")
			}
			if err != nil && (n != nil || oldN != nil || oldB != nil) {
				t.Fatal("partial failure result")
			}
			_, next, _ := DecodeAccounted([]byte(input))
			if next == b {
				t.Fatal("shared ledger")
			}
		})
	}
	// Exercise existing private exhaustion injection at both passes; decodeBudget
	// intentionally keeps its legacy nil failure outputs.
	for _, family := range []string{"entry", "reader", "nodes", "content", "string"} {
		b := newBudget()
		b.failFamily = family
		n, returned, err := decodeBudget([]byte("a: b"), b)
		if err != ErrLimit || n != nil || returned != nil || !b.injected {
			t.Fatalf("%s: failure contract", family)
		}
		bytes, objects := b.Usage()
		if family != "entry" && (bytes == 0 || objects == 0) {
			t.Fatal("lost cumulative charges")
		}
	}
	var wg sync.WaitGroup
	ledgers := make(chan *Budget, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, b, e := DecodeAccounted([]byte("a: b"))
			if e != nil {
				t.Error(e)
			}
			ledgers <- b
		}()
	}
	wg.Wait()
	close(ledgers)
	seen := map[*Budget]bool{}
	for b := range ledgers {
		if seen[b] {
			t.Fatal("concurrent shared ledger")
		}
		seen[b] = true
	}
}

func TestBudgetUsage(t *testing.T) {
	b := newBudget()
	if x, y := b.Usage(); x != 0 || y != 0 {
		t.Fatal("nonzero fresh usage")
	}
	if err := b.Reserve(123, 4); err != nil {
		t.Fatal(err)
	}
	x, y := b.Usage()
	if err := b.Reserve(456, 7); err != nil {
		t.Fatal(err)
	}
	if x != 123 || y != 4 {
		t.Fatal("snapshot mutated")
	}
	for _, r := range [][2]uint64{{^uint64(0), 0}, {0, ^uint64(0)}, {64 << 20, 0}, {0, 1000000}} {
		if b.Reserve(r[0], r[1]) != ErrLimit {
			t.Fatal("reservation accepted")
		}
		if a, c := b.Usage(); a != 579 || c != 11 {
			t.Fatal("failed reservation changed counters")
		}
	}
	if n := testing.AllocsPerRun(100, func() { x, y = b.Usage() }); n != 0 {
		t.Fatal("Usage allocates")
	}
	if x != 579 || y != 11 {
		t.Fatal("incorrect usage")
	}
}
