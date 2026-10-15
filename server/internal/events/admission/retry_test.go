package admission

import (
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

func TestRetryAfterBounds(t *testing.T) {
	h := newHarness(t)
	unavailable := func(random float64, weight int64) int {
		t.Helper()
		h.random = random
		d := h.l.Unavailable(ReasonStorageTimeout, weight)
		if d.Status != 503 || d.Reason != ReasonStorageTimeout || d.Finding != "" {
			t.Fatalf("Unavailable: %+v", d)
		}
		return d.RetryAfter
	}
	// No release in the last ten seconds: drain 0 gives a base of 60, jittered and clamped.
	for random, want := range map[float64]int{0: 48, 0.5: 60, 1: 60} {
		if got := unavailable(random, 1); got != want {
			t.Fatalf("zero drain, random %v: %d, want %d", random, got, want)
		}
	}
	// One receive-only release: drain = C / 10 bytes per second.
	h.receive("a", batch.ClassRaw).Release()
	drain := C / 10
	for _, c := range []struct {
		base   int64
		random float64
		want   int
	}{
		{1, 0.5, 5}, {1, 0, 5}, {1, 1, 6},
		{100, 0.5, 60}, {100, 0, 48}, {100, 1, 60},
		{25, 0, 20}, {25, 0.25, 23}, {25, 0.5, 25}, {25, 1, 30},
		{13, 1, 16}, {11, 0, 9}, {60, 1, 60}, {6, 0, 5},
	} {
		weight := testBudget + c.base*drain
		if c.base == 1 {
			weight = testBudget + 1
		}
		if got := unavailable(c.random, weight); got != c.want {
			t.Fatalf("base %d, random %v: %d, want %d", c.base, c.random, got, c.want)
		}
	}
	if got := unavailable(0.5, 0); got != 5 {
		t.Fatalf("fitting weight: %d", got)
	}
	// Ten one-second counters: a release counts for ten seconds, then drops out.
	h.clock.Advance(4 * time.Second)
	h.receive("b", batch.ClassRaw).Release()
	if got := unavailable(0.5, testBudget+20*2*drain); got != 20 {
		t.Fatalf("two releases: %d", got)
	}
	h.clock.Advance(5*time.Second + 999*time.Millisecond)
	if got := unavailable(0.5, testBudget+20*2*drain); got != 20 {
		t.Fatalf("both releases within ten seconds: %d", got)
	}
	h.clock.Advance(time.Millisecond)
	if got := unavailable(0.5, testBudget+20*drain); got != 20 {
		t.Fatalf("first release expired: %d", got)
	}
	h.clock.Advance(4 * time.Second)
	if got := unavailable(0.5, testBudget+20*drain); got != 60 {
		t.Fatalf("all releases expired: %d", got)
	}
	// Ahead counts every waiter in both queues; each refusal stays in 5 through 60.
	for _, random := range []float64{0, 0.3, 0.5, 0.999, 1} {
		for _, weight := range []int64{-1 << 40, 0, 1, testBudget, 1 << 40} {
			if got := unavailable(random, weight); got < 5 || got > 60 {
				t.Fatalf("random %v weight %d: %d", random, weight, got)
			}
		}
	}
}
