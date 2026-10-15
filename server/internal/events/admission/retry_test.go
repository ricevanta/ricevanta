package admission

import (
	"context"
	"fmt"
	"math"
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
	// A NaN random value counts as 0.5; infinities clamp to the factor bounds.
	h.receive("c", batch.ClassRaw).Release()
	h.receive("d", batch.ClassRaw).Release()
	drain = 2 * C / 10
	for random, want := range map[float64]int{math.NaN(): 25, math.Inf(1): 30, math.Inf(-1): 20} {
		if got := unavailable(random, testBudget+25*drain); got != want {
			t.Fatalf("random %v: %d, want %d", random, got, want)
		}
	}
	// Ahead counts every waiter in both queues; each refusal stays in 5 through 60.
	for _, random := range []float64{0, 0.3, 0.5, 0.999, 1, math.NaN(), math.Inf(1), -2} {
		for _, weight := range []int64{-1 << 40, 0, 1, testBudget, 1 << 40} {
			if got := unavailable(random, weight); got < 5 || got > 60 {
				t.Fatalf("random %v weight %d: %d", random, weight, got)
			}
		}
	}
}

// In-flight refusals take Retry-After from the slot-release ring:
// base = ceil(100 / n) for n releases in the last ten seconds, 60 for none.
func TestInflightRetryAfter(t *testing.T) {
	h := newHarness(t)
	held := make([]*Ticket, 10)
	for i := range held {
		held[i] = h.receive(fmt.Sprintf("held%d", i), batch.ClassAudit)
	}
	refuse := func(random float64) int {
		t.Helper()
		h.random = random
		ticket, d, err := h.l.Receive("late", batch.ClassAudit)
		if err != nil || ticket != nil || d.Status != 503 || d.Reason != ReasonInflight {
			t.Fatalf("expected an in-flight refusal: %+v %v", d, err)
		}
		return d.RetryAfter
	}
	if got := refuse(0.5); got != 60 {
		t.Fatalf("no release: %d", got)
	}
	if got := refuse(0); got != 48 {
		t.Fatalf("no release, random 0: %d", got)
	}
	// One release per second for ten seconds: base 10.
	for i := range 10 {
		h.clock.Advance(time.Second)
		held[i].Release()
		held[i] = h.receive(fmt.Sprintf("next%d", i), batch.ClassAudit)
	}
	h.clock.Advance(500 * time.Millisecond)
	for random, want := range map[float64]int{0.5: 10, 0: 8, 1: 12} {
		if got := refuse(random); got != want {
			t.Fatalf("one release per second, random %v: %d, want %d", random, got, want)
		}
	}
	// 100 releases per second: base 1, clamped to 5.
	for second := range 10 {
		h.clock.Advance(time.Second)
		for i := range 100 {
			held[0].Release()
			held[0] = h.receive(fmt.Sprintf("churn%d-%d", second, i), batch.ClassAudit)
		}
	}
	if got := refuse(0.5); got != 5 {
		t.Fatalf("100 releases per second: %d", got)
	}
}

func TestEvery429Jitter(t *testing.T) {
	for _, r := range []float64{0, .5, 1} {
		h := newHarness(t)
		h.random = r
		h.receive("a", batch.ClassRaw)
		h.receive("a", batch.ClassRaw)
		_, d, _ := h.l.Receive("a", batch.ClassRaw)
		want := 5
		if r == 1 {
			want = 6
		}
		if d.RetryAfter != want {
			t.Fatalf("concurrency random=%g: %+v", r, d)
		}
		h.l.devices["a"].tokens = 0
		_, d, _ = h.l.Receive("a", batch.ClassRaw)
		if d.RetryAfter != want {
			t.Fatalf("concurrency deficit random=%g: %+v", r, d)
		}
		first := h.receive("b", batch.ClassRaw)
		h.admit(first, 64<<20, 64<<20)
		first.Release()
		h.clock.Advance(time.Duration(MinCharge)*time.Second/time.Duration(ServerRefill) + time.Nanosecond)
		next := h.receive("b", batch.ClassRaw)
		d, err := next.Decode(context.Background(), 64<<20, 64<<20)
		wants := map[float64]int{0: 13, .5: 16, 1: 19}
		if err != nil || d.RetryAfter != wants[r] {
			t.Fatalf("rate random=%g: %+v %v", r, d, err)
		}
	}
}

func TestSlotReleaseRetryThreeAndChurn(t *testing.T) {
	for _, n := range []int{3, 20} {
		h := newHarness(t)
		held := make([]*Ticket, 10)
		for i := range held {
			held[i] = h.receive(fmt.Sprint(i), batch.ClassAudit)
		}
		for i := range n {
			held[0].Release()
			held[0] = h.receive(fmt.Sprintf("churn%d", i), batch.ClassAudit)
		}
		want := []int{27, 34, 41}
		if n == 20 {
			want = []int{5, 5, 6}
		}
		for i, r := range []float64{0, .5, 1} {
			h.random = r
			_, d, err := h.l.Receive(fmt.Sprintf("late%d", i), batch.ClassAudit)
			if err != nil || d.Reason != ReasonInflight || d.RetryAfter != want[i] {
				t.Fatalf("n=%d random=%g: %+v %v", n, r, d, err)
			}
		}
	}
}

func TestReserveRetryUsesUsableBytesAndSlots(t *testing.T) {
	for _, r := range []float64{0, .5, 1} {
		h := newHarness(t)
		h.random = r
		ticket := h.receive("held", batch.ClassAudit)
		// Priority work has left only one usable byte above the nonpriority floor.
		ticket.charge = testBudget - h.l.reserve - 1 - C
		h.l.inUse = C + ticket.charge
		h.l.drain.add(0, 1_000_000) // 100,000 bytes per second.
		_, d, err := h.l.Receive("bytes", batch.ClassRaw)
		if err != nil || d.Reason != ReasonReserve || d.RetryAfter != map[float64]int{0: 40, .5: 50, 1: 60}[r] {
			t.Fatalf("byte reserve: %+v %v", d, err)
		}
		if h.tokens("bytes") != BucketCapacity-MinCharge {
			t.Fatal("receive refusal refunded minimum")
		}
		ticket.Release()
		h = newHarness(t)
		h.random = r
		for i := range 7 {
			h.receive(fmt.Sprint(i), batch.ClassRaw)
		}
		h.l.slotReleases.add(0, 3)
		_, d, err = h.l.Receive("slots", batch.ClassRaw)
		if err != nil || d.Reason != ReasonReserve || d.RetryAfter != map[float64]int{0: 27, .5: 34, 1: 41}[r] {
			t.Fatalf("slot reserve: %+v %v", d, err)
		}
		if h.tokens("slots") != BucketCapacity-MinCharge {
			t.Fatal("slot refusal refunded minimum")
		}
	}
}
