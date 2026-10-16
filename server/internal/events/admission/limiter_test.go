package admission

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

// fakeClock fires timers only when the test advances it. Its times are
// base.Add(d) from one time.Now() base, so each carries a monotonic reading.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	hold   bool // the next timer never fires on its own
}

type fakeTimer struct {
	clock *fakeClock
	at    time.Time
	ch    chan time.Time
	fired bool
}

func newFakeClock() *fakeClock { return newFakeClockAt(time.Now()) }

func newFakeClockAt(base time.Time) *fakeClock { return &fakeClock{now: base} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if c.hold {
		c.hold = false
		t.at = c.now.Add(1 << 62)
	}
	c.timers = append(c.timers, t)
	return t
}

func (c *fakeClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

func (c *fakeClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.now) {
		panic("fake clock moved backwards")
	}
	c.now = now
	kept := c.timers[:0]
	for _, t := range c.timers {
		if !t.at.After(now) {
			t.fired = true
			t.ch <- now
			continue
		}
		kept = append(kept, t)
	}
	c.timers = kept
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.fired {
		return false
	}
	for i, x := range t.clock.timers {
		if x == t {
			t.clock.timers = append(t.clock.timers[:i], t.clock.timers[i+1:]...)
			break
		}
	}
	t.fired = true
	return true
}

const (
	testBudget  int64 = 256 * mib
	testReserve       = testBudget / 4
	C                 = CompressedWeight
)

type harness struct {
	t      *testing.T
	l      *Limiter
	clock  *fakeClock
	random float64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessConfig(t, Config{MemoryLimit: 1 << 30, AgentOnly: true, Budget: testBudget, MaxInflight: 10, DecodeWait: 2 * time.Second})
}

func newHarnessConfig(t *testing.T, c Config) *harness {
	t.Helper()
	h := &harness{t: t, clock: newFakeClock(), random: 0.5}
	l, err := New(c, h.clock, func() float64 { return h.random })
	if err != nil {
		t.Fatal(err)
	}
	h.l = l
	return h
}

func (h *harness) receive(device string, class batch.SpoolClass) *Ticket {
	h.t.Helper()
	ticket, d, err := h.l.Receive(device, class)
	if err != nil || ticket == nil || d != (Decision{}) {
		h.t.Fatalf("Receive(%s): %+v, %v", device, d, err)
	}
	return ticket
}

func (h *harness) admit(ticket *Ticket, window, size uint64) {
	h.t.Helper()
	d, err := ticket.Decode(context.Background(), window, size)
	if err != nil || d.Status != 0 || d.Reason != "" {
		h.t.Fatalf("Decode(%d, %d): %+v, %v", window, size, d, err)
	}
}

type decodeResult struct {
	d   Decision
	err error
}

// decodeAsync starts a Decode and returns once it has either finished or
// joined a queue, observed through the ticket's state under the limiter lock.
func (h *harness) decodeAsync(ctx context.Context, ticket *Ticket, window, size uint64) <-chan decodeResult {
	h.t.Helper()
	out := make(chan decodeResult, 1)
	before := h.l.Snapshot().Waiting
	go func() {
		d, err := ticket.Decode(ctx, window, size)
		out <- decodeResult{d, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if len(out) > 0 || h.l.Snapshot().Waiting > before {
			return out
		}
		if time.Now().After(deadline) {
			h.t.Fatal("decode neither finished nor waited")
		}
		runtime.Gosched()
	}
}

func (h *harness) result(ch <-chan decodeResult) decodeResult {
	h.t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		h.t.Fatal("decode did not finish")
	}
	return decodeResult{}
}

func pending(ch <-chan decodeResult) bool { return len(ch) == 0 }

func (h *harness) inUse() int64 {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	return h.l.inUse
}

func (h *harness) tokens(device string) uint64 {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	e := h.l.devices[device]
	if e == nil {
		return BucketCapacity
	}
	e.refill(h.clock.Now())
	return e.tokens
}

// capacity is BucketCapacity as a variable, so tests also compile against
// mutated capacities.
var capacity = BucketCapacity

func charge(window, size uint64) int64 {
	w, err := Weight(window, size)
	if err != nil {
		panic(err)
	}
	return w - C
}

func expectRetry(numerator, drain int64, random float64) int {
	base := 60
	if drain > 0 {
		base = int(min(max((numerator+drain-1)/drain, 5), 60))
		if numerator <= 0 {
			base = 5
		}
	}
	return int(min(max(math.Floor(float64(base)*(0.8+0.4*random)+0.5), 5), 60))
}

func TestReceiveRefusals(t *testing.T) {
	h := newHarness(t)
	if _, _, err := h.l.Receive("", batch.ClassRaw); !errors.Is(err, ErrDevice) {
		t.Fatalf("empty device: %v", err)
	}
	if _, _, err := h.l.Receive("x", batch.SpoolClass(0)); !errors.Is(err, ErrArgument) {
		t.Fatalf("unknown class: %v", err)
	}
	// Slots first: a third upload is refused for concurrency and charged MinCharge.
	a, b := h.receive("d1", batch.ClassRaw), h.receive("d1", batch.ClassFindings)
	if h.tokens("d1") != BucketCapacity-2*MinCharge {
		t.Fatalf("admission charge: %d", h.tokens("d1"))
	}
	ticket, d, err := h.l.Receive("d1", batch.ClassAudit)
	if err != nil || ticket != nil || d != (Decision{Status: 429, RetryAfter: 5, Reason: ReasonDeviceConcurrency}) {
		t.Fatalf("third upload: %v %+v %v", ticket, d, err)
	}
	s := h.l.Snapshot()
	if s.Inflight != 2 || s.InUse != 2*C || h.l.devices["d1"].slots != 2 || s.Refused[ReasonDeviceConcurrency] != 1 || len(s.Refused) != 1 || h.tokens("d1") != BucketCapacity-3*MinCharge {
		t.Fatalf("concurrency refusal: %+v, tokens %d", s, h.tokens("d1"))
	}
	// Both slots held and an empty bucket: still a concurrency refusal, charging nothing.
	h.l.mu.Lock()
	h.l.devices["d1"].tokens = MinCharge - 1
	h.l.mu.Unlock()
	if _, d, _ := h.l.Receive("d1", batch.ClassRaw); d.Reason != ReasonDeviceConcurrency || h.tokens("d1") != MinCharge-1 {
		t.Fatalf("concurrency before bucket: %+v, tokens %d", d, h.tokens("d1"))
	}
	// A free slot and a bucket below MinCharge: device_rate, charging nothing.
	a.Release()
	ticket, d, err = h.l.Receive("d1", batch.ClassRaw)
	if err != nil || ticket != nil || d != (Decision{Status: 429, RetryAfter: 5, Reason: ReasonDeviceRate}) || h.tokens("d1") != MinCharge-1 {
		t.Fatalf("bucket refusal: %+v %v, tokens %d", d, err, h.tokens("d1"))
	}
	if h.l.devices["d1"].slots != 1 || h.l.Snapshot().Inflight != 1 {
		t.Fatal("bucket refusal took a slot")
	}
	b.Release()

	// In-flight capacity last, after MinCharge; Retry-After follows slot releases:
	// two releases in the last ten seconds give ceil(100 / 2) = 50.
	for i := range 10 {
		h.receive(fmt.Sprintf("n%d", i), batch.ClassAudit)
	}
	ticket, d, err = h.l.Receive("n10", batch.ClassRaw)
	if err != nil || ticket != nil || d != (Decision{Status: 503, RetryAfter: 50, Reason: ReasonInflight}) {
		t.Fatalf("eleventh request: %+v %v", d, err)
	}
	if s := h.l.Snapshot(); s.Inflight != 10 || s.Refused[ReasonInflight] != 1 || h.l.devices["n10"].slots != 0 || h.tokens("n10") != BucketCapacity-MinCharge {
		t.Fatalf("in-flight refusal: %+v, tokens %d", s, h.tokens("n10"))
	}
	h.clock.Advance(10 * time.Second)
	if _, d, _ := h.l.Receive("n11", batch.ClassRaw); d.RetryAfter != 60 {
		t.Fatalf("no release in ten seconds: %+v", d)
	}
}

func TestDecodeBudgetAndReserve(t *testing.T) {
	h := newHarness(t)
	t1, t2, t3 := h.receive("a", batch.ClassRaw), h.receive("b", batch.ClassRaw), h.receive("c", batch.ClassRaw)
	h.admit(t1, 64*mib, 64*mib)
	h.admit(t2, 4*mib, 4*mib)
	if avail := testBudget - h.inUse(); avail-charge(4*mib, 4*mib) >= testReserve || avail < charge(4*mib, 4*mib) {
		t.Fatalf("setup: available %d", avail)
	}
	w3 := h.decodeAsync(context.Background(), t3, 4*mib, 4*mib)
	if !pending(w3) {
		t.Fatal("raw decode inside the reserve was admitted")
	}
	t4 := h.receive("d", batch.ClassFindings)
	h.admit(t4, 4*mib, 4*mib)
	if !pending(w3) {
		t.Fatal("raw waiter admitted by a findings admission")
	}
	t1.Release()
	if r := h.result(w3); r.err != nil || r.d != (Decision{}) {
		t.Fatalf("waiter after release: %+v", r)
	}
	if h.l.Snapshot().Waiting != 0 {
		t.Fatal("waiter still queued")
	}

	// A raw waiter that fits the whole budget but not above the reserve.
	t5 := h.receive("e", batch.ClassRaw)
	before := h.inUse()
	w5 := h.decodeAsync(context.Background(), t5, 64*mib, 64*mib)
	if !pending(w5) || h.inUse() != before {
		t.Fatal("reserve waiter admitted or charged")
	}
	h.clock.Advance(2*time.Second - 1)
	if !pending(w5) {
		t.Fatal("wait ended before DecodeWait")
	}
	h.clock.Advance(1)
	r := h.result(w5)
	if r.err != nil || r.d.Status != 503 || r.d.Reason != ReasonReserve || r.d.RetryAfter < 5 || r.d.RetryAfter > 60 {
		t.Fatalf("reserve refusal: %+v", r)
	}
	if h.inUse() != before {
		t.Fatal("refused ticket left the receive phase")
	}
	t5.Release()
	if h.inUse() != before-C {
		t.Fatal("refused ticket released more than its receive charge")
	}

	// A findings waiter that does not fit the whole budget.
	t6 := h.receive("f", batch.ClassFindings)
	h.admit(t6, 64*mib, 64*mib)
	t7 := h.receive("g", batch.ClassFindings)
	w7 := h.decodeAsync(context.Background(), t7, 4*mib, 4*mib)
	if !pending(w7) {
		t.Fatal("findings decode above the budget admitted")
	}
	h.clock.Advance(2 * time.Second)
	if r := h.result(w7); r.err != nil || r.d.Status != 503 || r.d.Reason != ReasonBudget {
		t.Fatalf("budget refusal: %+v", r)
	}
	if s := h.l.Snapshot(); s.Refused[ReasonReserve] != 1 || s.Refused[ReasonBudget] != 1 {
		t.Fatalf("refusal counts %+v", s.Refused)
	}
}

func TestQueueOrder(t *testing.T) {
	x := charge(4*mib, 4*mib)
	if c := charge(24*mib, 24*mib); c != 68_157_440 {
		t.Fatalf("24 MiB charge %d", c)
	}

	// A large findings head that does not fit, and a small raw waiter that does.
	h := newHarness(t)
	g1, g2 := h.receive("g1", batch.ClassRaw), h.receive("g2", batch.ClassFindings)
	f, r := h.receive("f", batch.ClassFindings), h.receive("r", batch.ClassRaw)
	h.admit(g1, 64*mib, 64*mib)
	h.admit(g2, 4*mib, 4*mib)
	wf := h.decodeAsync(context.Background(), f, 64*mib, 64*mib)
	wr := h.decodeAsync(context.Background(), r, 4*mib, 4*mib)
	if !pending(wf) || !pending(wr) {
		t.Fatal("setup admitted a waiter")
	}
	g2.Release()
	if res := h.result(wr); res.d != (Decision{}) || res.err != nil {
		t.Fatalf("raw waiter: %+v", res)
	}
	if !pending(wf) || h.l.Snapshot().Waiting != 1 {
		t.Fatal("findings head admitted without fitting")
	}
	h.clock.Advance(2 * time.Second)
	h.result(wf)

	// A fitting second waiter never overtakes a non-fitting first in its queue.
	h = newHarness(t)
	g1, g2 = h.receive("g1", batch.ClassFindings), h.receive("g2", batch.ClassFindings)
	r1, r2 := h.receive("r1", batch.ClassRaw), h.receive("r2", batch.ClassRaw)
	h.admit(g1, 64*mib, 64*mib)
	h.admit(g2, 4*mib, 4*mib)
	w1 := h.decodeAsync(context.Background(), r1, 64*mib, 64*mib)
	w2 := h.decodeAsync(context.Background(), r2, 4*mib, 4*mib)
	g2.Release()
	if avail := testBudget - h.inUse(); avail-x < testReserve {
		t.Fatalf("second waiter would not fit alone: %d", avail)
	}
	if !pending(w1) || !pending(w2) || h.l.Snapshot().Waiting != 2 {
		t.Fatal("second waiter overtook the head")
	}
	g1.Release()
	if a, b := h.result(w1), h.result(w2); a.d.Status != 0 || a.err != nil || b.d != (Decision{}) || b.err != nil {
		t.Fatalf("after a large release: %+v %+v", a, b)
	}

	// Priority heads are examined first: the release fits either waiter but not both.
	h = newHarness(t)
	g1, g2 = h.receive("g1", batch.ClassRaw), h.receive("g2", batch.ClassFindings)
	f, r = h.receive("f", batch.ClassFindings), h.receive("r", batch.ClassRaw)
	h.admit(g1, 64*mib, 64*mib)
	h.admit(g2, 24*mib, 24*mib)
	wr = h.decodeAsync(context.Background(), r, 4*mib, 4*mib)
	wf = h.decodeAsync(context.Background(), f, 4*mib, 4*mib)
	if !pending(wr) || !pending(wf) {
		t.Fatal("setup admitted a waiter")
	}
	g2.Release()
	if avail := testBudget - h.inUse() + x; avail < testReserve+x || avail >= testReserve+2*x {
		t.Fatalf("release does not discriminate order: available %d", avail)
	}
	if res := h.result(wf); res.d != (Decision{}) {
		t.Fatalf("findings waiter: %+v", res)
	}
	if !pending(wr) {
		t.Fatal("raw head admitted before the findings head")
	}
	h.clock.Advance(2 * time.Second)
	if res := h.result(wr); res.d.Reason != ReasonReserve {
		t.Fatalf("raw waiter: %+v", res)
	}

	// A waiter that times out behind a larger head was held back by that head,
	// not by the reserve: its refusal is budget.
	h = newHarness(t)
	g1, g2 = h.receive("g1", batch.ClassFindings), h.receive("g2", batch.ClassFindings)
	r1, r2 = h.receive("r1", batch.ClassRaw), h.receive("r2", batch.ClassRaw)
	h.admit(g1, 64*mib, 64*mib)
	h.admit(g2, 4*mib, 4*mib)
	ctx, cancel := context.WithCancel(context.Background())
	h.clock.mu.Lock()
	h.clock.hold = true // the head's timer never fires
	h.clock.mu.Unlock()
	w1 = h.decodeAsync(ctx, r1, 64*mib, 64*mib)
	w2 = h.decodeAsync(context.Background(), r2, 4*mib, 4*mib)
	if avail := testBudget - h.inUse(); avail < x || avail-x >= testReserve {
		t.Fatalf("setup: available %d", avail)
	}
	h.clock.Advance(2 * time.Second)
	if res := h.result(w2); res.d.Status != 503 || res.d.Reason != ReasonBudget {
		t.Fatalf("waiter behind a larger head: %+v", res)
	}
	cancel()
	if res := h.result(w1); !errors.Is(res.err, context.Canceled) {
		t.Fatalf("head: %+v", res)
	}
}

func TestDeviceBucket(t *testing.T) {
	h := newHarness(t)
	tk := h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 64*mib)
	tk.Release()
	if h.tokens("x") != 0 {
		t.Fatalf("64 MiB request left %d", h.tokens("x"))
	}
	ticket, d, err := h.l.Receive("x", batch.ClassRaw)
	if err != nil || ticket != nil || d != (Decision{Status: 429, RetryAfter: 5, Reason: ReasonDeviceRate}) || h.tokens("x") != 0 {
		t.Fatalf("receive with an empty bucket: %+v %v", d, err)
	}
	h.clock.Advance(2 * time.Second)
	if got := h.tokens("x"); got != 2*ServerRefill || got < 8*mib+mib/8 {
		t.Fatalf("refill after 2 s: %d", got)
	}
	tk = h.receive("x", batch.ClassRaw)
	before := h.inUse()
	d, err = tk.Decode(context.Background(), 4*mib, 64*mib)
	// Deficit 64 MiB - MinCharge - (2 s of refill - MinCharge) = 58,589,184 bytes.
	if err != nil || d != (Decision{Status: 429, RetryAfter: 14, Reason: ReasonDeviceRate}) {
		t.Fatalf("second 64 MiB: %+v %v", d, err)
	}
	if h.tokens("x") != 2*ServerRefill-MinCharge || h.inUse() != before {
		t.Fatal("refusal charged the bucket or the budget")
	}
	if _, err := tk.Decode(context.Background(), 0, 0); !errors.Is(err, ErrState) {
		t.Fatalf("Decode after a refusal: %v", err)
	}
	tk.Release()
	tk = h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 4*mib)
	tk.Release()
	if got := h.tokens("x"); got != 2*ServerRefill-MinCharge-4*mib {
		t.Fatalf("4 MiB request charged %d", 2*ServerRefill-MinCharge-got)
	}
	h.clock.Advance(15 * time.Second)
	tk = h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 64*mib)
	tk.Release()

	// Charged on the call, before waiting; never refunded.
	f1, f2 := h.receive("f1", batch.ClassFindings), h.receive("f2", batch.ClassFindings)
	h.clock.Advance(20 * time.Second)
	y1, y2 := h.receive("y", batch.ClassRaw), h.receive("y", batch.ClassRaw)
	h.admit(f1, 64*mib, 64*mib)
	h.admit(f2, 24*mib, 24*mib)
	wy := h.decodeAsync(context.Background(), y1, 4*mib, 32*mib)
	if !pending(wy) || h.tokens("y") != capacity-2*MinCharge-(32*mib-MinCharge) {
		t.Fatalf("bucket not charged before waiting: %d", h.tokens("y"))
	}
	h.clock.Advance(2 * time.Second)
	if r := h.result(wy); r.d.Status != 503 {
		t.Fatalf("expected a budget refusal: %+v", r)
	}
	after := capacity - 2*MinCharge - (32*mib - MinCharge) + 2*ServerRefill
	if got := h.tokens("y"); got != after {
		t.Fatalf("bucket refunded after timeout: %d, want %d", got, after)
	}
	ctx, cancel := context.WithCancel(context.Background())
	wy = h.decodeAsync(ctx, y2, 0, 4*mib)
	if !pending(wy) || h.tokens("y") != after-(4*mib-MinCharge) {
		t.Fatal("second waiter not charged")
	}
	cancel()
	if r := h.result(wy); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("canceled waiter: %+v", r)
	}
	if h.tokens("y") != after-(4*mib-MinCharge) {
		t.Fatal("bucket refunded after cancellation")
	}
}

func TestMinimumCharge(t *testing.T) {
	h := newHarness(t)
	tk := h.receive("m", batch.ClassRaw)
	if h.tokens("m") != BucketCapacity-MinCharge {
		t.Fatal("Receive did not charge MinCharge")
	}
	h.admit(tk, 0, 100)
	tk.Release()
	if h.tokens("m") != BucketCapacity-MinCharge {
		t.Fatal("a decode below MinCharge charged more")
	}
	tk = h.receive("m", batch.ClassRaw)
	h.admit(tk, 0, MinCharge+5)
	tk.Release()
	if h.tokens("m") != BucketCapacity-2*MinCharge-5 {
		t.Fatalf("a decode above MinCharge: %d", h.tokens("m"))
	}
	h.receive("m", batch.ClassRaw).Release()
	if h.tokens("m") != BucketCapacity-3*MinCharge-5 {
		t.Fatal("MinCharge refunded on release without decoding")
	}
	for i := range 10 {
		h.receive(fmt.Sprintf("n%d", i), batch.ClassAudit)
	}
	if _, d, _ := h.l.Receive("m", batch.ClassRaw); d.Reason != ReasonInflight || h.tokens("m") != BucketCapacity-4*MinCharge-5 {
		t.Fatalf("in-flight refusal: %+v, tokens %d", d, h.tokens("m"))
	}

	// One-line batches as fast as two slots allow: a burst of 512, then 32.5 per second.
	h = newHarnessConfig(t, Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second})
	request := func() bool {
		tk, d, err := h.l.Receive("fast", batch.ClassRaw)
		if err != nil || tk == nil && d.Reason != ReasonDeviceRate {
			t.Fatalf("%+v %v", d, err)
		}
		if tk == nil {
			return false
		}
		h.admit(tk, 0, 103)
		tk.Release()
		return true
	}
	burst := 0
	for request() {
		burst++
	}
	if burst != int(BucketCapacity/MinCharge) {
		t.Fatalf("burst of %d requests", burst)
	}
	admitted := 0
	for range 10_000 {
		h.clock.Advance(time.Millisecond)
		for request() {
			admitted++
		}
	}
	if want := int(10 * ServerRefill / MinCharge); admitted != want {
		t.Fatalf("%d requests in 10 s, want %d", admitted, want)
	}
}

// simEvent drives TestAgentConformance in server time.
type simEvent struct {
	at   time.Duration
	seq  int
	kind int
	req  *simRequest
}

type simRequest struct {
	ticket       *Ticket
	window, size uint64
	abandoned    bool
}

type simQueue []*simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	return q[i].at < q[j].at || q[i].at == q[j].at && q[i].seq < q[j].seq
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(*simEvent)) }
func (q *simQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	*q = old[:len(old)-1]
	return x
}

// TestAgentConformance drives a simulated unmodified agent: a bucket of 4 MiB/s
// and 8 MiB burst on a clock 500 ppm fast against the server's, charging
// max(window, size, MinCharge) for every request it sends, retries included, at most two
// in flight. No phase may meet a device_rate refusal or a Finding.
func TestAgentConformance(t *testing.T) {
	const (
		agentBurst = float64(8 * mib)
		agentRate  = float64(AgentRate) * (1 + 500e-6)
	)
	config := Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second}
	agentCharge := func(size uint64) float64 { return float64(max(size, MinCharge)) }
	type phase struct {
		h        *harness
		start    time.Time
		minimum  uint64
		requests int
	}
	newPhase := func() *phase {
		h := newHarnessConfig(t, config)
		return &phase{h: h, start: h.clock.Now(), minimum: BucketCapacity}
	}
	// serve receives, decodes and releases one request at the current time.
	serve := func(p *phase, window, size uint64) {
		t.Helper()
		ticket, d, err := p.h.l.Receive("agent", batch.ClassRaw)
		if err != nil || ticket == nil {
			t.Fatalf("request %d refused at receive: %+v %v", p.requests, d, err)
		}
		d, err = ticket.Decode(context.Background(), window, size)
		if err != nil || d != (Decision{}) {
			t.Fatalf("request %d refused or flagged at decode: %+v %v", p.requests, d, err)
		}
		p.minimum = min(p.minimum, p.h.tokens("agent"))
		ticket.Release()
		p.requests++
	}
	// stream sends batches of size back to back at the agent's full rate.
	stream := func(p *phase, size uint64, tokens float64, duration time.Duration) float64 {
		end := p.h.clock.Now().Add(duration)
		for p.h.clock.Now().Before(end) {
			if need := agentCharge(size) - tokens; need > 0 {
				wait := time.Duration(math.Ceil(need / agentRate * 1e9))
				p.h.clock.Advance(wait)
				tokens = min(agentBurst, tokens+agentRate*wait.Seconds())
			}
			tokens -= agentCharge(size)
			serve(p, size, size)
		}
		return tokens
	}
	assertClean := func(name string, p *phase) {
		t.Helper()
		s := p.h.l.Snapshot()
		if s.Refused[ReasonDeviceRate] != 0 || s.Findings != 0 || p.h.l.devices["agent"].counters(p.h.l.minute(p.h.clock.Now()), counterRate) != 0 {
			t.Fatalf("%s: %+v", name, s)
		}
		t.Logf("%s: %d requests over %s, lowest bucket %d bytes (drawdown %.2f MiB)", name, p.requests, p.h.clock.Now().Sub(p.start), p.minimum, float64(BucketCapacity-p.minimum)/mib)
	}

	// Sustained full-rate drain of 4 MiB batches for two hours, from an empty agent bucket.
	p := newPhase()
	stream(p, SealingLimit, 0, 2*time.Hour)
	assertClean("sustained 4 MiB", p)

	// The agent's smallest real batches, one record each, at its full rate.
	p = newPhase()
	stream(p, 103, 0, 10*time.Minute)
	assertClean("sustained one-record", p)

	// Worst-case bunching: from a full agent bucket, two requests abandoned and
	// two in flight, all delayed in the network, reach the server at once; the
	// in-flight pair completes and the agent spends its refilled burst at once.
	p = newPhase()
	for cycle := range 50 {
		tokens := agentBurst
		tokens -= 2 * agentCharge(SealingLimit) // A and B, later abandoned
		p.h.clock.Advance(2 * time.Second)
		tokens = min(agentBurst, tokens+agentRate*2)
		tokens -= 2 * agentCharge(SealingLimit) // C and D
		p.h.clock.Advance(8 * time.Second)
		tokens = min(agentBurst, tokens+agentRate*8)
		for range 4 { // A, B, C, D arrive together
			serve(p, SealingLimit, SealingLimit)
		}
		for range 2 { // E and F, sent as C and D complete
			tokens -= agentCharge(SealingLimit)
			serve(p, SealingLimit, SealingLimit)
		}
		if tokens < 0 {
			t.Fatalf("cycle %d: the simulated agent overspent", cycle)
		}
		tokens = stream(p, SealingLimit, tokens, 30*time.Second)
		p.h.clock.Advance(time.Minute)
	}
	if p.minimum != capacity-24*mib {
		t.Fatalf("bunching drew the bucket to %d, want %d", p.minimum, capacity-24*mib)
	}
	assertClean("bunching", p)

	// Randomized: charge delays up to 6,104 s, abandoned requests the server
	// still charges up to two at a time, pauses and restarts.
	const (
		eventTry = iota
		eventDecode
		eventDone
		requests     = 100_000
		maxChargeLag = 6104 * time.Second
	)
	p = newPhase()
	h := p.h
	rng := rand.New(rand.NewPCG(20261015, 11))
	var q simQueue
	seq := 0
	push := func(at time.Duration, kind int, req *simRequest) {
		seq++
		heap.Push(&q, &simEvent{at: at, seq: seq, kind: kind, req: req})
	}
	tokens, last := 0.0, time.Duration(0) // the agent bucket starts empty
	inflight, tries, abandoned, issued, refusedSlots, restarts := 0, 0, 0, 0, 0, 0
	pickSize := func() uint64 {
		switch rng.IntN(10) {
		case 0, 1:
			return 1 + rng.Uint64N(MinCharge)
		case 2, 3, 4:
			return 1 + rng.Uint64N(SealingLimit)
		}
		return SealingLimit
	}
	nextSize := pickSize()
	nextWindow := nextSize
	if rng.IntN(2) == 0 {
		nextWindow = SealingLimit
	}
	schedule := func(now time.Duration) {
		if inflight+tries >= PerDeviceInflight || issued+inflight+tries >= requests+PerDeviceInflight {
			return
		}
		tries++
		wait := time.Duration(0)
		if need := agentCharge(max(nextSize, nextWindow)) - tokens; need > 0 {
			wait = time.Duration(math.Ceil(need / agentRate * 1e9))
		}
		if rng.IntN(5) == 0 {
			wait += time.Duration(rng.Int64N(int64(30 * time.Second)))
		}
		push(now+wait, eventTry, nil)
	}
	schedule(0)
	schedule(0)
	for q.Len() > 0 {
		ev := heap.Pop(&q).(*simEvent)
		now := ev.at
		h.clock.Set(p.start.Add(now))
		tokens = min(agentBurst, tokens+agentRate*(now-last).Seconds())
		last = now
		switch ev.kind {
		case eventTry:
			tries--
			if issued >= requests {
				continue
			}
			if tokens < agentCharge(max(nextSize, nextWindow)) {
				schedule(now)
				continue
			}
			size, window := nextSize, nextWindow
			nextSize = pickSize()
			nextWindow = nextSize
			if rng.IntN(2) == 0 {
				nextWindow = SealingLimit
			}
			tokens -= agentCharge(max(size, window))
			inflight++
			issued++
			ticket, d, err := h.l.Receive("agent", batch.ClassRaw)
			if err != nil {
				t.Fatal(err)
			}
			if ticket == nil {
				if d.Reason != ReasonDeviceConcurrency || d.Finding != "" {
					t.Fatalf("request %d refused: %+v", issued, d)
				}
				refusedSlots++
				push(now+time.Duration(d.RetryAfter)*time.Second, eventDone, nil)
				continue
			}
			req := &simRequest{ticket: ticket, window: window, size: size}
			var lag time.Duration
			switch r := rng.IntN(10); {
			case r < 4:
				lag = 0
			case r < 7:
				lag = time.Duration(rng.Int64N(int64(time.Second)))
			case r < 9:
				lag = time.Duration(rng.Int64N(int64(time.Minute)))
			default:
				lag = time.Duration(rng.Int64N(int64(maxChargeLag)))
			}
			if abandoned < 2 && lag > 0 && rng.IntN(20) == 0 {
				req.abandoned = true
				abandoned++
				push(now+time.Duration(rng.Int64N(int64(lag))), eventDone, nil)
			}
			push(now+lag, eventDecode, req)
		case eventDecode:
			d, err := ev.req.ticket.Decode(context.Background(), ev.req.window, ev.req.size)
			if err != nil || d != (Decision{}) {
				t.Fatalf("unmodified agent refused or flagged after %d requests: %+v %v", issued, d, err)
			}
			p.minimum = min(p.minimum, h.tokens("agent"))
			ev.req.ticket.Decoded(time.Millisecond)
			ev.req.ticket.Release()
			p.requests++
			if ev.req.abandoned {
				abandoned--
			} else {
				push(now+time.Millisecond, eventDone, nil)
			}
		case eventDone:
			inflight--
			if inflight == 0 && abandoned == 0 && rng.IntN(50) == 0 {
				tokens = 0 // restart: the bucket starts empty again
				restarts++
			}
			schedule(now)
		}
	}
	if issued != requests {
		t.Fatalf("issued %d", issued)
	}
	t.Logf("randomized: %d slot refusals, %d restarts", refusedSlots, restarts)
	assertClean("randomized", p)
}

func TestFindings(t *testing.T) {
	h := newHarnessConfig(t, Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second})
	var tk *Ticket
	for range BucketCapacity / SealingLimit {
		tk = h.receive("r", batch.ClassRaw)
		h.admit(tk, SealingLimit, SealingLimit)
		tk.Release()
	}
	for i := 1; i <= 22; i++ {
		ticket, d, err := h.l.Receive("r", batch.ClassRaw)
		want := Finding("")
		if i == 21 {
			want = FindingRate
		}
		if err != nil || ticket != nil || d.Reason != ReasonDeviceRate || d.Finding != want {
			t.Fatalf("refusal %d: %+v %v", i, d, err)
		}
	}
	// Suppressed for ten minutes, but every oversize frame is still counted.
	h.clock.Advance(2 * time.Second)
	tk = h.receive("r", batch.ClassFindings)
	d, err := tk.Decode(context.Background(), SealingLimit+1, 0)
	if err != nil || d != (Decision{}) {
		t.Fatalf("suppressed oversize frame: %+v %v", d, err)
	}
	tk.Release()
	h.clock.Advance(10 * time.Minute)
	tk = h.receive("r", batch.ClassFindings)
	d, err = tk.Decode(context.Background(), 0, SealingLimit+1)
	if err != nil || d != (Decision{Finding: FindingOversize}) {
		t.Fatalf("oversize after suppression: %+v %v", d, err)
	}
	tk.Release()
	tk = h.receive("r", batch.ClassFindings)
	if d, _ := tk.Decode(context.Background(), SealingLimit+1, SealingLimit+1); d != (Decision{}) {
		t.Fatalf("second oversize frame raised a finding: %+v", d)
	}
	tk.Release()
	tk = h.receive("ok", batch.ClassRaw)
	if d, _ := tk.Decode(context.Background(), SealingLimit, SealingLimit); d != (Decision{}) {
		t.Fatalf("frame at the sealing limit: %+v", d)
	}
	tk.Release()
	s := h.l.Snapshot()
	if s.OversizeFrames[batch.ClassFindings] != 3 || s.OversizeFrames[batch.ClassRaw] != 0 || s.Findings != 2 {
		t.Fatalf("oversize counts %+v findings %d", s.OversizeFrames, s.Findings)
	}
	h.l.mu.Lock()
	oversize := h.l.devices["r"].counters(h.l.minute(h.clock.Now()), counterOversize)
	h.l.mu.Unlock()
	if oversize != 2 {
		t.Fatalf("device oversize counter %d in the trailing ten minutes", oversize)
	}
	h.clock.Advance(10 * time.Minute)
	tk = h.receive("r", batch.ClassRaw)
	if d, _ := tk.Decode(context.Background(), SealingLimit+1, 0); d.Finding != FindingOversize {
		t.Fatalf("finding after suppression expired: %+v", d)
	}
	tk.Release()

	// Idle entries leave within two later calls.
	h = newHarnessConfig(t, Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second})
	tk = h.receive("old", batch.ClassRaw)
	h.admit(tk, 0, 64*mib)
	tk.Release()
	if _, d, _ := h.l.Receive("old", batch.ClassRaw); d.Reason != ReasonDeviceRate {
		t.Fatal(d)
	}
	h.clock.Advance(11 * time.Minute)
	if h.l.devices["old"] == nil {
		t.Fatal("entry removed early")
	}
	h.receive("n1", batch.ClassRaw).Release()
	if h.l.devices["old"] != nil {
		t.Fatal("idle entry kept after two calls")
	}
	if len(h.l.devices) > 1 {
		t.Fatalf("%d entries remain", len(h.l.devices))
	}

	// 20,000 devices refused once each stay within 384 bytes per entry.
	h = newHarnessConfig(t, Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second})
	devices := make([]string, 20_000)
	for i := range devices {
		devices[i] = fmt.Sprintf("%036d", i)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, device := range devices {
		tk := h.receive(device, batch.ClassRaw)
		h.admit(tk, 0, 64*mib)
		tk.Release()
		if _, d, _ := h.l.Receive(device, batch.ClassRaw); d.Reason != ReasonDeviceRate {
			t.Fatal(d)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if len(h.l.devices) != len(devices) {
		t.Fatalf("%d entries", len(h.l.devices))
	}
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("20,000 device entries use %d bytes, %d per device", used, used/20_000)
	if used > 20_000*384 {
		t.Fatalf("device entries use %d bytes", used)
	}
	runtime.KeepAlive(devices)
}

func TestAttribution(t *testing.T) {
	h := newHarness(t)
	for i := range 20 {
		tk := h.receive(fmt.Sprintf("dev%02d", i), batch.ClassRaw)
		tk.Decoded(time.Duration(i+1) * time.Second)
		if i == 15 {
			if d, _ := tk.Decode(context.Background(), SealingLimit+1, 0); d.Finding != FindingOversize {
				t.Fatal(d)
			}
		}
		tk.Release()
		tk.Decoded(time.Hour)
	}
	top := h.l.Snapshot().TopDevices
	if len(top) != 10 {
		t.Fatalf("%d top devices", len(top))
	}
	for i, u := range top {
		want := fmt.Sprintf("dev%02d", 19-i)
		oversize := uint64(0)
		if want == "dev15" {
			oversize = 1
		}
		if u.Device != want || u.DecodeTime != time.Duration(20-i)*time.Second || u.OversizeFrames != oversize {
			t.Fatalf("top %d: %+v", i, u)
		}
	}
	h.clock.Advance(10*time.Minute + time.Second)
	if top := h.l.Snapshot().TopDevices; len(top) != 0 {
		t.Fatalf("decode time kept after ten minutes: %+v", top)
	}

	// Time is counted in microseconds: short decodes are never rounded away.
	h = newHarness(t)
	many, one := h.receive("many", batch.ClassRaw), h.receive("one", batch.ClassRaw)
	for range 10_000 {
		many.Decoded(999 * time.Microsecond)
	}
	one.Decoded(2 * time.Millisecond)
	top = h.l.Snapshot().TopDevices
	if len(top) != 2 || top[0].Device != "many" || top[0].DecodeTime != 9_990*time.Millisecond || top[1].DecodeTime != 2*time.Millisecond {
		t.Fatalf("microsecond attribution: %+v", top)
	}
}

// TestElapsedIndexing starts the clock 1 ms before a wall-clock minute and
// second boundary. Every index follows now.Sub(start), so crossing the wall
// boundary moves nothing, while indexes derived from Unix time would.
func TestElapsedIndexing(t *testing.T) {
	now := time.Now()
	base := now.Add(time.Minute - time.Duration(now.UnixNano()%int64(time.Minute)) - time.Millisecond)
	if base.Second() != 59 || base.Nanosecond() != int(999*time.Millisecond) {
		t.Fatalf("base %v", base)
	}
	h := &harness{t: t, clock: newFakeClockAt(base), random: 0.5}
	l, err := New(Config{MemoryLimit: 1 << 30, AgentOnly: true, Budget: testBudget, MaxInflight: 10, DecodeWait: 2 * time.Second}, h.clock, func() float64 { return h.random })
	if err != nil {
		t.Fatal(err)
	}
	h.l = l
	at := func(d time.Duration) { h.clock.Set(base.Add(d)) }
	for _, d := range []time.Duration{0, time.Millisecond, time.Minute - 1, time.Minute, 61 * time.Minute} {
		if got := l.minute(base.Add(d)); got != int64(d/time.Minute) {
			t.Fatalf("minute index at %s: %d", d, got)
		}
	}
	// At elapsed 0: ten releases (nine receive-only tickets and the oversize
	// decode), one second of decode time and an oversize finding.
	for i := range 9 {
		h.receive(fmt.Sprintf("r%d", i), batch.ClassRaw).Release()
	}
	m := h.receive("m", batch.ClassRaw)
	m.Decoded(time.Second)
	oversize := func() Finding {
		tk := h.receive("s", batch.ClassRaw)
		defer tk.Release()
		d, err := tk.Decode(context.Background(), SealingLimit+1, 0)
		if err != nil || d.Status != 0 {
			t.Fatalf("oversize decode: %+v %v", d, err)
		}
		return d.Finding
	}
	if oversize() != FindingOversize {
		t.Fatal("first oversize frame")
	}
	rings := func() (int, int) {
		l.mu.Lock()
		defer l.mu.Unlock()
		drain := (10*C + charge(SealingLimit+1, 0)) / 10
		return l.inflightRetryAfter(h.clock.Now()), l.retryAfter(h.clock.Now(), 0, testBudget-l.inUse+20*drain)
	}
	at(9*time.Second + 999*time.Millisecond)
	if slot, drain := rings(); slot != 10 || drain != 20 {
		t.Fatalf("rings before ten seconds: slot %d, drain %d", slot, drain)
	}
	at(10 * time.Second)
	if slot, drain := rings(); slot != 60 || drain != 60 {
		t.Fatalf("rings after ten seconds: slot %d, drain %d", slot, drain)
	}
	at(10*time.Minute - time.Millisecond)
	if top := l.Snapshot().TopDevices; len(top) != 1 || top[0].DecodeTime != time.Second {
		t.Fatalf("minute counters before ten minutes: %+v", top)
	}
	if oversize() != "" {
		t.Fatal("finding inside the suppression")
	}
	at(10 * time.Minute)
	if top := l.Snapshot().TopDevices; len(top) != 0 {
		t.Fatalf("minute counters after ten minutes: %+v", top)
	}
	if oversize() != FindingOversize {
		t.Fatal("no finding after the suppression")
	}
	m.Release()
}

func TestCancellationAndState(t *testing.T) {
	h := newHarness(t)
	g := h.receive("g", batch.ClassFindings)
	h.admit(g, 64*mib, 64*mib)
	w := h.receive("w", batch.ClassFindings)
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.decodeAsync(ctx, w, 64*mib, 64*mib)
	if !pending(ch) {
		t.Fatal("not waiting")
	}
	cancel()
	if r := h.result(ch); !errors.Is(r.err, context.Canceled) || r.d.Status != 0 {
		t.Fatalf("canceled wait: %+v", r)
	}
	if s := h.l.Snapshot(); s.Waiting != 0 || s.InUse != 2*C+charge(64*mib, 64*mib) {
		t.Fatalf("after cancel: %+v", s)
	}
	w.Release()
	if h.inUse() != C+charge(64*mib, 64*mib) {
		t.Fatal("release after cancel")
	}
	// Release while Decode waits: the wait ends with ErrState and frees everything.
	w2 := h.receive("w2", batch.ClassFindings)
	ch = h.decodeAsync(context.Background(), w2, 64*mib, 64*mib)
	if !pending(ch) {
		t.Fatal("not waiting")
	}
	w2.Release()
	if r := h.result(ch); !errors.Is(r.err, ErrState) || r.d.Status != 0 {
		t.Fatalf("release during wait: %+v", r)
	}
	if s := h.l.Snapshot(); s.Waiting != 0 || s.WaitingBytes != 0 || s.InUse != C+charge(64*mib, 64*mib) || s.Inflight != 1 {
		t.Fatalf("after release during wait: %+v", s)
	}
	if _, err := g.Decode(context.Background(), 0, 0); !errors.Is(err, ErrState) {
		t.Fatalf("Decode twice: %v", err)
	}
	g.Release()
	g.Release()
	g.Decoded(time.Second)
	if s := h.l.Snapshot(); s.InUse != 0 || s.Inflight != 0 || len(s.TopDevices) != 0 {
		t.Fatalf("after double release: %+v", s)
	}
	if _, err := g.Decode(context.Background(), 0, 0); !errors.Is(err, ErrState) {
		t.Fatalf("Decode after Release: %v", err)
	}
	a := h.receive("a", batch.ClassRaw)
	for _, c := range [][2]uint64{{64*mib + 1, 0}, {0, 64*mib + 1}} {
		if _, err := a.Decode(context.Background(), c[0], c[1]); !errors.Is(err, ErrArgument) {
			t.Fatalf("argument %v: %v", c, err)
		}
	}
	h.admit(a, 0, 0)
	a.Release()
	b := h.receive("b", batch.ClassRaw)
	b.Release()
	if _, err := b.Decode(context.Background(), 0, 0); !errors.Is(err, ErrState) {
		t.Fatal("Decode after receive-phase Release")
	}
	expired, stop := context.WithCancel(context.Background())
	stop()
	c := h.receive("c", batch.ClassRaw)
	if d, err := c.Decode(expired, 0, 0); err != nil || d != (Decision{}) {
		t.Fatalf("an immediate admission ignores the context: %+v %v", d, err)
	}
	c.Release()
}

func TestInvariants(t *testing.T) {
	h := newHarness(t)
	rng := rand.New(rand.NewPCG(7, 2026))
	type held struct {
		ticket   *Ticket
		device   string
		decoded  bool
		result   <-chan decodeResult
		deadline time.Time
		cancel   context.CancelFunc
	}
	var live []*held
	previousCharges := map[*Ticket]int64{}
	sizes := []uint64{0, 1, 4 * kib, mib, SealingLimit, SealingLimit + 1, 24 * mib, 64 * mib}
	finish := func(x *held) {
		r := h.result(x.result)
		x.result = nil
		if r.err != nil && !errors.Is(r.err, context.Canceled) && !errors.Is(r.err, ErrState) {
			t.Fatalf("decode: %v", r.err)
		}
	}
	for op := range 10_000 {
		switch rng.IntN(6) {
		case 0, 1:
			device := fmt.Sprintf("d%d", rng.IntN(6))
			class := batch.SpoolClass(1 + rng.IntN(5))
			ticket, d, err := h.l.Receive(device, class)
			if err != nil {
				t.Fatal(err)
			}
			if ticket != nil {
				if priorityQueue(class) == 1 {
					s := h.l.Snapshot()
					if s.Budget-s.InUse < h.l.reserve || h.l.config.MaxInflight-s.Inflight < (h.l.config.MaxInflight+3)/4 {
						t.Fatalf("receive crossed reserve: %+v", s)
					}
				}
				live = append(live, &held{ticket: ticket, device: device})
			} else if d.Status == 0 {
				t.Fatal("nil ticket without refusal")
			}
		case 2:
			if len(live) == 0 {
				continue
			}
			x := live[rng.IntN(len(live))]
			if x.decoded {
				continue
			}
			x.decoded = true
			ctx, cancel := context.WithCancel(context.Background())
			x.cancel = cancel
			x.deadline = h.clock.Now().Add(2 * time.Second)
			x.result = h.decodeAsync(ctx, x.ticket, sizes[rng.IntN(len(sizes))], sizes[rng.IntN(len(sizes))])
			if !pending(x.result) {
				finish(x)
			}
		case 3:
			if len(live) == 0 {
				continue
			}
			i := rng.IntN(len(live))
			x := live[i]
			x.ticket.Release()
			live = append(live[:i], live[i+1:]...)
			if x.result != nil {
				finish(x) // a Release during the wait ends it
			}
			for _, x := range live {
				if x.result != nil && !pending(x.result) {
					finish(x)
				}
			}
		case 4:
			h.clock.Advance(time.Duration(rng.Int64N(int64(3 * time.Second))))
			for _, x := range live {
				if x.result != nil && !x.deadline.After(h.clock.Now()) {
					finish(x)
				}
			}
		case 5:
			for _, x := range live {
				if x.result != nil {
					x.cancel()
					finish(x)
					break
				}
			}
		}
		h.l.mu.Lock()
		sum := int64(0)
		slots := map[string]int{}
		currentCharges := make(map[*Ticket]int64, len(live))
		for _, x := range live {
			currentCharges[x.ticket] = x.ticket.charge
			if x.ticket.charge > previousCharges[x.ticket] && priorityQueue(x.ticket.class) == 1 && h.l.config.Budget-h.l.inUse < h.l.reserve {
				t.Fatalf("op %d: nonpriority decode crossed reserve", op)
			}
			sum += C + x.ticket.charge
			slots[x.device]++
		}
		for device, e := range h.l.devices {
			if e.slots != slots[device] || e.slots > PerDeviceInflight {
				t.Fatalf("op %d: device %s slots %d, held %d", op, device, e.slots, slots[device])
			}
		}
		if h.l.inUse < 0 || h.l.inUse > testBudget || h.l.inUse != sum || h.l.inflight != len(live) {
			t.Fatalf("op %d: in use %d, held %d, in flight %d of %d", op, h.l.inUse, sum, h.l.inflight, len(live))
		}
		previousCharges = currentCharges
		h.l.mu.Unlock()
	}
}

// TestRefillRemainder refills a bucket every 200 ns: the fraction of a byte
// each call adds is carried, so 10 ms refill exactly as one 10 ms step does.
func TestRefillRemainder(t *testing.T) {
	h := newHarness(t)
	tk := h.receive("v", batch.ClassRaw)
	h.admit(tk, 0, 64*mib)
	tk.Release()
	for range 50_000 {
		h.clock.Advance(200 * time.Nanosecond)
		h.tokens("v")
	}
	if got, want := h.tokens("v"), uint64(10*time.Millisecond)*ServerRefill/uint64(time.Second); got != want {
		t.Fatalf("refill over 50,000 calls: %d, want %d", got, want)
	}
}

func TestWindowWorkCharge(t *testing.T) {
	h := newHarness(t)
	ticket := h.receive("window", batch.ClassRaw)
	h.admit(ticket, 64<<20, 103)
	if got := h.l.devices["window"].tokens; got != 0 {
		t.Fatalf("large window left %d credits", got)
	}
	ticket.Release()
	ticket, d, err := h.l.Receive("window", batch.ClassRaw)
	if ticket != nil || err != nil || d.Reason != ReasonDeviceRate {
		t.Fatalf("window deficit: %+v %v", d, err)
	}
}

func TestConcurrencyRateEvidence(t *testing.T) {
	h := newHarness(t)
	h.receive("a", batch.ClassRaw)
	h.receive("a", batch.ClassRaw)
	e := h.l.devices["a"]
	e.tokens = MinCharge
	_, d, err := h.l.Receive("a", batch.ClassRaw)
	if err != nil || d.Reason != ReasonDeviceConcurrency || e.counters(h.l.minute(h.clock.Now()), counterRate) != 0 {
		t.Fatalf("exact minimum: %+v %v", d, err)
	}
	for i := 1; i <= 21; i++ {
		_, d, err = h.l.Receive("a", batch.ClassRaw)
		if err != nil || d.Reason != ReasonDeviceConcurrency || e.tokens != 0 {
			t.Fatalf("deficit %d: %+v %v", i, d, err)
		}
		if (d.Finding == FindingRate) != (i == 21) {
			t.Fatalf("finding %d: %+v", i, d)
		}
	}
	if got := h.l.Snapshot(); got.Refused[ReasonDeviceRate] != 0 || got.Refused[ReasonDeviceConcurrency] != 22 {
		t.Fatalf("wrong attribution: %+v", got)
	}
}

func TestMixedPhaseReserve(t *testing.T) {
	const budget int64 = 1_932_735_283
	for _, class := range []batch.SpoolClass{batch.ClassRaw, batch.ClassContext, batch.ClassLineage} {
		t.Run(class.String(), func(t *testing.T) {
			h := newHarnessConfig(t, Config{MemoryLimit: 8 << 30, AgentOnly: true, Budget: budget, MaxInflight: 176, DecodeWait: 2 * time.Second})
			for i := range 55 {
				ticket := h.receive(fmt.Sprintf("decoded%d", i), class)
				h.admit(ticket, 4<<20, 4<<20)
			}
			for i := range 4 {
				h.receive(fmt.Sprintf("receive%d", i), class)
			}
			if got := budget - h.l.Snapshot().InUse; got != 484_301_683 {
				t.Fatalf("available=%d", got)
			}
			for i := range 10 {
				ticket, d, err := h.l.Receive(fmt.Sprintf("refused%d", i), class)
				if ticket != nil || err != nil || d.Reason != ReasonReserve {
					t.Fatalf("byte reserve: %+v %v", d, err)
				}
			}
			p := h.receive("priority", batch.ClassFindings)
			h.admit(p, 4<<20, 4<<20)
			s := h.l.Snapshot()
			if s.Refused[ReasonReserve] != 10 || s.Refused[ReasonInflight] != 0 || s.Refused[ReasonBudget] != 0 {
				t.Fatalf("counters: %+v", s)
			}
		})
	}
	for _, cap := range []int{4, 5, 176, 256} {
		b := int64(minBudget)
		if cap == 176 {
			b = budget
		}
		if cap == 256 {
			b = 4 << 30
		}
		h := newHarnessConfig(t, Config{MemoryLimit: 16 << 30, AgentOnly: true, Budget: b, MaxInflight: cap, DecodeWait: 2 * time.Second})
		p := (cap + 3) / 4
		for i := range cap - p {
			h.receive(fmt.Sprintf("held%d", i), batch.ClassRaw)
		}
		for i := range 10 {
			ticket, d, err := h.l.Receive(fmt.Sprintf("reserve%d", i), batch.ClassRaw)
			if ticket != nil || err != nil || d.Reason != ReasonReserve {
				t.Fatalf("slots %d: %+v %v", cap, d, err)
			}
		}
		snapshot := h.l.Snapshot()
		if snapshot.Refused[ReasonReserve] != 10 || snapshot.Refused[ReasonInflight] != 0 || snapshot.Refused[ReasonBudget] != 0 {
			t.Fatalf("slot counters: %+v", snapshot)
		}
		for _, priorityClass := range []batch.SpoolClass{batch.ClassAudit, batch.ClassFindings} {
			priority := h.receive("priority", priorityClass)
			h.admit(priority, 4<<20, 4<<20)
			priority.Release()
		}

	}
}

func TestReceiveReserveByteBoundaries(t *testing.T) {
	for _, class := range []batch.SpoolClass{batch.ClassRaw, batch.ClassContext, batch.ClassLineage, batch.ClassFindings, batch.ClassAudit} {
		for _, delta := range []int64{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%d", class, delta), func(t *testing.T) {
				h := newHarness(t)
				// Build the boundary entirely from held, priority tickets. All budget
				// values include their receive charge and match real ticket accounting.
				a, b := h.receive("a", batch.ClassAudit), h.receive("b", batch.ClassAudit)
				h.admit(a, 64<<20, 64<<20)
				target := testBudget - testReserve - C + delta
				need := target - h.l.inUse
				h.l.mu.Lock()
				// This setup represents already charged priority work. It also gives the
				// refusal test an exact byte boundary independent of Weight's rounding.
				b.charge = need
				h.l.inUse += need
				h.l.mu.Unlock()
				before := h.l.Snapshot()
				ticket, d, err := h.l.Receive("boundary", class)
				refused := priorityQueue(class) == 1 && delta > 0
				if err != nil || refused && (ticket != nil || d.Reason != ReasonReserve) || !refused && (ticket == nil || d.Status != 0) {
					t.Fatalf("delta=%d: %+v %v", delta, d, err)
				}
				if h.tokens("boundary") != BucketCapacity-MinCharge {
					t.Fatal("capacity check did not charge minimum")
				}
				if refused {
					after := h.l.Snapshot()
					if after.InUse != before.InUse || after.Inflight != before.Inflight {
						t.Fatal("refusal mutated capacity")
					}
				} else {
					ticket.Release()
				}
				a.Release()
				b.Release()
				if h.l.Snapshot().InUse != 0 {
					t.Fatal("release leaked")
				}
			})
		}
	}
}

func TestMixedRateEvidence(t *testing.T) {
	h := newHarness(t)
	a := h.receive("mixed", batch.ClassRaw)
	h.receive("mixed", batch.ClassRaw)
	e := h.l.devices["mixed"]
	e.tokens = 0
	for range 10 {
		h.l.Receive("mixed", batch.ClassRaw)
	}
	a.Release()
	e.tokens = MinCharge
	a = h.receive("mixed", batch.ClassRaw)
	d, err := a.Decode(context.Background(), 4<<20, 103)
	if err != nil || d.Reason != ReasonDeviceRate {
		t.Fatalf("decode deficit: %+v %v", d, err)
	}
	a.Release()
	_, d, err = h.l.Receive("mixed", batch.ClassRaw)
	if err != nil || d.Reason != ReasonDeviceRate {
		t.Fatalf("receive deficit: %+v %v", d, err)
	}
	e.tokens = MinCharge
	h.receive("mixed", batch.ClassRaw)
	for i := range 9 {
		_, d, err = h.l.Receive("mixed", batch.ClassRaw)
		if err != nil || d.Reason != ReasonDeviceConcurrency || (d.Finding == FindingRate) != (i == 8) {
			t.Fatalf("mixed deficit %d: %+v %v", i, d, err)
		}
	}
	if count := e.counters(h.l.minute(h.clock.Now()), counterRate); count != 21 {
		t.Fatalf("evidence count=%d", count)
	}
}

func TestDecodeReserveByteBoundaries(t *testing.T) {
	for _, class := range []batch.SpoolClass{batch.ClassRaw, batch.ClassContext, batch.ClassLineage, batch.ClassFindings, batch.ClassAudit} {
		for _, offset := range []int64{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%d", class, offset), func(t *testing.T) {
				h := newHarness(t)
				ticket := h.receive("request", class)
				a, b := h.receive("a", batch.ClassAudit), h.receive("b", batch.ClassAudit)
				weight, _ := Weight(4<<20, 4<<20)
				need := weight - C
				// Isolate the exact boundary from Weight's integer size rounding, with
				// all synthetic priority charges represented by held tickets.
				total := testBudget - h.l.reserve - need - offset
				a.charge = (total - 3*C) / 2
				b.charge = total - 3*C - a.charge
				h.l.inUse = total
				ch := h.decodeAsync(context.Background(), ticket, 4<<20, 4<<20)
				if priorityQueue(class) == 1 && offset < 0 {
					if !pending(ch) {
						t.Fatal("decode crossed reserve")
					}
					h.clock.Advance(2 * time.Second)
					r := h.result(ch)
					if r.err != nil || r.d.Reason != ReasonReserve || ticket.charge != 0 {
						t.Fatalf("reserve wait: %+v charge=%d", r, ticket.charge)
					}
				} else {
					r := h.result(ch)
					if r.err != nil || r.d.Status != 0 || ticket.charge != need || h.l.inUse != total+need {
						t.Fatalf("upgrade: %+v bytes=%d", r, h.l.inUse)
					}
				}
				ticket.Release()
				a.Release()
				b.Release()
				if h.l.Snapshot().InUse != 0 {
					t.Fatal("boundary release leaked")
				}
			})
		}
	}
}

func TestReceiveGlobalByteBudget(t *testing.T) {
	h := newHarness(t)
	a, b := h.receive("a", batch.ClassAudit), h.receive("b", batch.ClassAudit)
	h.admit(a, 64<<20, 64<<20)
	h.admit(b, 32<<20, 16<<20)
	for i := range 3 {
		ticket := h.receive(fmt.Sprintf("small%d", i), batch.ClassAudit)
		h.admit(ticket, 0, 0)
	}
	before := h.l.Snapshot()
	if before.Budget-before.InUse >= C {
		t.Fatal("setup leaves room for receive")
	}
	for _, class := range []batch.SpoolClass{batch.ClassRaw, batch.ClassContext, batch.ClassLineage, batch.ClassAudit, batch.ClassFindings} {
		for i, r := range []float64{0, .5, 1} {
			h.random = r
			device := fmt.Sprintf("refused-%s-%d", class, i)
			ticket, d, err := h.l.Receive(device, class)
			if ticket != nil || err != nil || d.Reason != ReasonBudget || d.Status != 503 || d.RetryAfter != []int{48, 60, 60}[i] {
				t.Fatalf("global bytes: %+v %v", d, err)
			}
			if h.tokens(device) != BucketCapacity-MinCharge {
				t.Fatal("budget refusal did not spend minimum")
			}
			after := h.l.Snapshot()
			if before.InUse != after.InUse || before.Inflight != after.Inflight {
				t.Fatal("budget refusal changed held capacity")
			}
		}
	}
	e := h.l.devices["refused-raw-0"]
	e.tokens = MinCharge - 1
	_, d, err := h.l.Receive(e.device, batch.ClassRaw)
	if err != nil || d.Reason != ReasonDeviceRate || e.tokens != MinCharge-1 {
		t.Fatalf("credit check precedence: %+v %v", d, err)
	}
}
