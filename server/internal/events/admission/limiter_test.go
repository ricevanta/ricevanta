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

// fakeClock fires timers only when the test advances it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	clock *fakeClock
	at    time.Time
	ch    chan time.Time
	fired bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
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
	released := int64(0)
	h.receive("drain", batch.ClassRaw).Release()
	released += C

	a, b := h.receive("d1", batch.ClassRaw), h.receive("d1", batch.ClassFindings)
	ticket, d, err := h.l.Receive("d1", batch.ClassAudit)
	if err != nil || ticket != nil || d != (Decision{Status: 429, RetryAfter: 5, Reason: ReasonDeviceConcurrency}) {
		t.Fatalf("third upload: %v %+v %v", ticket, d, err)
	}
	s := h.l.Snapshot()
	if s.Inflight != 2 || s.InUse != 2*C || h.l.devices["d1"].slots != 2 || s.Refused[ReasonDeviceConcurrency] != 1 || len(s.Refused) != 1 {
		t.Fatalf("refusal changed state: %+v", s)
	}
	a.Release()
	b.Release()
	released += 2 * C

	// Ten in flight: T1 findings admitted at 64 MiB, T2 findings waiting at 24 MiB.
	tickets := make([]*Ticket, 10)
	for i := range tickets {
		class := batch.ClassRaw
		if i < 2 {
			class = batch.ClassFindings
		}
		tickets[i] = h.receive(fmt.Sprintf("n%d", i), class)
	}
	h.admit(tickets[0], 64*mib, 64*mib)
	waiting := h.decodeAsync(context.Background(), tickets[1], 24*mib, 24*mib)
	if !pending(waiting) {
		t.Fatal("24 MiB decode did not wait")
	}
	available := testBudget - 10*C - charge(64*mib, 64*mib)
	want := expectRetry(charge(24*mib, 24*mib)+C-available, released/10, 0.5)
	ticket, d, err = h.l.Receive("n10", batch.ClassRaw)
	if err != nil || ticket != nil || d != (Decision{Status: 503, RetryAfter: want, Reason: ReasonInflight}) {
		t.Fatalf("eleventh request: %+v %v, want Retry-After %d", d, err, want)
	}
	if want == 5 || want == 60 {
		t.Fatalf("Retry-After %d does not discriminate the formula", want)
	}
	if s := h.l.Snapshot(); s.Inflight != 10 || s.Refused[ReasonInflight] != 1 || h.l.devices["n10"] != nil && h.l.devices["n10"].slots != 0 {
		t.Fatalf("in-flight refusal changed state: %+v", s)
	}
	h.clock.Advance(2 * time.Second)
	if r := h.result(waiting); r.d.Status != 503 || r.d.Reason != ReasonBudget {
		t.Fatalf("waiter: %+v", r)
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
}

func TestDeviceBucket(t *testing.T) {
	h := newHarness(t)
	tk := h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 64*mib)
	tk.Release()
	tk = h.receive("x", batch.ClassRaw)
	before := h.inUse()
	d, err := tk.Decode(context.Background(), 4*mib, 64*mib)
	if err != nil || d != (Decision{Status: 429, RetryAfter: 16, Reason: ReasonDeviceRate}) {
		t.Fatalf("second 64 MiB: %+v %v", d, err)
	}
	if h.tokens("x") != 0 || h.inUse() != before {
		t.Fatal("refusal charged the bucket or the budget")
	}
	if _, err := tk.Decode(context.Background(), 0, 0); !errors.Is(err, ErrState) {
		t.Fatalf("Decode after a refusal: %v", err)
	}
	tk.Release()
	h.clock.Advance(2 * time.Second)
	if got := h.tokens("x"); got != 2*ServerRefill || got < 8*mib+mib/8 {
		t.Fatalf("refill after 2 s: %d", got)
	}
	tk = h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 4*mib)
	tk.Release()
	h.clock.Advance(15 * time.Second)
	tk = h.receive("x", batch.ClassRaw)
	h.admit(tk, 4*mib, 64*mib)
	tk.Release()

	// Charged on the call, before waiting; never refunded.
	f1, f2 := h.receive("f1", batch.ClassFindings), h.receive("f2", batch.ClassFindings)
	h.admit(f1, 64*mib, 64*mib)
	h.admit(f2, 24*mib, 24*mib)
	y1, y2 := h.receive("y", batch.ClassRaw), h.receive("y", batch.ClassRaw)
	wy := h.decodeAsync(context.Background(), y1, 4*mib, 64*mib)
	if !pending(wy) || h.tokens("y") != 0 {
		t.Fatalf("bucket not charged before waiting: %d", h.tokens("y"))
	}
	h.clock.Advance(2 * time.Second)
	if r := h.result(wy); r.d.Status != 503 {
		t.Fatalf("expected a budget refusal: %+v", r)
	}
	if got := h.tokens("y"); got != 2*ServerRefill {
		t.Fatalf("bucket refunded after timeout: %d", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	wy = h.decodeAsync(ctx, y2, 0, 2*ServerRefill)
	if !pending(wy) || h.tokens("y") != 0 {
		t.Fatal("second waiter not charged")
	}
	cancel()
	if r := h.result(wy); !errors.Is(r.err, context.Canceled) {
		t.Fatalf("canceled waiter: %+v", r)
	}
	if h.tokens("y") != 0 {
		t.Fatal("bucket refunded after cancellation")
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

func TestAgentConformance(t *testing.T) {
	const (
		agentBurst   = 8 * mib
		agentRate    = float64(AgentRate) * (1 + 500e-6) // the agent's clock runs 500 ppm fast
		requests     = 100_000
		maxChargeLag = 6104 * time.Second
	)
	const (
		eventTry = iota
		eventDecode
		eventDone
	)
	h := newHarnessConfig(t, Config{MemoryLimit: 1 << 40, AgentOnly: true, Budget: 1 << 39, MaxInflight: 256, DecodeWait: 2 * time.Second})
	start := h.clock.Now()
	rng := rand.New(rand.NewPCG(20261015, 11))
	var q simQueue
	seq := 0
	push := func(at time.Duration, kind int, req *simRequest) {
		seq++
		heap.Push(&q, &simEvent{at: at, seq: seq, kind: kind, req: req})
	}
	tokens, last := 0.0, time.Duration(0) // the agent bucket starts empty
	inflight, tries, abandoned, issued, refusedSlots, restarts := 0, 0, 0, 0, 0, 0
	nextSize, minTokens := uint64(0), BucketCapacity
	pickSize := func() uint64 {
		if rng.IntN(10) < 7 {
			return SealingLimit
		}
		return 1 + rng.Uint64N(SealingLimit)
	}
	nextSize = pickSize()
	schedule := func(now time.Duration) {
		if inflight+tries >= PerDeviceInflight || issued+inflight+tries >= requests+PerDeviceInflight {
			return
		}
		tries++
		wait := time.Duration(0)
		if need := float64(nextSize) - tokens; need > 0 {
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
		h.clock.Set(start.Add(now))
		tokens = min(agentBurst, tokens+agentRate*(now-last).Seconds())
		last = now
		switch ev.kind {
		case eventTry:
			tries--
			if issued >= requests {
				continue
			}
			if tokens < float64(nextSize) {
				schedule(now)
				continue
			}
			size := nextSize
			nextSize = pickSize()
			tokens -= float64(size)
			inflight++
			issued++
			ticket, d, err := h.l.Receive("agent", batch.ClassRaw)
			if err != nil {
				t.Fatal(err)
			}
			if ticket == nil {
				if d.Reason != ReasonDeviceConcurrency {
					t.Fatalf("request %d refused: %+v", issued, d)
				}
				refusedSlots++
				push(now+time.Duration(d.RetryAfter)*time.Second, eventDone, nil)
				continue
			}
			window := size
			if rng.IntN(2) == 0 {
				window = SealingLimit
			}
			req := &simRequest{ticket: ticket, window: window, size: size}
			var lag time.Duration
			switch p := rng.IntN(10); {
			case p < 4:
				lag = 0
			case p < 7:
				lag = time.Duration(rng.Int64N(int64(time.Second)))
			case p < 9:
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
			minTokens = min(minTokens, h.tokens("agent"))
			d, err := ev.req.ticket.Decode(context.Background(), ev.req.window, ev.req.size)
			if err != nil || d.Status != 0 || d.Finding != "" {
				t.Fatalf("unmodified agent refused or flagged after %d requests: %+v %v", issued, d, err)
			}
			ev.req.ticket.Decoded(time.Millisecond)
			ev.req.ticket.Release()
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
	s := h.l.Snapshot()
	if issued != requests || s.Refused[ReasonDeviceRate] != 0 || s.Findings != 0 {
		t.Fatalf("issued %d, snapshot %+v", issued, s)
	}
	t.Logf("%d requests over %s of server time, %d slot refusals, %d restarts, lowest server bucket %d bytes before a charge", issued, h.clock.Now().Sub(start), refusedSlots, restarts, minTokens)
	if minTokens > BucketCapacity-agentBurst {
		t.Fatalf("simulation never drew the server bucket below %d bytes", BucketCapacity-agentBurst)
	}
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
		h.clock.Advance(10 * time.Millisecond)
		tk = h.receive("r", batch.ClassRaw)
		d, err := tk.Decode(context.Background(), 0, SealingLimit)
		want := Finding("")
		if i == 21 {
			want = FindingRate
		}
		if err != nil || d.Reason != ReasonDeviceRate || d.Finding != want {
			t.Fatalf("refusal %d: %+v %v", i, d, err)
		}
		tk.Release()
	}
	// Suppressed for ten minutes, but every oversize frame is still counted.
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
	oversize := h.l.devices["r"].counters(h.clock.Now(), counterOversize)
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
	tk = h.receive("old", batch.ClassRaw)
	if d, _ := tk.Decode(context.Background(), 0, 64*mib); d.Reason != ReasonDeviceRate {
		t.Fatal(d)
	}
	tk.Release()
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
		tk = h.receive(device, batch.ClassRaw)
		if d, _ := tk.Decode(context.Background(), 0, 1); d.Reason != ReasonDeviceRate {
			t.Fatal(d)
		}
		tk.Release()
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
	sizes := []uint64{0, 1, 4 * kib, mib, SealingLimit, SealingLimit + 1, 24 * mib, 64 * mib}
	finish := func(x *held) {
		r := h.result(x.result)
		x.result = nil
		if r.err != nil && !errors.Is(r.err, context.Canceled) {
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
			if live[i].result != nil {
				continue
			}
			live[i].ticket.Release()
			live = append(live[:i], live[i+1:]...)
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
		for _, x := range live {
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
		h.l.mu.Unlock()
	}
}
