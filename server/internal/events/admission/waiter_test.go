package admission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

// waiterClock can expire a wait while Release holds the limiter lock. A gated
// timer keeps Decode outside its select until the test inspects dispatch.
type waiterClock struct {
	*fakeClock
	hooksMu   sync.Mutex
	nextNow   func()
	nextTimer <-chan struct{}
}

func (c *waiterClock) Now() time.Time {
	c.hooksMu.Lock()
	hook := c.nextNow
	c.nextNow = nil
	c.hooksMu.Unlock()
	if hook != nil {
		hook()
	}
	return c.fakeClock.Now()
}

func (c *waiterClock) NewTimer(d time.Duration) Timer {
	timer := c.fakeClock.NewTimer(d)
	c.hooksMu.Lock()
	gate := c.nextTimer
	c.nextTimer = nil
	c.hooksMu.Unlock()
	if gate == nil {
		return timer
	}
	return gatedWaiterTimer{Timer: timer, gate: gate}
}

func (c *waiterClock) onNextNow(hook func()) {
	c.hooksMu.Lock()
	c.nextNow = hook
	c.hooksMu.Unlock()
}

func (c *waiterClock) gateNextTimer() func() {
	gate := make(chan struct{})
	c.hooksMu.Lock()
	c.nextTimer = gate
	c.hooksMu.Unlock()
	return sync.OnceFunc(func() { close(gate) })
}

type gatedWaiterTimer struct {
	Timer
	gate <-chan struct{}
}

func (t gatedWaiterTimer) C() <-chan time.Time {
	<-t.gate
	return t.Timer.C()
}

// Removing deadline or cancellation checks from dispatch must fail this test,
// even if Decode later rolls back the invalid reservation. An invalid head
// must also stop blocking a live FIFO successor when the head does not fit.
func TestQueuedDecodeDispatchExpiry(t *testing.T) {
	for _, class := range []batch.SpoolClass{batch.ClassFindings, batch.ClassAudit, batch.ClassRaw, batch.ClassContext, batch.ClassLineage} {
		for _, expiry := range []string{"deadline", "delayed-timer", "context"} {
			for _, releaseBlocker := range []bool{true, false} {
				name := class.String() + "/" + expiry
				if !releaseBlocker {
					name += "/nonfitting-head"
				}
				t.Run(name, func(t *testing.T) {
					h := newHarness(t)
					clock := &waiterClock{fakeClock: h.clock}
					h.l.clock = clock
					blocker := h.receive("blocker", batch.ClassFindings)
					h.admit(blocker, 64<<20, 64<<20)
					defer blocker.Release()
					victim := h.receive("victim", class)
					defer victim.Release()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					resume := clock.gateNextTimer()
					defer resume()
					if expiry == "delayed-timer" {
						h.clock.hold = true
					}
					result := h.decodeAsync(ctx, victim, 64<<20, 64<<20)
					h.clock.Advance(500 * time.Millisecond)
					follower := h.receive("follower", class)
					defer follower.Release()
					followResult := h.decodeAsync(context.Background(), follower, 0, 0)
					trigger := blocker
					if !releaseBlocker {
						trigger = h.receive("trigger", batch.ClassAudit)
						defer trigger.Release()
					}
					clock.onNextNow(func() {
						if expiry == "context" {
							cancel()
						} else {
							// Equality with DecodeWait is already expired, including
							// when the timer notification has not arrived yet.
							h.clock.Advance(1500 * time.Millisecond)
						}
					})
					trigger.Release()
					wantUse := int64(14_196_352) // two receives plus Weight(0,0)-C
					if !releaseBlocker {
						wantUse += 167_529_280
					}
					if s := h.l.Snapshot(); s.InUse != wantUse || s.Waiting != 0 || s.WaitingBytes != 0 {
						t.Errorf("dispatch charged invalid work or blocked its successor: %+v, want in use %d", s, wantUse)
						if expiry == "delayed-timer" && s.Waiting != 0 {
							cancel() // clean up a broken dispatch without waiting for a held timer
						}
					}
					resume()
					assertWaiterRefused(t, h, victim, h.result(result), expiry == "context")
					if r := h.result(followResult); r.err != nil || r.d != (Decision{}) {
						t.Fatalf("live FIFO successor: %+v", r)
					}
					wantTokens := uint64(8_519_680) // two seconds of ServerRefill
					if expiry == "context" {
						wantTokens = 2_129_920 // half a second of ServerRefill
					}
					if got := h.tokens("victim"); got != wantTokens {
						t.Errorf("refusal refunded the work charge: %d tokens, want %d", got, wantTokens)
					}
					victim.Release()
					follower.Release()
					blocker.Release()
					if s := h.l.Snapshot(); s.InUse != 0 || s.Inflight != 0 || s.WaitingBytes != 0 {
						t.Errorf("terminal accounting: %+v", s)
					}
				})
			}
		}
	}
}

// An admission signal is provisional until Decode arbitrates its result.
// Cancellation, expiry or Release before that arbitration must not return
// success, retain decode bytes or count the victim's declared bytes.
func TestQueuedDecodeResultExpiry(t *testing.T) {
	for _, class := range []batch.SpoolClass{batch.ClassFindings, batch.ClassRaw} {
		for _, expiry := range []string{"deadline", "context", "release"} {
			t.Run(class.String()+"/"+expiry, func(t *testing.T) {
				h := newHarness(t)
				clock := &waiterClock{fakeClock: h.clock}
				h.l.clock = clock
				blocker := h.receive("blocker", batch.ClassFindings)
				h.admit(blocker, 64<<20, 64<<20)
				defer blocker.Release()
				victim := h.receive("victim", class)
				defer victim.Release()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				resume := clock.gateNextTimer()
				defer resume()
				result := h.decodeAsync(ctx, victim, 64<<20, 64<<20)
				h.clock.Advance(500 * time.Millisecond)
				follower := h.receive("follower", class)
				defer follower.Release()
				followResult := h.decodeAsync(context.Background(), follower, 64<<20, 64<<20)
				blocker.Release()
				if s := h.l.Snapshot(); s.InUse != 172_529_280 || s.Waiting != 1 {
					t.Fatalf("setup did not reserve only the live head: %+v", s)
				}
				switch expiry {
				case "deadline":
					h.clock.Advance(1500 * time.Millisecond)
				case "context":
					cancel()
				case "release":
					victim.Release()
				}
				resume()
				r := h.result(result)
				wantUse, wantInflight := int64(172_529_280), 2
				if expiry == "release" {
					if !errors.Is(r.err, ErrState) {
						t.Errorf("released queued admission: %+v", r)
					}
					wantUse, wantInflight = 167_529_280, 1
				} else {
					assertWaiterRefused(t, h, victim, r, expiry == "context")
				}
				if s := h.l.Snapshot(); s.InUse != wantUse || s.Inflight != wantInflight || s.Waiting != 0 || s.WaitingBytes != 0 {
					t.Errorf("reservation rollback accounting: %+v", s)
					victim.Release() // finish the successor even when rollback is broken
				}
				if r := h.result(followResult); r.err != nil || r.d.Status != 0 || r.d.Finding != FindingOversize {
					t.Errorf("live successor after reservation rollback: %+v", r)
				}
				follower.Decoded(time.Microsecond)
				if top := h.l.Snapshot().TopDevices; len(top) != 1 || top[0].Device != "follower" || top[0].DeclaredBytes != 67_108_864 {
					t.Errorf("successful queued decode lost declared-byte attribution: %+v", top)
				}
				follower.Release()
				victim.Release()
				if s := h.l.Snapshot(); s.InUse != 0 || s.Inflight != 0 {
					t.Errorf("terminal accounting: %+v", s)
				}
			})
		}
	}
}

func assertWaiterRefused(t *testing.T, h *harness, ticket *Ticket, r decodeResult, canceled bool) {
	t.Helper()
	if canceled {
		if !errors.Is(r.err, context.Canceled) || r.d.Status != 0 {
			t.Errorf("canceled wait: %+v", r)
		}
	} else if r.err != nil || r.d.Status != 503 || (r.d.Reason != ReasonBudget && r.d.Reason != ReasonReserve) || r.d.RetryAfter < 5 || r.d.RetryAfter > 60 {
		t.Errorf("expired wait: %+v", r)
	}
	if r.d.Finding != FindingOversize {
		t.Errorf("lost oversize finding: %+v", r)
	}
	if s := h.l.Snapshot(); canceled && len(s.Refused) != 0 || !canceled && (len(s.Refused) != 1 || s.Refused[r.d.Reason] != 1) {
		t.Errorf("wait refusal counted incorrectly: %+v", s.Refused)
	}
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	if ticket.charge != 0 || ticket.entry.counters(h.l.minute(h.clock.Now()), counterBytes) != 0 {
		t.Errorf("refused waiter kept decode bytes or attribution: charge %d", ticket.charge)
	}
}
