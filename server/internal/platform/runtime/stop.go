package runtime

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/platform/health"
)

// stopController serializes budget publication, failure commitment and all
// resource/readiness handoffs. No I/O or cleanup runs under mu.
type stopController struct {
	terminal        *int
	step            string
	mu              sync.Mutex
	stopped         chan struct{}
	cancelled       func() bool
	parentCancelled func() bool
	parentSeen      bool
	now             func() time.Time
	budget          time.Duration
	first, deadline time.Time
	repeated        int
	signals         int
	failure         int
	registry        *health.Registry
	listener        net.Listener
	server          *http.Server
}

func newStopController(parent context.Context) *stopController {
	done := parent.Done()
	cancelled := func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	return &stopController{stopped: make(chan struct{}), cancelled: cancelled, parentCancelled: cancelled, now: time.Now, budget: 20 * time.Second}
}
func (c *stopController) latch() {
	if !c.first.IsZero() {
		return
	}
	c.first = c.now()
	c.deadline = c.first.Add(c.budget)
	close(c.stopped)
}
func (c *stopController) request() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.first.IsZero() {
		c.repeated++
		return
	}
	c.latch()
}
func (c *stopController) countSignal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signals++
	if c.signals > 1 || c.parentSeen {
		c.repeated++
	}
	c.latch()
}
func (c *stopController) stoppedLocked() bool {
	if c.parentCancelled() && !c.parentSeen {
		c.parentSeen = true
		if !c.first.IsZero() {
			c.repeated++
		}
		c.latch()
	}
	if c.cancelled() {
		c.latch()
	}
	return !c.first.IsZero()
}
func (c *stopController) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stoppedLocked()
}
func (c *stopController) publish(b time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stoppedLocked() {
		c.budget = b
	}
}
func (c *stopController) handoff(f func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stoppedLocked() {
		return false
	}
	f()
	return true
}
func (c *stopController) commitFailure(code int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stoppedLocked() {
		return false
	}
	c.failure = code
	return true
}
func (c *stopController) failureCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failure
}
func (c *stopController) repeatCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.repeated
}

func (c *stopController) stepName() string { c.mu.Lock(); defer c.mu.Unlock(); return c.step }

// finish commits the terminal outcome at the graceful cutoff. Later worker
// results cannot change a timeout into success during the finalization reserve.
func (c *stopController) finish(allDone bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return *c.terminal
	}
	code := c.failure
	if !allDone || !c.now().Before(c.deadline.Add(-100*time.Millisecond)) {
		code = ExitFailure
	}
	c.terminal = &code
	return code
}
func (c *stopController) observeCancellation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stoppedLocked()
}
