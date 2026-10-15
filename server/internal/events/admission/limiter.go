package admission

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

// Reason names why a request was refused.
type Reason string

const (
	ReasonDeviceConcurrency Reason = "device_concurrency"
	ReasonDeviceRate        Reason = "device_rate"
	ReasonInflight          Reason = "inflight"
	ReasonBudget            Reason = "budget"
	ReasonReserve           Reason = "reserve"
	ReasonStorageTimeout    Reason = "storage_timeout"
	ReasonCommitLatency     Reason = "commit_latency"
	ReasonStoreUnavailable  Reason = "store_unavailable"
)

// Finding names evidence that a client is not an unmodified agent.
type Finding string

const (
	FindingOversize Finding = "oversize_frame"
	FindingRate     Finding = "rate"
)

// Decision is an admission outcome. Status 0 means admitted; otherwise it is
// 429 or 503 with RetryAfter in 5 through 60 seconds. Finding can accompany
// either outcome.
type Decision struct {
	Status     int
	RetryAfter int
	Reason     Reason
	Finding    Finding
}

// DeviceUsage attributes decode work to one device over the trailing ten minutes.
type DeviceUsage struct {
	Device         string
	DecodeTime     time.Duration
	DeclaredBytes  uint64
	OversizeFrames uint64
}

// Snapshot holds the limiter counters for metrics.
type Snapshot struct {
	Budget         int64
	InUse          int64
	Inflight       int
	Waiting        int
	WaitingBytes   int64
	Devices        int
	Refused        map[Reason]uint64
	OversizeFrames map[batch.SpoolClass]uint64
	Findings       uint64
	TopDevices     []DeviceUsage // at most 10, most decode time first
}

const (
	retryMin           = 5
	retryMax           = 60
	drainSeconds       = 10
	rateFindingLimit   = 20
	findingSuppression = 10 * time.Minute
	topDevices         = 10
	counterMinutes     = 10
	sweepPerCall       = 2
)

// Per-device counters, each ten one-minute buckets.
const (
	counterRate = iota
	counterBytes
	counterDecode // milliseconds
	counterOversize
	counterKinds
)

// deviceEntry is the per-device state, kept while the device holds a slot, its
// bucket is below capacity, a counter is nonzero or its finding suppression
// runs. Entries form a list ordered by last update for the idle sweep.
type deviceEntry struct {
	device        string
	prev, next    *deviceEntry
	slots         int
	tokens        uint64
	refilled      time.Time
	minute        int64
	suppressUntil int64 // UnixNano
	counts        [counterKinds][counterMinutes]uint32
}

func (e *deviceEntry) refill(now time.Time) {
	elapsed := now.Sub(e.refilled)
	e.refilled = now
	if elapsed <= 0 || e.tokens >= BucketCapacity {
		return
	}
	full := time.Duration((BucketCapacity*uint64(time.Second) + ServerRefill - 1) / ServerRefill)
	if elapsed >= full {
		e.tokens = BucketCapacity
		return
	}
	e.tokens = min(BucketCapacity, e.tokens+uint64(elapsed)*ServerRefill/uint64(time.Second))
}

func minuteOf(now time.Time) int64 {
	return now.Unix() / 60
}

// advance zeroes the buckets of minutes that left the ten-minute window.
func (e *deviceEntry) advance(now time.Time) {
	m := minuteOf(now)
	if m <= e.minute {
		return
	}
	if m-e.minute >= counterMinutes {
		e.counts = [counterKinds][counterMinutes]uint32{}
	} else {
		for k := e.minute + 1; k <= m; k++ {
			for i := range e.counts {
				e.counts[i][k%counterMinutes] = 0
			}
		}
	}
	e.minute = m
}

func (e *deviceEntry) add(now time.Time, kind int, n uint64) {
	e.advance(now)
	slot := &e.counts[kind][e.minute%counterMinutes]
	*slot = uint32(min(uint64(*slot)+n, math.MaxUint32))
}

// counters returns the trailing ten-minute sum of one counter.
func (e *deviceEntry) counters(now time.Time, kind int) uint64 {
	e.advance(now)
	var sum uint64
	for _, v := range e.counts[kind] {
		sum += uint64(v)
	}
	return sum
}

func (e *deviceEntry) idle(now time.Time) bool {
	if e.slots > 0 || now.UnixNano() < e.suppressUntil {
		return false
	}
	e.refill(now)
	if e.tokens < BucketCapacity {
		return false
	}
	e.advance(now)
	return e.counts == [counterKinds][counterMinutes]uint32{}
}

type waiter struct {
	ticket   *Ticket
	need     int64
	size     uint64
	done     chan struct{}
	admitted bool
	released bool
}

// Limiter is the per-process decode admission limiter. It holds no goroutines.
type Limiter struct {
	mu           sync.Mutex
	config       Config
	reserve      int64
	clock        Clock
	random       func() float64
	inUse        int64
	inflight     int
	queues       [2][]*waiter // 0: findings and audit; 1: raw, context and lineage
	waitingBytes int64
	devices      map[string]*deviceEntry
	head, tail   *deviceEntry
	drain        [drainSeconds]int64
	drainSecond  [drainSeconds]int64
	refused      map[Reason]uint64
	oversize     map[batch.SpoolClass]uint64
	findings     uint64
}

// Ticket tracks one request from Receive to Release.
type Ticket struct {
	l            *Limiter
	entry        *deviceEntry
	class        batch.SpoolClass
	charge       int64 // decode-phase bytes held after admission
	decodeCalled bool
	released     bool
	waiter       *waiter
}

// New validates c and returns a limiter. random returns values in [0, 1].
func New(c Config, clock Clock, random func() float64) (*Limiter, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if clock == nil || random == nil {
		return nil, fmt.Errorf("%w: nil clock or random source", ErrConfig)
	}
	return &Limiter{
		config:   c,
		reserve:  c.Budget / 4,
		clock:    clock,
		random:   random,
		devices:  make(map[string]*deviceEntry),
		refused:  make(map[Reason]uint64),
		oversize: make(map[batch.SpoolClass]uint64),
	}, nil
}

func priorityQueue(class batch.SpoolClass) int {
	if class == batch.ClassFindings || class == batch.ClassAudit {
		return 0
	}
	return 1
}

// Receive admits a request after authentication and header parsing, before any
// body byte. It never blocks. A refusal returns a nil ticket.
func (l *Limiter) Receive(device string, class batch.SpoolClass) (*Ticket, Decision, error) {
	if device == "" {
		return nil, Decision{}, ErrDevice
	}
	if class.String() == "" {
		return nil, Decision{}, fmt.Errorf("%w: spool class %d", ErrArgument, class)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	l.sweep(now)
	e := l.devices[device]
	if e != nil && e.slots >= PerDeviceInflight {
		l.refused[ReasonDeviceConcurrency]++
		return nil, Decision{Status: 429, RetryAfter: retryMin, Reason: ReasonDeviceConcurrency}, nil
	}
	// The in-flight invariant normally guarantees room for C; refusing when it
	// does not keeps the bytes in use within the budget.
	if l.inflight >= l.config.MaxInflight || l.inUse+CompressedWeight > l.config.Budget {
		l.refused[ReasonInflight]++
		return nil, Decision{Status: 503, RetryAfter: l.retryAfter(now, l.waitingBytes, CompressedWeight), Reason: ReasonInflight}, nil
	}
	if e == nil {
		e = &deviceEntry{device: device, tokens: BucketCapacity, refilled: now, minute: minuteOf(now)}
		l.devices[device] = e
	}
	l.touch(e)
	e.slots++
	l.inflight++
	l.inUse += CompressedWeight
	return &Ticket{l: l, entry: e, class: class}, Decision{}, nil
}

// Decode charges the device bucket the declared size, then waits at most
// DecodeWait, or until ctx ends, for H(w) + S(s) + T(s) bytes of budget. A
// refusal leaves the ticket in the receive phase. A canceled wait returns
// ctx.Err(). Decode may be called once per ticket.
func (t *Ticket) Decode(ctx context.Context, window, size uint64) (Decision, error) {
	weight, err := Weight(window, size)
	if err != nil {
		return Decision{}, err
	}
	l := t.l
	l.mu.Lock()
	if t.released || t.decodeCalled {
		l.mu.Unlock()
		return Decision{}, ErrState
	}
	t.decodeCalled = true
	now := l.clock.Now()
	l.sweep(now)
	e := t.entry
	l.touch(e)
	var finding Finding
	if size > SealingLimit || window > SealingLimit {
		e.add(now, counterOversize, 1)
		l.oversize[t.class]++
		finding = l.flag(e, now, FindingOversize)
	}
	e.refill(now)
	if e.tokens < size {
		l.refused[ReasonDeviceRate]++
		e.add(now, counterRate, 1)
		if finding == "" && e.counters(now, counterRate) > rateFindingLimit {
			finding = l.flag(e, now, FindingRate)
		}
		deficit := size - e.tokens
		retry := int(min(max((deficit+ServerRefill-1)/ServerRefill, retryMin), retryMax))
		l.mu.Unlock()
		return Decision{Status: 429, RetryAfter: retry, Reason: ReasonDeviceRate, Finding: finding}, nil
	}
	e.tokens -= size
	need := weight - CompressedWeight
	q := priorityQueue(t.class)
	if len(l.queues[q]) == 0 && l.fits(q, need) {
		l.admit(t, need, size, now)
		l.mu.Unlock()
		return Decision{Finding: finding}, nil
	}
	w := &waiter{ticket: t, need: need, size: size, done: make(chan struct{})}
	l.queues[q] = append(l.queues[q], w)
	l.waitingBytes += need
	t.waiter = w
	timer := l.clock.NewTimer(l.config.DecodeWait)
	l.mu.Unlock()

	canceled := false
	select {
	case <-w.done:
	case <-timer.C():
	case <-ctx.Done():
		canceled = true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	timer.Stop()
	if w.admitted {
		return Decision{Finding: finding}, nil
	}
	if w.released {
		return Decision{Finding: finding}, ErrState
	}
	now = l.clock.Now()
	l.unqueue(w)
	l.dispatch(now)
	if canceled {
		return Decision{Finding: finding}, ctx.Err()
	}
	reason := ReasonBudget
	if q == 1 && l.config.Budget-l.inUse-need >= 0 {
		reason = ReasonReserve
	}
	l.refused[reason]++
	return Decision{Status: 503, RetryAfter: l.retryAfter(now, l.waitingBytes, need), Reason: reason, Finding: finding}, nil
}

// Decoded adds a decode's duration to the device's attribution counters. It
// is ignored after Release.
func (t *Ticket) Decoded(d time.Duration) {
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.released || d <= 0 {
		return
	}
	now := l.clock.Now()
	l.sweep(now)
	l.touch(t.entry)
	t.entry.add(now, counterDecode, uint64(d/time.Millisecond))
}

// Release returns every byte and slot the ticket holds. It is idempotent and
// never blocks.
func (t *Ticket) Release() {
	l := t.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.released {
		return
	}
	now := l.clock.Now()
	l.sweep(now)
	t.released = true
	if w := t.waiter; w != nil {
		l.unqueue(w)
		w.released = true
		close(w.done)
	}
	freed := CompressedWeight + t.charge
	l.inUse -= freed
	l.inflight--
	t.entry.slots--
	l.touch(t.entry)
	l.recordDrain(now, freed)
	l.dispatch(now)
}

// Unavailable computes the 503 decision for a handler-level refusal of a
// request whose current charge is weight.
func (l *Limiter) Unavailable(reason Reason, weight int64) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	l.refused[reason]++
	return Decision{Status: 503, RetryAfter: l.retryAfter(now, l.waitingBytes, weight), Reason: reason}
}

// Snapshot returns the counters and the ten devices with the most decode time
// in the trailing ten minutes.
func (l *Limiter) Snapshot() Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	s := Snapshot{
		Budget:         l.config.Budget,
		InUse:          l.inUse,
		Inflight:       l.inflight,
		Waiting:        len(l.queues[0]) + len(l.queues[1]),
		WaitingBytes:   l.waitingBytes,
		Devices:        len(l.devices),
		Refused:        make(map[Reason]uint64, len(l.refused)),
		OversizeFrames: make(map[batch.SpoolClass]uint64, len(l.oversize)),
		Findings:       l.findings,
	}
	for k, v := range l.refused {
		s.Refused[k] = v
	}
	for k, v := range l.oversize {
		s.OversizeFrames[k] = v
	}
	for _, e := range l.devices {
		ms := e.counters(now, counterDecode)
		if ms == 0 {
			continue
		}
		u := DeviceUsage{Device: e.device, DecodeTime: time.Duration(ms) * time.Millisecond, DeclaredBytes: e.counters(now, counterBytes), OversizeFrames: e.counters(now, counterOversize)}
		if len(s.TopDevices) == topDevices && compareUsage(u, s.TopDevices[topDevices-1]) >= 0 {
			continue
		}
		i, _ := slices.BinarySearchFunc(s.TopDevices, u, compareUsage)
		s.TopDevices = slices.Insert(s.TopDevices, i, u)
		if len(s.TopDevices) > topDevices {
			s.TopDevices = s.TopDevices[:topDevices]
		}
	}
	return s
}

func compareUsage(a, b DeviceUsage) int {
	if c := cmp.Compare(b.DecodeTime, a.DecodeTime); c != 0 {
		return c
	}
	return cmp.Compare(a.Device, b.Device)
}

// fits reports whether need bytes fit the budget: the whole budget for the
// findings and audit queue, above the reserve for the others.
func (l *Limiter) fits(q int, need int64) bool {
	available := l.config.Budget - l.inUse - need
	if q == 0 {
		return available >= 0
	}
	return available >= l.reserve
}

func (l *Limiter) admit(t *Ticket, need int64, size uint64, now time.Time) {
	l.inUse += need
	t.charge = need
	t.entry.add(now, counterBytes, size)
}

// dispatch admits queue heads in priority order until neither head fits. A
// head that does not fit blocks only its own queue.
func (l *Limiter) dispatch(now time.Time) {
	for progressed := true; progressed; {
		progressed = false
		for q := range l.queues {
			for len(l.queues[q]) > 0 && l.fits(q, l.queues[q][0].need) {
				w := l.queues[q][0]
				l.unqueue(w)
				l.admit(w.ticket, w.need, w.size, now)
				w.admitted = true
				close(w.done)
				progressed = true
			}
		}
	}
}

func (l *Limiter) unqueue(w *waiter) {
	q := priorityQueue(w.ticket.class)
	if i := slices.Index(l.queues[q], w); i >= 0 {
		l.queues[q] = slices.Delete(l.queues[q], i, i+1)
		l.waitingBytes -= w.need
		w.ticket.waiter = nil
	}
}

// flag returns f unless the device's finding suppression runs, and starts it.
func (l *Limiter) flag(e *deviceEntry, now time.Time, f Finding) Finding {
	if now.UnixNano() < e.suppressUntil {
		return ""
	}
	e.suppressUntil = now.Add(findingSuppression).UnixNano()
	l.findings++
	return f
}

func (l *Limiter) recordDrain(now time.Time, freed int64) {
	sec := now.Unix()
	i := ((sec % drainSeconds) + drainSeconds) % drainSeconds
	if l.drainSecond[i] != sec {
		l.drainSecond[i], l.drain[i] = sec, 0
	}
	l.drain[i] += freed
}

// retryAfter returns the jittered 503 Retry-After: base =
// ceil((ahead + weight - available) / drain), where drain is the bytes released
// in the last ten seconds divided by ten, and 60 when nothing drained; the base
// is clamped to 5 through 60, multiplied by a factor in 0.8 through 1.2,
// rounded half up and clamped again.
func (l *Limiter) retryAfter(now time.Time, ahead, weight int64) int {
	sec := now.Unix()
	var released int64
	for i, s := range l.drainSecond {
		if s > sec-drainSeconds && s <= sec {
			released += l.drain[i]
		}
	}
	drain := released / drainSeconds
	base := int64(retryMax)
	if drain > 0 {
		need := ahead + weight - (l.config.Budget - l.inUse)
		base = retryMin
		if need > 0 {
			base = min(need/drain+min(need%drain, 1), retryMax)
		}
	}
	base = min(max(base, retryMin), retryMax)
	r := min(max(l.random(), 0), 1)
	jittered := math.Floor(float64(base)*(0.8+0.4*r) + 0.5)
	return int(min(max(jittered, retryMin), retryMax))
}

// touch moves e to the tail of the update-ordered list.
func (l *Limiter) touch(e *deviceEntry) {
	if l.tail == e {
		return
	}
	l.unlink(e)
	e.prev = l.tail
	if l.tail != nil {
		l.tail.next = e
	} else {
		l.head = e
	}
	l.tail = e
}

func (l *Limiter) unlink(e *deviceEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if l.head == e {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if l.tail == e {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

// sweep examines up to two entries at the head of the list, removing idle ones
// and moving the others to the tail, so idle entries leave and memory stays
// bounded by the devices active in the last ten minutes.
func (l *Limiter) sweep(now time.Time) {
	for range sweepPerCall {
		e := l.head
		if e == nil {
			return
		}
		if e.idle(now) {
			l.unlink(e)
			delete(l.devices, e.device)
			continue
		}
		l.touch(e)
	}
}
