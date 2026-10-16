package admission

import "time"

// Clock supplies time and wait timers; tests inject a fake clock.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is a stoppable one-shot timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// SystemClock returns a Clock backed by package time.
func SystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.t.C }

func (t systemTimer) Stop() bool { return t.t.Stop() }
