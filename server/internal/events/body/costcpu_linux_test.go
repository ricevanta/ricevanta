//go:build !race && linux

package body

import (
	"syscall"
	"testing"
)

type costCPUClock struct{ usage syscall.Rusage }

func (c *costCPUClock) read(out *costCPUSample) error { return c.readWith(out, syscall.Getrusage) }
func (c *costCPUClock) readWith(out *costCPUSample, get func(int, *syscall.Rusage) error) error {
	if err := get(syscall.RUSAGE_SELF, &c.usage); err != nil {
		return err
	}
	user, err := costCPUTimeval(c.usage.Utime.Sec, c.usage.Utime.Usec)
	if err != nil {
		return err
	}
	system, err := costCPUTimeval(c.usage.Stime.Sec, c.usage.Stime.Usec)
	if err != nil {
		return err
	}
	next := costCPUSample{user, system}
	if _, err := costCPUSum(next); err != nil {
		return err
	}
	*out = next
	return nil
}
func TestCostCPUInjectedClock(t *testing.T) {
	var clock costCPUClock
	out := costCPUSample{8, 9}
	calls := 0
	get := func(who int, usage *syscall.Rusage) error {
		calls++
		if who != syscall.RUSAGE_SELF || usage != &clock.usage {
			t.Fatal("wrong scope or storage")
		}
		usage.Utime.Sec = 1
		usage.Utime.Usec = 2
		usage.Stime.Usec = 3
		return nil
	}
	for range 2 {
		if err := clock.readWith(&out, get); err != nil || out != (costCPUSample{1000002000, 3000}) {
			t.Fatalf("%+v %v", out, err)
		}
	}
	sentinel := errorString("injected syscall failure")
	if err := clock.readWith(&out, func(int, *syscall.Rusage) error { return sentinel }); err != sentinel {
		t.Fatalf("lost failure: %v", err)
	}
	if calls != 2 || out != (costCPUSample{1000002000, 3000}) {
		t.Fatal("fallback or partial write")
	}
	if err := clock.readWith(&out, func(_ int, r *syscall.Rusage) error { r.Utime.Usec = 1000000; return nil }); err == nil {
		t.Fatal("noncanonical timeval accepted")
	}
}
