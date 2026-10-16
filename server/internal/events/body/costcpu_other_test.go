//go:build !race && !linux

package body

import "testing"

type costCPUClock struct{}

func (*costCPUClock) read(*costCPUSample) error {
	return errorString("unsupported qualification CPU clock: Linux getrusage required")
}

func TestCostCPUUnsupportedClock(t *testing.T) {
	var clock costCPUClock
	sample := costCPUSample{1, 2}
	if err := clock.read(&sample); err == nil || sample != (costCPUSample{1, 2}) {
		t.Fatal("unsupported clock fabricated a sample")
	}
}
