//go:build !race

package body

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestDecodePeakMemory(t *testing.T) {
	name := os.Getenv("RICEVANTA_BODY_MEMORY_CASE")
	if name == "" {
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"decoded-bytes-67108864", "bomb-claimed-1GiB", "bomb-small-claim"} {
			t.Run(name, func(t *testing.T) {
				cmd := exec.Command(exe, "-test.run=^TestDecodePeakMemory$", "-test.v")
				cmd.Env = append(os.Environ(), "RICEVANTA_BODY_MEMORY_CASE="+name, "GOGC=100", "GOMEMLIMIT=off")
				output, e := cmd.CombinedOutput()
				t.Logf("%s", output)
				if e != nil {
					t.Fatal(e)
				}
			})
		}
		return
	}
	f := loadFixtures(t)
	var chosen *bodyFixture
	for i := range f.Cases {
		if f.Cases[i].Name == name {
			chosen = &f.Cases[i]
			break
		}
	}
	if chosen == nil {
		t.Fatal("unknown memory fixture")
	}
	data, e := chosen.body()
	if e != nil {
		t.Fatal(e)
	}
	d, e := chosen.descriptor()
	if e != nil {
		t.Fatal(e)
	}
	device := chosen.Device
	want := batchSentinel(chosen.Expected.Error)
	f = fixtureFile{}
	chosen = nil
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	baseline := stats.HeapInuse
	peak := baseline
	var mu sync.Mutex
	sample := func() {
		var s runtime.MemStats
		runtime.ReadMemStats(&s)
		mu.Lock()
		peak = max(peak, s.HeapInuse)
		mu.Unlock()
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sample()
			case <-done:
				return
			}
		}
	}()
	sample()
	lines, e := Decode(&io.LimitedReader{R: bytes.NewReader(data), N: remainingBudget}, d, device)
	sample()
	runtime.KeepAlive(lines)
	close(done)
	<-finished
	if !errors.Is(e, want) || e != nil && lines != nil {
		t.Fatalf("result=%v want=%v", e, want)
	}
	t.Logf("%s baseline=%d maximum=%d delta=%d", name, baseline, peak, peak-baseline)
	if peak > baseline+512*1024*1024 {
		t.Fatal("sampled peak heap exceeds budget")
	}
}
