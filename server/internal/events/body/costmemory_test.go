package body

import (
	"runtime/metrics"
	"sync/atomic"
	"testing"
)

// distinctCostMemorySamples rejects aliasing before either owner starts a read.
func distinctCostMemorySamples(a, b *costMemorySamples) bool {
	return a != nil && b != nil && &a[0] != &b[0] && &a[1] != &b[1]
}

func TestCostMemorySamples(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		var peak atomic.Uint64
		peak.Store(17)
		a, b := newCostMemorySampler(&peak), newCostMemorySampler(&peak)
		if a.peak != &peak || b.peak != &peak || peak.Load() != 17 {
			t.Fatal("constructor changed peak ownership or value")
		}
		for _, owner := range []*costMemorySampler{a, b} {
			if len(owner.samples) != 2 || owner.samples[0].Name != "/memory/classes/total:bytes" || owner.samples[1].Name != "/memory/classes/heap/released:bytes" {
				t.Fatalf("unexpected samples: %#v", owner.samples)
			}
			for _, sample := range owner.samples {
				if sample.Value.Kind() != metrics.KindBad {
					t.Fatal("constructor populated a metric value")
				}
			}
		}
		if !distinctCostMemorySamples(&a.samples, &b.samples) {
			t.Fatal("owners share backing storage")
		}
		if distinctCostMemorySamples(&a.samples, &a.samples) {
			t.Fatal("shared-pointer negative control accepted")
		}
	})
	t.Run("reuse-snapshot-and-peer", func(t *testing.T) {
		var peak atomic.Uint64
		a, b := newCostMemorySampler(&peak), newCostMemorySampler(&peak)
		if !distinctCostMemorySamples(&a.samples, &b.samples) {
			t.Fatal("owners share backing storage")
		}
		first, second := &a.samples[0], &a.samples[1]
		check := func(samples *costMemorySamples, got uint64) {
			t.Helper()
			if got != samples[0].Value.Uint64()-samples[1].Value.Uint64() {
				t.Fatal("result differs from the filled snapshot")
			}
			if samples[0].Name != "/memory/classes/total:bytes" || samples[1].Name != "/memory/classes/heap/released:bytes" {
				t.Fatal("read changed metric names")
			}
		}
		check(&a.samples, a.samples.usedMemory())
		before := a.samples
		check(&b.samples, b.samples.usedMemory())
		if a.samples != before {
			t.Fatal("peer read mutated owner samples")
		}
		check(&a.samples, a.samples.usedMemory())
		if &a.samples[0] != first || &a.samples[1] != second {
			t.Fatal("repeated read replaced backing storage")
		}
	})
	t.Run("atomic-maximum", func(t *testing.T) {
		var peak atomic.Uint64
		owner := newCostMemorySampler(&peak)
		owner.sample()
		if used := owner.samples[0].Value.Uint64() - owner.samples[1].Value.Uint64(); peak.Load() != used {
			t.Fatal("sample did not update peak to its snapshot")
		}
		peak.Store(^uint64(0))
		owner.sample()
		if peak.Load() != ^uint64(0) {
			t.Fatal("sample reset a larger seeded maximum")
		}
	})
	t.Run("concurrent-owners", func(t *testing.T) {
		var peak atomic.Uint64
		a, b := newCostMemorySampler(&peak), newCostMemorySampler(&peak)
		if !distinctCostMemorySamples(&a.samples, &b.samples) || distinctCostMemorySamples(&a.samples, &a.samples) {
			t.Fatal("invalid ownership before concurrent reads")
		}
		start := make(chan struct{})
		done := make(chan struct{}, 2)
		go func() { <-start; a.sample(); done <- struct{}{} }()
		go func() { <-start; b.sample(); done <- struct{}{} }()
		close(start)
		<-done
		<-done
		av := a.samples[0].Value.Uint64() - a.samples[1].Value.Uint64()
		bv := b.samples[0].Value.Uint64() - b.samples[1].Value.Uint64()
		if peak.Load() != max(av, bv) {
			t.Fatal("concurrent peak differs from the maximum owner snapshot")
		}
	})
}

// costMemorySamples belongs to one reader for its entire lifetime.
type costMemorySamples [2]metrics.Sample

// costMemorySampler owns its sample backing and shares only the peak atomic.
type costMemorySampler struct {
	samples costMemorySamples
	peak    *atomic.Uint64
}

//go:noinline
func newCostMemorySampler(peak *atomic.Uint64) *costMemorySampler {
	return &costMemorySampler{
		samples: costMemorySamples{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}},
		peak:    peak,
	}
}

func (samples *costMemorySamples) usedMemory() uint64 {
	metrics.Read(samples[:])
	return samples[0].Value.Uint64() - samples[1].Value.Uint64()
}

func (sampler *costMemorySampler) sample() {
	used := sampler.samples.usedMemory()
	for {
		old := sampler.peak.Load()
		if used <= old || sampler.peak.CompareAndSwap(old, used) {
			return
		}
	}
}
