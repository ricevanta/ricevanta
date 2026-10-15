package admission

import (
	"errors"
	"testing"
)

const (
	kib = 1 << 10
	mib = 1 << 20
)

func TestWeightTable(t *testing.T) {
	for _, c := range []struct {
		name         string
		window, size uint64
		want         int64
	}{
		{"maximal", 64 * mib, 64 * mib, 167_529_280},
		{"largest-legitimate", 4 * mib, 4 * mib, 25_971_520},
		{"small-single-segment", 10 * kib, 10 * kib, 9_278_784},
		// H: v = max(w, 1 KiB), H = v + min(v, 2 MiB). Size 0 gives S = 0, T = 4 MiB.
		{"H-window-0", 0, 0, 5_000_000 + 2*kib + 4*mib},
		{"H-window-100", 100, 0, 5_000_000 + 2*kib + 4*mib},
		{"H-window-1023", 1023, 0, 5_000_000 + 2*kib + 4*mib},
		{"H-window-1KiB", kib, 0, 5_000_000 + 2*kib + 4*mib},
		{"H-window-1KiB+1", kib + 1, 0, 5_000_000 + 2*kib + 2 + 4*mib},
		{"H-window-1MiB", mib, 0, 5_000_000 + 2*mib + 4*mib},
		{"H-window-2MiB-1", 2*mib - 1, 0, 5_000_000 + 4*mib - 2 + 4*mib},
		{"H-window-2MiB", 2 * mib, 0, 5_000_000 + 4*mib + 4*mib},
		{"H-window-64MiB", 64 * mib, 0, 5_000_000 + 66*mib + 4*mib},
		// S = s + s/4 with integer division; T = 4 MiB + 5 * min(s, 1 MiB). Window 0 gives H = 2 KiB.
		{"S-size-3", 0, 3, 5_000_000 + 2*kib + 3 + 4*mib + 15},
		{"S-size-4", 0, 4, 5_000_000 + 2*kib + 5 + 4*mib + 20},
		{"T-size-1MiB-1", 0, mib - 1, 5_000_000 + 2*kib + (mib - 1) + (mib-1)/4 + 4*mib + 5*(mib-1)},
		{"T-size-1MiB", 0, mib, 5_000_000 + 2*kib + mib + mib/4 + 9*mib},
		{"T-size-64MiB", 0, 64 * mib, 5_000_000 + 2*kib + 80*mib + 9*mib},
	} {
		got, err := Weight(c.window, c.size)
		if err != nil || got != c.want {
			t.Fatalf("%s: Weight(%d, %d) = %d, %v; want %d", c.name, c.window, c.size, got, err, c.want)
		}
	}
	if MaxWeight != 167_529_280 || CompressedWeight != 5_000_000 {
		t.Fatal("constants")
	}
	for _, c := range [][2]uint64{{64*mib + 1, 0}, {0, 64*mib + 1}, {64*mib + 1, 64*mib + 1}, {^uint64(0), ^uint64(0)}} {
		if got, err := Weight(c[0], c[1]); !errors.Is(err, ErrArgument) || got != 0 {
			t.Fatalf("Weight(%d, %d) = %d, %v", c[0], c[1], got, err)
		}
	}
}

func TestDefaults(t *testing.T) {
	const limit36 = 3_865_470_566 // 3.6 GiB, 0.9 of a 4 GiB container
	for _, c := range []struct {
		memory    int64
		agentOnly bool
		budget    int64
		inflight  int
	}{
		{limit36, false, 966_367_641, 79},
		{limit36, true, 1_932_735_283, 176},
		{512 * mib, true, 256 * mib, 10},
		{1 << 30, false, 256 * mib, 10},
		{1 << 30, true, 512 * mib, 36},
		{64 << 30, true, 32 << 30, 256},
	} {
		got, err := Defaults(c.memory, c.agentOnly)
		if err != nil || got.Budget != c.budget || got.MaxInflight != c.inflight || got.DecodeWait != 2e9 || got.MemoryLimit != c.memory || got.AgentOnly != c.agentOnly {
			t.Fatalf("Defaults(%d, %v) = %+v, %v", c.memory, c.agentOnly, got, err)
		}
		if _, err := New(got, newFakeClock(), func() float64 { return 0.5 }); err != nil {
			t.Fatalf("New(Defaults(%d, %v)): %v", c.memory, c.agentOnly, err)
		}
	}
	for _, c := range []struct {
		memory    int64
		agentOnly bool
	}{
		{512*mib - 1, true}, {1<<30 - 1, false}, {512 * mib, false}, {0, true}, {-1, false},
	} {
		if _, err := Defaults(c.memory, c.agentOnly); !errors.Is(err, ErrConfig) {
			t.Fatalf("Defaults(%d, %v): %v", c.memory, c.agentOnly, err)
		}
	}
}

func TestNewRejectsConfig(t *testing.T) {
	clock := newFakeClock()
	random := func() float64 { return 0.5 }
	base := Config{MemoryLimit: 1 << 30, AgentOnly: true, Budget: 512 * mib, MaxInflight: 10, DecodeWait: 2e9}
	if _, err := New(base, clock, random); err != nil {
		t.Fatal(err)
	}
	allRoles := Config{MemoryLimit: 2 << 30, Budget: 512 * mib, MaxInflight: 10, DecodeWait: 2e9}
	if _, err := New(allRoles, clock, random); err != nil {
		t.Fatal(err)
	}
	odd := Config{MemoryLimit: 1<<30 + 6, AgentOnly: true, Budget: (1<<30 + 6) / 2, MaxInflight: 10, DecodeWait: 2e9}
	if _, err := New(odd, clock, random); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"budget-below-256MiB":         func(c *Config) { c.Budget = 256*mib - 1; c.MaxInflight = 4 },
		"budget-above-half":           func(c *Config) { c.Budget = 512*mib + 1 },
		"budget-above-half-odd":       func(c *Config) { *c = odd; c.Budget++ },
		"budget-above-quarter":        func(c *Config) { *c = allRoles; c.Budget++ },
		"all-roles-at-half":           func(c *Config) { c.AgentOnly = false },
		"inflight-below-4":            func(c *Config) { c.MaxInflight = 3 },
		"inflight-invariant":          func(c *Config) { c.MaxInflight = 37 },
		"inflight-invariant-smallest": func(c *Config) { c.Budget = 256 * mib; c.MaxInflight = 11 },
		"zero-wait":                   func(c *Config) { c.DecodeWait = 0 },
		"negative-wait":               func(c *Config) { c.DecodeWait = -1 },
		"zero-memory":                 func(c *Config) { c.MemoryLimit = 0 },
	} {
		c := base
		change(&c)
		if l, err := New(c, clock, random); !errors.Is(err, ErrConfig) || l != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	c := base
	c.Budget, c.MaxInflight = 256*mib, 10
	if _, err := New(c, clock, random); err != nil {
		t.Fatalf("smallest budget with 10 in flight: %v", err)
	}
	if _, err := New(base, nil, random); !errors.Is(err, ErrConfig) {
		t.Fatal("nil clock accepted")
	}
	if _, err := New(base, clock, nil); !errors.Is(err, ErrConfig) {
		t.Fatal("nil random accepted")
	}
}
