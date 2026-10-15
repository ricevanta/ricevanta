// Package admission bounds how many event batch bodies one agent replica
// decodes at once. It charges each request a byte weight computed from the
// frame header before decompression, keeps a reserve for findings and audit
// batches, and limits each device's concurrency and declared decoded bytes.
package admission

import (
	"fmt"
	"time"
)

const (
	// CompressedWeight is C, the compressed buffer (wire.MaxCompressedBytes).
	CompressedWeight int64 = 5_000_000
	// MaxWeight is Weight(64 MiB, 64 MiB).
	MaxWeight         int64  = 167_529_280
	PerDeviceInflight        = 2
	BucketCapacity    uint64 = 64 << 20
	// AgentRate is the agent's upload bucket rate in bytes per second.
	AgentRate    uint64 = 4 << 20
	ServerRefill uint64 = AgentRate + AgentRate/64
	SealingLimit uint64 = 4 << 20
	// MinCharge is the least bucket charge of one request, taken at Receive.
	MinCharge uint64 = 128 << 10

	maxFrameBytes uint64 = 64 << 20 // EV-09 content and window ceiling
	historyFloor  uint64 = 1 << 10  // the decoder's MinWindowSize
	historyExtra  uint64 = 2 << 20
	constantT     uint64 = 4 << 20
	lineFactor    uint64 = 5
	lineCap       uint64 = 1 << 20
	minBudget     int64  = 256 << 20
	minInflight          = 4
	maxInflight          = 256
	defaultWait          = 2 * time.Second
)

// Weight returns C + H(w) + S(s) + T(s), the live-byte bound of one decode
// with effective window w and declared content size s:
// H(w) = v + min(v, 2 MiB) with v = max(w, 1 KiB), S(s) = s + s/4 and
// T(s) = 4 MiB + 5 * min(s, 1 MiB). Arguments above 64 MiB are ErrArgument.
func Weight(window, size uint64) (int64, error) {
	if window > maxFrameBytes || size > maxFrameBytes {
		return 0, fmt.Errorf("%w: window %d, size %d above %d", ErrArgument, window, size, maxFrameBytes)
	}
	v := max(window, historyFloor)
	h := v + min(v, historyExtra)
	s := size + size/4
	t := constantT + lineFactor*min(size, lineCap)
	return CompressedWeight + int64(h+s+t), nil
}

// Config holds the per-replica limits. Budget, MaxInflight and DecodeWait
// come from Defaults unless overridden.
type Config struct {
	MemoryLimit int64
	AgentOnly   bool
	Budget      int64
	MaxInflight int
	DecodeWait  time.Duration
}

// budgetCeiling is the role's fraction of the memory limit: one half for an
// agent-only process, else one quarter.
func budgetCeiling(memoryLimit int64, agentOnly bool) int64 {
	if agentOnly {
		return memoryLimit / 2
	}
	return memoryLimit / 4
}

// Defaults computes the default limits for a process memory limit.
func Defaults(memoryLimit int64, agentOnly bool) (Config, error) {
	budget := budgetCeiling(memoryLimit, agentOnly)
	if budget < minBudget {
		return Config{}, fmt.Errorf("%w: memory limit %d gives decode budget %d, below %d (agent only %v)", ErrConfig, memoryLimit, budget, minBudget, agentOnly)
	}
	inflight := int(min(max((budget-MaxWeight)/(2*CompressedWeight), minInflight), maxInflight))
	return Config{MemoryLimit: memoryLimit, AgentOnly: agentOnly, Budget: budget, MaxInflight: inflight, DecodeWait: defaultWait}, nil
}

func (c Config) validate() error {
	switch {
	case c.MemoryLimit <= 0:
		return fmt.Errorf("%w: memory limit %d", ErrConfig, c.MemoryLimit)
	case c.Budget < minBudget:
		return fmt.Errorf("%w: decode budget %d below %d", ErrConfig, c.Budget, minBudget)
	case c.Budget > budgetCeiling(c.MemoryLimit, c.AgentOnly):
		return fmt.Errorf("%w: decode budget %d above %d for memory limit %d (agent only %v)", ErrConfig, c.Budget, budgetCeiling(c.MemoryLimit, c.AgentOnly), c.MemoryLimit, c.AgentOnly)
	case c.MaxInflight < minInflight:
		return fmt.Errorf("%w: max in flight %d below %d", ErrConfig, c.MaxInflight, minInflight)
	case int64(c.MaxInflight) > (c.Budget-MaxWeight)/(2*CompressedWeight):
		return fmt.Errorf("%w: max in flight %d exceeds (budget %d - %d) / %d", ErrConfig, c.MaxInflight, c.Budget, MaxWeight, 2*CompressedWeight)
	case c.DecodeWait <= 0:
		return fmt.Errorf("%w: decode wait %s", ErrConfig, c.DecodeWait)
	}
	return nil
}
