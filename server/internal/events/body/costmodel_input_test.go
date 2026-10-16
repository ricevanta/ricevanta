package body

import (
	"testing"

	"github.com/klauspost/compress/zstd"
)

// The small qualification inputs must encode the specified 103-byte record.
// Hardcoding that size into a replacement header cannot repair a shorter
// payload: it changes the intended accepted/checksum stage into a size error.
func TestAdversarialSmallCostInputs(t *testing.T) {
	for _, tc := range []struct {
		key    string
		window uint64
	}{
		{"blocks-min-at", 103},
		{"blocks-min-over", 103},
		{"blocks-min-ceiling", 103},
		{"small-window64", 64 << 20},
		{"small-window64-checksum", 64 << 20},
		{"concurrent-small-window64", 64 << 20},
	} {
		t.Run(tc.key, func(t *testing.T) {
			c := adversarialCostInput(t, tc.key)
			var h zstd.Header
			if err := h.Decode(c.frame); err != nil {
				t.Fatal(err)
			}
			window := h.WindowSize
			if h.SingleSegment {
				window = h.FrameContentSize
			}
			if !h.HasFCS || h.FrameContentSize != 103 || window != tc.window || c.size != 103 || c.window != tc.window {
				t.Errorf("qualification metadata: frame size=%d window=%d; charged size=%d window=%d; want size=103 window=%d", h.FrameContentSize, window, c.size, c.window, tc.window)
			}
			checkCostInput(t, c)
		})
	}
}
