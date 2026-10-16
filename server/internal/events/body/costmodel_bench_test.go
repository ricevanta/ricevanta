package body

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ricevanta/ricevanta/server/internal/events/admission"
	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

// costShape is one generated measurement input of ingest admission section 1.
// These are measurement inputs, not contract fixtures.
type costShape struct {
	name    string
	plain   func() []byte
	single  bool // single segment; otherwise a 4 MiB window
	badID   bool // every line fails eventid.Parse
	hostile bool // a non-flat maximal shape for the CPU ratio
	flat    bool // a flat shape for the CPU ratio
}

type costCase struct {
	shape string
	n     int
}

func (c costCase) key() string {
	for _, key := range adversarialCostKeys {
		if key == c.shape {
			return key
		}
	}
	return c.shape + "/" + itoa(c.n)
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

const costMiB = 1 << 20

func costShapes() []costShape {
	maximal := func(gen func(int, int) []byte) func() []byte {
		return func() []byte { return gen(64, costMiB) }
	}
	shapes := []costShape{
		{name: "flat-64x1MiB-single", plain: maximal(genFlat), single: true, flat: true},
		{name: "nested-64x1MiB-single", plain: maximal(genNested), single: true, hostile: true},
		{name: "dense-64x1MiB-single", plain: maximal(genDense), single: true, hostile: true},
		{name: "densenested-64x1MiB-single", plain: maximal(genDenseNested), single: true, hostile: true},
		{name: "arrayobjs-64x1MiB-single", plain: maximal(genArrayObjs), single: true, hostile: true},
		{name: "singlechar-64x1MiB-single", plain: maximal(genSingleChar), single: true, hostile: true},
		{name: "random3-64x1MiB-single", plain: maximal(genRandom3), single: true, hostile: true},
		{name: "prefix-64x1MiB-single", plain: maximal(genPrefix), single: true, hostile: true},
		{name: "numbers-64x1MiB-single", plain: maximal(genNumbers), single: true, hostile: true},
		{name: "strings-64x1MiB-single", plain: maximal(genStrings), single: true, hostile: true},
		{name: "round-2047x32769-single", plain: func() []byte { return genFlat(2047, 32770) }, single: true, flat: true},
		{name: "round-10000x5377-single", plain: func() []byte { return genFlat(10000, 5378) }, single: true, flat: true},
		{name: "flat-10000x6710-single", plain: func() []byte { return genFlat(10000, 6710) }, single: true, flat: true},
		{name: "badid-10000-single", plain: func() []byte { return genBadID(10000) }, single: true, badID: true},
		{name: "minok-10000-single", plain: func() []byte { return genMinOK(10000) }, single: true},
		{name: "realistic-2000-win4", plain: func() []byte { return genRealistic(2000) }},
		{name: "realistic-5000-win4", plain: func() []byte { return genRealistic(5000) }},
		{name: "realistic-10000-win4", plain: func() []byte { return genRealistic(10000) }},
		{name: "dense-4x1MiB-win4", plain: func() []byte { return genDense(4, costMiB) }},
	}
	for _, mib := range []int{1, 4, 16, 64} {
		lines := mib
		if mib != 64 {
			shapes = append(shapes, costShape{name: "flat-" + itoa(mib) + "x1MiB-single", plain: func() []byte { return genFlat(lines, costMiB) }, single: true, flat: true})
		}
		shapes = append(shapes, costShape{name: "flat-" + itoa(mib) + "x1MiB-win4", plain: func() []byte { return genFlat(lines, costMiB) }, flat: true})
	}
	return shapes
}

// costCases lists one decode of every shape, then the concurrent cases of
// ingest admission section 9.
func costCases() []costCase {
	var cases []costCase
	for _, s := range costShapes() {
		cases = append(cases, costCase{s.name, 1})
	}
	cases = append(cases,
		costCase{"flat-64x1MiB-single", 4},
		costCase{"round-2047x32769-single", 4},
		costCase{"arrayobjs-64x1MiB-single", 4},
		costCase{"singlechar-64x1MiB-single", 4},
		costCase{"random3-64x1MiB-single", 4},
		costCase{"badid-10000-single", 8},
		costCase{"realistic-5000-win4", 8},
		costCase{"dense-4x1MiB-win4", 16},
	)
	for _, key := range adversarialCostKeys {
		n := 1
		if key == "concurrent-small-window64" {
			n = 16
		}
		if key == "concurrent-blocks64" {
			n = 4
		}
		cases = append(cases, costCase{key, n})
	}
	return cases
}

// encodeCostFrame encodes with the pinned encoder at level 3 with a checksum,
// as a single segment or with a 4 MiB window.
func encodeCostFrame(t testing.TB, plain []byte, single bool) []byte {
	t.Helper()
	options := []zstd.EOption{zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(1), zstd.WithZeroFrames(true), zstd.WithSingleSegment(single)}
	if single {
		options = append(options, zstd.WithWindowSize(64*costMiB))
	} else {
		options = append(options, zstd.WithWindowSize(4*costMiB))
	}
	encoder, err := zstd.NewWriter(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	frame := encoder.EncodeAll(plain, nil)
	f, err := ReadFrame(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget})
	if err != nil {
		t.Fatalf("generated frame rejected: %v", err)
	}
	if f.ContentSize() != uint64(len(plain)) {
		t.Fatalf("content size %d for %d bytes", f.ContentSize(), len(plain))
	}
	return frame
}

func costDescriptor(lines int) batch.Descriptor {
	return batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, FirstSequence: 0, LastSequence: uint64(lines - 1), RecordCount: uint32(lines)}
}

// BenchmarkDecodeCost reports time, bytes and allocations per decode of every
// cost-model shape.
func BenchmarkDecodeCost(b *testing.B) {
	for _, key := range adversarialCostKeys {
		b.Run(key, func(b *testing.B) {
			c := adversarialCostInput(b, key)
			checkCostInput(b, c)
			b.ReportAllocs()
			b.SetBytes(int64(len(c.frame)))
			b.ResetTimer()
			for b.Loop() {
				checkCostInput(b, c)
			}
		})
	}

	for _, s := range costShapes() {
		b.Run(s.name, func(b *testing.B) {
			plain := s.plain()
			lines := bytes.Count(plain, []byte{'\n'})
			frame := encodeCostFrame(b, plain, s.single)
			d := costDescriptor(lines)
			b.ReportAllocs()
			b.SetBytes(int64(len(plain)))
			plain = nil
			b.ResetTimer()
			for b.Loop() {
				got, err := Decode(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget}, d, "device-a")
				if err != nil || len(got) != lines {
					b.Fatalf("decode: %v, %d lines", err, len(got))
				}
			}
		})
	}
}

// adversarialCostKeys is the literal rejection/accepted-block corpus of section 9.
var adversarialCostKeys = []string{
	"blocks-min-at", "blocks-min-over", "blocks-min-ceiling", "blocks-4m-at", "blocks-4m-over",
	"blocks-64m-at", "blocks-64m-over", "small-window64", "small-window64-checksum",
	"malformed-entropy", "late-checksum64", "size-lie-small", "preflight-ceiling",
	"preflight-rate-deficit", "concurrent-small-window64", "concurrent-blocks64",
}

type costInput struct {
	frame                 []byte
	window, size          uint64
	lines, blocks, codecs int
	want                  error
	rateDeficit           bool
}

// paddedCostFrame inserts empty raw blocks immediately before the last block.
// The checksum still describes the same output. Header offsets come from an
// independent test parser, rather than production preflight.
func paddedCostFrame(t testing.TB, frame []byte, count int) []byte {
	t.Helper()
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		t.Fatal(err)
	}
	pos := h.HeaderSize
	blocks := 0
	for {
		start := pos
		v := uint32(frame[pos]) | uint32(frame[pos+1])<<8 | uint32(frame[pos+2])<<16
		pos += 3
		blocks++
		stored := int(v >> 3)
		if (v>>1)&3 == 1 {
			stored = 1
		}
		pos += stored
		if v&1 != 0 {
			if blocks > count {
				t.Fatalf("encoder used %d blocks above %d", blocks, count)
			}
			out := bytes.Clone(frame[:start])
			out = append(out, make([]byte, 3*(count-blocks))...)
			return append(out, frame[start:]...)
		}
	}
}

func adversarialCostInput(t testing.TB, key string) costInput {
	t.Helper()
	c := costInput{window: 128 << 10, size: 103, lines: 1, blocks: 2, codecs: 1}
	small := func() []byte { return encodeCostFrame(t, genMinOK(1), true) }
	switch key {
	case "blocks-min-at", "blocks-min-over", "blocks-min-ceiling":
		c.window = 103
		c.frame = paddedCostFrame(t, small(), 2)
		if key != "blocks-min-at" {
			c.frame = paddedCostFrame(t, small(), 3)
			c.blocks = 3
			c.codecs = 0
			c.want = ErrFrame
			if key == "blocks-min-ceiling" {
				c.frame = append(c.frame, make([]byte, int(compressedBudget)-1-len(c.frame))...)
			}
		}
	case "blocks-4m-at", "blocks-4m-over", "blocks-64m-at", "blocks-64m-over", "late-checksum64", "concurrent-blocks64":
		mib := 64
		if strings.HasPrefix(key, "blocks-4m") {
			mib = 4
		}
		c.size = uint64(mib * costMiB)
		c.window = c.size
		c.lines = mib
		c.blocks = 1 + mib*8
		c.frame = paddedCostFrame(t, encodeCostFrame(t, genFlat(mib, costMiB), true), c.blocks)
		if strings.HasSuffix(key, "-over") {
			c.frame = paddedCostFrame(t, c.frame, c.blocks+1)
			c.blocks++
			c.codecs = 0
			c.want = ErrFrame
		}
		if key == "late-checksum64" {
			c.frame[len(c.frame)-1] ^= 1
			c.want = ErrChecksum
		}
	case "small-window64", "small-window64-checksum", "concurrent-small-window64":
		// Replace the single-segment header with a four-byte size and 64 MiB window.
		f := small()
		var h zstd.Header
		if err := h.Decode(f); err != nil {
			t.Fatal(err)
		}
		c.frame = append([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x84, 0x80, 103, 0, 0, 0}, f[h.HeaderSize:]...)
		c.window = 64 << 20
		c.blocks = 1
		if key == "small-window64-checksum" {
			c.frame[len(c.frame)-1] ^= 1
			c.want = ErrChecksum
		}
	case "malformed-entropy":
		c.frame = rawFrame(103, 0xc4, 0x38, nil)[:14]
		v := uint32(128<<10)<<3 | 5
		c.frame = append(c.frame, byte(v), byte(v>>8), byte(v>>16))
		c.frame = append(c.frame, make([]byte, 128<<10+4)...)
		c.blocks = 1
		c.want = ErrFrame
	case "size-lie-small":
		f := encodeCostFrame(t, genFlat(1, 104), true)
		var h zstd.Header
		if err := h.Decode(f); err != nil {
			t.Fatal(err)
		}
		c.frame = append([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x84, 0x38, 103, 0, 0, 0}, f[h.HeaderSize:]...)
		c.blocks = 1
		c.want = ErrContentSize
	case "preflight-ceiling", "preflight-rate-deficit":
		// 38 legal maximum-size compressed blocks, then a final short block or
		// truncated header, fill the receive allowance without triggering overflow.
		c.size = 64 << 20
		c.window = 64 << 20
		c.lines = 64
		c.codecs = 0
		c.blocks = 513
		c.frame = rawFrame(c.size, 0xc4, 0x80, nil)[:14]
		for range 38 {
			v := uint32(128<<10)<<3 | 4
			c.frame = append(c.frame, byte(v), byte(v>>8), byte(v>>16))
			c.frame = append(c.frame, make([]byte, 128<<10)...)
		}
		c.frame = append(c.frame, make([]byte, 3*(512-38))...)
		if key == "preflight-ceiling" {
			c.frame = append(c.frame, 0, 0)
			c.blocks = 512
			c.want = ErrFrame
		} else {
			length := int(compressedBudget) - 1 - len(c.frame) - 7
			v := uint32(length)<<3 | 5
			c.frame = append(c.frame, byte(v), byte(v>>8), byte(v>>16))
			c.frame = append(c.frame, make([]byte, length+4)...)
			c.rateDeficit = true
		}
	default:
		t.Fatalf("unknown adversarial key %s", key)
	}
	return c
}

func TestAdversarialCostCorpus(t *testing.T) {
	for _, key := range adversarialCostKeys {
		// Large qualification inputs belong in CI; structural table completeness
		// is always checked, and these small representatives exercise every stage.
		if strings.Contains(key, "64") || strings.Contains(key, "4m") || strings.HasPrefix(key, "concurrent-") {
			continue
		}
		t.Run(key, func(t *testing.T) { c := adversarialCostInput(t, key); checkCostInput(t, c) })
	}
}

func checkCostInput(t testing.TB, c costInput) {
	t.Helper()
	f, err := ReadFrame(&io.LimitedReader{R: bytes.NewReader(c.frame), N: compressedBudget})
	if c.codecs == 0 {
		if c.rateDeficit {
			if err != nil {
				t.Fatal(err)
			}
			costRateRefusal(t, c.window, c.size)
		} else if !errors.Is(err, c.want) {
			t.Fatalf("preflight: %v want %v", err, c.want)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeFrame(f, costDescriptor(c.lines), "device-a")
	if !errors.Is(err, c.want) || err != nil && got != nil || err == nil && len(got) != c.lines {
		t.Fatalf("decode: %v lines=%d want=%v", err, len(got), c.want)
	}
}

// costRateRefusal reaches decode-rate admission with two receive tickets held.
// Filling the bucket deficit uses real charged concurrency refusals; no codec
// is entered for this request. Setup is included, making its CPU check stricter.
func costRateRefusal(t testing.TB, window, size uint64) {
	t.Helper()
	cfg, err := admission.Defaults(1<<30, true)
	if err != nil {
		t.Fatal(err)
	}
	l, err := admission.New(cfg, admission.SystemClock(), func() float64 { return .5 })
	if err != nil {
		t.Fatal(err)
	}
	ticket, _, err := l.Receive("rate", batch.ClassRaw)
	if err != nil || ticket == nil {
		t.Fatalf("receive: %v", err)
	}
	defer ticket.Release()
	other, _, err := l.Receive("rate", batch.ClassRaw)
	if err != nil || other == nil {
		t.Fatalf("receive: %v", err)
	}
	defer other.Release()
	for range (admission.BucketCapacity / admission.MinCharge) - 2 {
		l.Receive("rate", batch.ClassRaw)
	}
	decision, err := ticket.Decode(context.Background(), window, size)
	if err != nil || decision.Reason != admission.ReasonDeviceRate {
		t.Fatalf("rate rejection: %+v %v", decision, err)
	}
}
