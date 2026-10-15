package body

import (
	"bytes"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
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

func (c costCase) key() string { return c.shape + "/" + itoa(c.n) }

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
	return append(cases,
		costCase{"flat-64x1MiB-single", 4},
		costCase{"round-2047x32769-single", 4},
		costCase{"arrayobjs-64x1MiB-single", 4},
		costCase{"singlechar-64x1MiB-single", 4},
		costCase{"random3-64x1MiB-single", 4},
		costCase{"badid-10000-single", 8},
		costCase{"realistic-5000-win4", 8},
		costCase{"dense-4x1MiB-win4", 16},
	)
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
