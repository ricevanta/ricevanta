package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

func fixtureBytes(t testing.TB, c fixture) []byte {
	t.Helper()
	b, err := hex.DecodeString(c.FrameHex)
	if err != nil || hex.EncodeToString(b) != c.FrameHex || len(b) > 48 {
		t.Fatal("invalid fixture frame hex")
	}
	return b
}

func validFrame(t testing.TB) []byte {
	t.Helper()
	for _, c := range loadFixtures(t, "descriptor") {
		if c.Name == "valid-raw" {
			return fixtureBytes(t, c)
		}
	}
	t.Fatal("missing valid frame fixture")
	return nil
}

// probeReader records physical consumption and rejects any read beyond its limit.
type probeReader struct {
	data     []byte
	consumed int
	calls    int
	step     int
	stop     int
	cause    error
	finalEOF bool
}

func (r *probeReader) Read(p []byte) (int, error) {
	r.calls++
	if r.consumed >= r.stop {
		return 0, r.cause
	}
	size := len(p)
	if r.step > 0 && size > r.step {
		size = r.step
	}
	if size > r.stop-r.consumed {
		size = r.stop - r.consumed
	}
	if size > len(r.data)-r.consumed {
		size = len(r.data) - r.consumed
	}
	if size == 0 {
		return 0, io.EOF
	}
	n := copy(p[:size], r.data[r.consumed:])
	r.consumed += n
	if r.finalEOF && r.consumed == len(r.data) {
		return n, io.EOF
	}
	if r.cause != nil && r.consumed == r.stop {
		return n, r.cause
	}
	return n, nil
}

func TestDecodeFixtures(t *testing.T) {
	for _, c := range loadFixtures(t, "descriptor") {
		t.Run(c.Name, func(t *testing.T) {
			data := fixtureBytes(t, c)
			r := &probeReader{data: data, stop: len(data), cause: io.EOF}
			body := &io.LimitedReader{R: r, N: MaxCompressedBytes + 1}
			d, err := Decode(c.Values, body)
			requireResult(t, d, err, fixtureError(t, c.Error), fixtureDescriptor(t, c.Descriptor))
			if r.consumed != c.Consumed || body.N != MaxCompressedBytes+1-int64(c.Consumed) {
				t.Fatalf("consumed %d, budget %d, want %d consumed", r.consumed, body.N, c.Consumed)
			}
		})
	}
}

func TestDecodeReadBoundaries(t *testing.T) {
	frame := validFrame(t)
	for length := 0; length < 48; length++ {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			r := &probeReader{data: frame[:length], stop: length, cause: io.EOF}
			d, err := Decode([]string{validHeader}, &io.LimitedReader{R: r, N: 49})
			requireResult(t, d, err, ErrFrameRead, batch.Descriptor{})
			cause := error(io.ErrUnexpectedEOF)
			if length == 0 || length == 4 || length == 8 {
				cause = io.EOF
			}
			if !errors.Is(err, cause) || r.consumed != length {
				t.Fatalf("error %v, consumed %d; want %v, %d", err, r.consumed, cause, length)
			}
		})
	}
	for _, step := range []int{0, 1} {
		for _, eof := range []bool{false, true} {
			r := &probeReader{data: frame, stop: 48, cause: errors.New("read past prefix"), step: step, finalEOF: eof}
			d, err := Decode([]string{validHeader}, &io.LimitedReader{R: r, N: 49})
			requireResult(t, d, err, nil, batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, RecordCount: 1})
			wantCalls := 3
			if step == 1 {
				wantCalls = 48
			}
			if r.consumed != 48 || r.calls != wantCalls {
				t.Fatalf("consumed = %d, calls = %d; want 48, %d", r.consumed, r.calls, wantCalls)
			}
		}
	}
	// A wrong magic or size must stop without another read.
	for _, stage := range []struct {
		offset, stop int
		want         error
	}{{0, 4, ErrFrameMagic}, {4, 8, ErrFrameSize}} {
		data := bytes.Clone(frame)
		data[stage.offset] ^= 1
		r := &probeReader{data: data, stop: stage.stop, cause: errors.New("read past failed stage")}
		d, err := Decode([]string{validHeader}, &io.LimitedReader{R: r, N: 49})
		requireResult(t, d, err, stage.want, batch.Descriptor{})
		if r.consumed != stage.stop || r.calls != stage.stop/4 {
			t.Fatalf("unexpected reads: bytes %d, calls %d", r.consumed, r.calls)
		}
	}
}

func TestDecodeIncompletePayloadPrecedence(t *testing.T) {
	injected := errors.New("injected payload failure")
	for _, defect := range []struct {
		name   string
		change func([]byte)
	}{
		{"version", func(b []byte) { b[8] = 2 }},
		{"reserved first", func(b []byte) { b[10] = 1 }},
		{"reserved second", func(b []byte) { b[11] = 1 }},
		{"class", func(b []byte) { b[9] = 0 }},
		{"epoch", func(b []byte) { binary.LittleEndian.PutUint64(b[12:], 0) }},
		{"count", func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 0) }},
		{"sequence range", func(b []byte) { binary.LittleEndian.PutUint64(b[28:], 1) }},
		{"sequence count", func(b []byte) { binary.LittleEndian.PutUint64(b[36:], 1) }},
	} {
		t.Run(defect.name, func(t *testing.T) {
			frame := validFrame(t)
			defect.change(frame)
			for length := 9; length < 48; length++ {
				for _, cause := range []error{io.EOF, injected} {
					t.Run(fmt.Sprintf("%d/%v", length, cause), func(t *testing.T) {
						r := &probeReader{data: frame[:length], stop: length, cause: cause}
						body := &io.LimitedReader{R: r, N: 49}
						d, err := Decode([]string{validHeader}, body)
						requireResult(t, d, err, ErrFrameRead, batch.Descriptor{})
						wantCause := cause
						if cause == io.EOF {
							wantCause = io.ErrUnexpectedEOF
						}
						if !errors.Is(err, wantCause) || r.consumed != length || body.N != 49-int64(length) {
							t.Fatalf("error %v, consumed %d, budget %d; want %v, %d, %d", err, r.consumed, body.N, wantCause, length, 49-length)
						}
					})
				}
			}
		})
	}
}

func TestDecodeReaderBounds(t *testing.T) {
	frame := validFrame(t)
	for _, n := range []int64{-1, 0, 47, 48, 49, 5_000_000, 5_000_001, 5_000_002} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := &probeReader{data: frame, stop: 48, cause: io.EOF}
			body := &io.LimitedReader{R: r, N: n}
			d, err := Decode([]string{validHeader}, body)
			want := error(nil)
			consumed := 48
			if n < 0 || n > MaxCompressedBytes+1 {
				want = ErrReaderBound
				consumed = 0
			} else if n < 48 {
				want = ErrFrameRead
				consumed = int(n)
			}
			requireResult(t, d, err, want, batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, RecordCount: 1})
			if r.consumed != consumed || body.N != n-int64(consumed) {
				t.Fatalf("consumed %d budget %d", r.consumed, body.N)
			}
			if want == ErrReaderBound && r.calls != 0 {
				t.Fatal("invalid budget read body")
			}
		})
	}
	for _, body := range []*io.LimitedReader{nil, {N: 49}} {
		d, err := Decode([]string{validHeader}, body)
		requireResult(t, d, err, ErrReaderBound, batch.Descriptor{})
	}
}

func TestDecodeIOErrors(t *testing.T) {
	injected := errors.New("injected reader failure")
	frame := validFrame(t)
	for _, stop := range []int{0, 1, 3, 4, 5, 7, 8, 9, 20, 47} {
		t.Run(fmt.Sprint(stop), func(t *testing.T) {
			r := &probeReader{data: frame, stop: stop, cause: injected}
			d, err := Decode([]string{validHeader}, &io.LimitedReader{R: r, N: 49})
			requireResult(t, d, err, ErrFrameRead, batch.Descriptor{})
			if !errors.Is(err, injected) || r.consumed != stop {
				t.Fatalf("error %v, consumed %d", err, r.consumed)
			}
		})
	}
}

func TestDecodeErrorPrecedence(t *testing.T) {
	for _, c := range loadFixtures(t, "header") {
		if c.Error == nil {
			continue
		}
		r := &probeReader{data: []byte{0}, stop: 0, cause: errors.New("body must stay unread")}
		body := &io.LimitedReader{R: r, N: -1}
		d, err := Decode(c.Values, body)
		requireResult(t, d, err, fixtureError(t, c.Error), batch.Descriptor{})
		if r.calls != 0 || body.N != -1 {
			t.Fatal("header failure touched reader")
		}
		d, err = Decode(c.Values, nil)
		requireResult(t, d, err, fixtureError(t, c.Error), batch.Descriptor{})
	}
	frame := validFrame(t)
	for _, c := range []struct {
		name   string
		change func([]byte)
		want   error
	}{
		{"version before reserved", func(b []byte) { b[8] = 2; b[10] = 1; b[9] = 0 }, ErrVersion},
		{"reserved before class", func(b []byte) { b[11] = 1; b[9] = 0 }, ErrFrameReserved},
		{"class before epoch", func(b []byte) { b[9] = 0; binary.LittleEndian.PutUint64(b[12:], 0) }, batch.ErrClass},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := bytes.Clone(frame)
			c.change(b)
			d, err := Decode([]string{validHeader}, &io.LimitedReader{R: bytes.NewReader(b), N: 49})
			requireResult(t, d, err, c.want, batch.Descriptor{})
		})
	}
}

func TestDecodeZeroOnError(t *testing.T) {
	for _, c := range loadFixtures(t, "descriptor") {
		if c.Error != nil {
			d, err := Decode(c.Values, &io.LimitedReader{R: bytes.NewReader(fixtureBytes(t, c)), N: 49})
			requireResult(t, d, err, fixtureError(t, c.Error), batch.Descriptor{})
		}
	}
	// Independently vary each range field while keeping each frame descriptor valid.
	for _, fields := range []struct {
		first, last uint64
		count       uint32
	}{{1, 1, 1}, {0, 1, 2}, {1, 2, 2}} {
		b := validFrame(t)
		binary.LittleEndian.PutUint64(b[28:], fields.first)
		binary.LittleEndian.PutUint64(b[36:], fields.last)
		binary.LittleEndian.PutUint32(b[44:], fields.count)
		d, err := Decode([]string{validHeader}, &io.LimitedReader{R: bytes.NewReader(b), N: 49})
		requireResult(t, d, err, ErrDescriptorMismatch, batch.Descriptor{})
	}
}

func TestDecodeLeavesSuffix(t *testing.T) {
	frame := validFrame(t)
	for _, suffix := range [][]byte{{0, 255, 1, 2, 3}, frame} {
		data := append(bytes.Clone(frame), suffix...)
		r := bytes.NewReader(data)
		body := &io.LimitedReader{R: r, N: MaxCompressedBytes + 1}
		d, err := Decode([]string{validHeader}, body)
		requireResult(t, d, err, nil, batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, RecordCount: 1})
		rest, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(rest, suffix) || body.N != MaxCompressedBytes+1-48 {
			t.Fatal("suffix or budget changed")
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, c := range loadFixtures(f, "descriptor") {
		value := ""
		if len(c.Values) > 0 {
			value = c.Values[0]
		}
		f.Add(value, fixtureBytes(f, c))
	}
	f.Fuzz(func(t *testing.T, value string, data []byte) {
		r := bytes.NewReader(data)
		body := &io.LimitedReader{R: r, N: MaxCompressedBytes + 1}
		d, err := Decode([]string{value}, body)
		consumed := len(data) - r.Len()
		if consumed > 48 || body.N != MaxCompressedBytes+1-int64(consumed) {
			t.Fatal("prefix read exceeded bound")
		}
		if err != nil {
			if d != (batch.Descriptor{}) {
				t.Fatal("nonzero error result")
			}
			return
		}
		header, headerErr := ParseHeader([]string{value})
		if headerErr != nil || d != header || d.Validate() != nil || consumed != 48 {
			t.Fatal("invalid decode success")
		}
		// Decode's returned descriptor cannot stand in for the bytes on the wire.
		if binary.LittleEndian.Uint32(data[:4]) != 0x184d2a50 ||
			binary.LittleEndian.Uint32(data[4:8]) != 40 ||
			data[8] != 1 || data[10] != 0 || data[11] != 0 {
			t.Fatal("invalid binary framing on decode success")
		}
		frame := batch.Descriptor{
			Class:         batch.SpoolClass(data[9]),
			StreamEpoch:   binary.LittleEndian.Uint64(data[12:20]),
			SegmentID:     binary.LittleEndian.Uint64(data[20:28]),
			FirstSequence: binary.LittleEndian.Uint64(data[28:36]),
			LastSequence:  binary.LittleEndian.Uint64(data[36:44]),
			RecordCount:   binary.LittleEndian.Uint32(data[44:48]),
		}
		if frame.Validate() != nil || frame != header {
			t.Fatal("binary descriptor differs from header on decode success")
		}
		rest, readErr := io.ReadAll(r)
		if readErr != nil || !bytes.Equal(rest, data[48:]) {
			t.Fatal("suffix changed")
		}
	})
}
