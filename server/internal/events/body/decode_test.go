package body

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ricevanta/ricevanta/server/internal/events/batch"
	"github.com/ricevanta/ricevanta/server/internal/events/wire"
)

func batchSentinel(name *string) error {
	if name == nil {
		return nil
	}
	return map[string]error{
		"body.ErrCompressedLimit": ErrCompressedLimit, "body.ErrFrame": ErrFrame, "body.ErrChecksumRequired": ErrChecksumRequired, "body.ErrContentSizeRequired": ErrContentSizeRequired, "body.ErrDecodedLimit": ErrDecodedLimit, "body.ErrWindowLimit": ErrWindowLimit, "body.ErrTrailingData": ErrTrailingData, "body.ErrContentSize": ErrContentSize, "body.ErrChecksum": ErrChecksum, "body.ErrLineLimit": ErrLineLimit, "body.ErrLineCountLimit": ErrLineCountLimit, "body.ErrLineFraming": ErrLineFraming, "body.ErrRecordCount": ErrRecordCount}[*name]
}
func decodeFixture(t testing.TB, c bodyFixture, template string) []Line {
	t.Helper()
	b, p, d := fixtureBytes(t, c, template)
	lr := &io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}
	lines, e := Decode(lr, d, c.Device)
	if !errors.Is(e, batchSentinel(c.Expected.Error)) {
		t.Fatalf("err=%v want=%v", e, c.Expected.Error)
	}
	if e != nil {
		if lines != nil {
			t.Fatal("partial results")
		}
		return nil
	}
	if len(lines) != int(d.RecordCount) {
		t.Fatal("count")
	}
	raw := bytes.Split(p[:len(p)-1], []byte{'\n'})
	i := 0
	for _, r := range c.Expected.Lines {
		for j := 0; j < r.Count; j++ {
			assertLine(t, lines[i], raw[i], uint32(i+1), r, j)
			i++
		}
	}
	return lines
}
func TestDecodeFixtures(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) { decodeFixture(t, c, f.Template) })
	}
}
func TestDecodeCallerPrecedence(t *testing.T) {
	for _, c := range []struct {
		name            string
		nilReader, nilR bool
		n               int64
		d               batch.Descriptor
		device          string
		want            error
	}{
		{"descriptor", true, false, 0, batch.Descriptor{}, "", batch.ErrClass},
		{"nil-reader", true, false, 0, descriptor(0, 1), "", ErrReaderBound},
		{"nil-R", false, true, remainingBudget, descriptor(0, 1), "", ErrReaderBound},
		{"reset", false, false, 5000001, descriptor(0, 1), "a", ErrReaderBound},
		{"reduced", false, false, remainingBudget - 1, descriptor(0, 1), "a", ErrReaderBound},
		{"empty-device", false, false, remainingBudget, descriptor(0, 1), "", ErrDevice},
		{"invalid-UTF8", false, false, remainingBudget, descriptor(0, 1), string([]byte{255}), ErrDevice},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &readProbe{end: io.EOF}
			lr := &io.LimitedReader{R: r, N: c.n}
			if c.nilReader {
				lr = nil
			} else if c.nilR {
				lr.R = nil
			}
			lines, e := Decode(lr, c.d, c.device)
			if !errors.Is(e, c.want) || lines != nil || r.calls != 0 {
				t.Fatalf("err=%v calls=%d", e, r.calls)
			}
		})
	}
}
func TestDecodeWireHandoff(t *testing.T) {
	f := loadFixtures(t)
	c := f.Cases[0]
	b, _, d := fixtureBytes(t, c, f.Template)
	prefix := make([]byte, 48)
	binary.LittleEndian.PutUint32(prefix, 0x184d2a50)
	binary.LittleEndian.PutUint32(prefix[4:], 40)
	prefix[8] = 1
	prefix[9] = byte(d.Class)
	binary.LittleEndian.PutUint64(prefix[12:], d.StreamEpoch)
	binary.LittleEndian.PutUint64(prefix[20:], d.SegmentID)
	binary.LittleEndian.PutUint64(prefix[28:], d.FirstSequence)
	binary.LittleEndian.PutUint64(prefix[36:], d.LastSequence)
	binary.LittleEndian.PutUint32(prefix[44:], d.RecordCount)
	lr := &io.LimitedReader{R: bytes.NewReader(append(prefix, b...)), N: wire.MaxCompressedBytes + 1}
	header := fmt.Sprintf("v=1;class=%s;epoch=%d;segment=%d;first=%d;last=%d;count=%d", d.Class, d.StreamEpoch, d.SegmentID, d.FirstSequence, d.LastSequence, d.RecordCount)
	parsed, e := wire.Decode([]string{header}, lr)
	if e != nil {
		t.Fatal(e)
	}
	if lines, e := Decode(lr, parsed, c.Device); e != nil || len(lines) != 1 {
		t.Fatalf("%v", e)
	}
	opaque := " 雪 "
	p := append(record("0", opaque), '\n')
	if lines, e := Decode(&io.LimitedReader{R: bytes.NewReader(encode(t, p)), N: remainingBudget}, d, opaque); e != nil || lines[0].Err != nil {
		t.Fatalf("opaque identity %v", e)
	}
}
func encode(t testing.TB, p []byte) []byte {
	t.Helper()
	encoder, e := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(1), zstd.WithSingleSegment(true))
	if e != nil {
		t.Fatal(e)
	}
	defer encoder.Close()
	return encoder.EncodeAll(p, nil)
}
func TestDecodeNoPartialResults(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Cases {
		if c.Expected.Error != nil {
			t.Run(c.Name, func(t *testing.T) { decodeFixture(t, c, f.Template) })
		}
	}
}
func TestDecodeRawOwnership(t *testing.T) {
	p := append(record("0", "device-a"), '\n')
	p = append(p, record("1", "device-a")...)
	p = append(p, '\n')
	b := encode(t, p)
	lines, e := Decode(&io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}, descriptor(0, 2), "device-a")
	if e != nil {
		t.Fatal(e)
	}
	saved := bytes.Clone(lines[1].Raw)
	clear(b)
	lines[0].Raw[0] = 'x'
	if !bytes.Equal(lines[1].Raw, saved) {
		t.Fatal("aliased lines")
	}
	if !bytes.Equal(lines[0].Raw[1:], record("0", "device-a")[1:]) {
		t.Fatal("decoder aliases")
	}
}

type closeProbe struct {
	io.Reader
	closed int
}

func (d *closeProbe) Close() { d.closed++ }
func TestDecodeCodecOptions(t *testing.T) {
	f := loadFixtures(t)
	b, p, d := fixtureBytes(t, f.Cases[0], f.Template)
	probe := &closeProbe{Reader: bytes.NewReader(p)}
	calls := 0
	factory := func(r io.Reader, options ...zstd.DOption) (streamDecoder, error) {
		calls++
		if len(options) != 6 {
			t.Fatalf("options=%d", len(options))
		}
		state := reflect.New(reflect.TypeOf(options[0]).In(0).Elem())
		for _, option := range options {
			result := reflect.ValueOf(option).Call([]reflect.Value{state})
			if !result[0].IsNil() {
				t.Fatal("invalid option")
			}
		}
		s := state.Elem()
		if s.FieldByName("concurrent").Int() != 1 || s.FieldByName("maxDecodedSize").Uint() != uint64(MaxDecodedBytes) || s.FieldByName("maxWindowSize").Uint() != MaxWindowBytes || !s.FieldByName("lowMem").Bool() || s.FieldByName("decodeBufsBelow").Int() != 0 || s.FieldByName("ignoreChecksum").Bool() {
			t.Fatal("codec contract")
		}
		return probe, nil
	}
	if _, e := decodeWithFactory(&io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}, d, "device-a", factory); e != nil || calls != 1 || probe.closed != 1 {
		t.Fatalf("err=%v calls=%d closed=%d", e, calls, probe.closed)
	}
	for _, failure := range []error{zstd.ErrFrameSizeMismatch, zstd.ErrFrameSizeExceeded, zstd.ErrCRCMismatch, zstd.ErrWindowSizeExceeded, zstd.ErrDecoderSizeExceeded, io.ErrUnexpectedEOF} {
		probe = &closeProbe{Reader: &outputReader{left: len(p), pattern: p, end: failure}}
		_, e := decodeWithFactory(&io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}, d, "device-a", factory)
		want := ErrFrame
		switch failure {
		case zstd.ErrFrameSizeMismatch, zstd.ErrFrameSizeExceeded:
			want = ErrContentSize
		case zstd.ErrCRCMismatch:
			want = ErrChecksum
		case zstd.ErrWindowSizeExceeded, zstd.ErrDecoderSizeExceeded:
			want = ErrWindowLimit
		}
		if !errors.Is(e, want) || errors.Is(e, failure) || probe.closed != 1 {
			t.Fatalf("mapping %v => %v closed=%d", failure, e, probe.closed)
		}
	}
}
func FuzzDecode(f *testing.F) {
	fixtures := loadFixtures(f)
	for _, c := range fixtures.Cases {
		b, e := c.body()
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b, uint32(mustCount(c.Descriptor.Count)))
	}
	f.Fuzz(func(t *testing.T, b []byte, selector uint32) {
		if len(b) > 5000001 {
			return
		}
		lr := &io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}
		d := descriptor(0, selector%10000+1)
		lines, e := Decode(lr, d, "device-a")
		if lr.N < 0 || lr.N > remainingBudget {
			t.Fatal("reader bound")
		}
		if e != nil {
			if lines != nil {
				t.Fatal("partial batch")
			}
			return
		}
		if len(lines) != int(d.RecordCount) {
			t.Fatal("count")
		}
		for i, line := range lines {
			if line.Number != uint32(i+1) || len(line.Raw) == 0 || len(line.Raw) > MaxLineBytes {
				t.Fatal("line bounds")
			}
			assertReferenceLine(t, line, line.Raw, uint32(i+1), d, "device-a")
		}
	})
}
