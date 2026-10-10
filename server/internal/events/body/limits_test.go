package body

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type outputReader struct {
	left       int
	pattern    []byte
	pos        int
	chunk      int
	end        error
	calls      int
	maxRequest int
	wantProbe  bool
}

func (r *outputReader) Read(p []byte) (int, error) {
	r.calls++
	r.maxRequest = max(r.maxRequest, len(p))
	if len(p) > 32768 || int64(len(p)) > MaxDecodedBytes-int64(r.pos)+1 {
		panic("unbounded output request")
	}
	if r.left == 0 {
		return 0, r.end
	}
	n := min(len(p), r.left)
	if r.chunk > 0 {
		n = min(n, r.chunk)
	}
	for i := 0; i < n; i++ {
		p[i] = r.pattern[(r.pos+i)%len(r.pattern)]
	}
	r.pos += n
	r.left -= n
	if r.left == 0 {
		return n, r.end
	}
	return n, nil
}
func TestConsumeLimits(t *testing.T) {
	cause := errors.New("simultaneous")
	for _, c := range []struct {
		name  string
		p     []byte
		chunk int
		want  error
		count uint32
	}{
		{"split-LF", append(record("0", "device-a"), '\n'), 1, nil, 1},
		{"CRLF", append(record("0", "device-a"), '\r', '\n'), 7, ErrLineFraming, 1},
		{"blank", []byte(" \t\n"), 1, ErrLineFraming, 1},
		{"missing-LF", record("0", "device-a"), 7, ErrLineFraming, 1},
		{"exact-line", append(bytes.Repeat([]byte{'x'}, MaxLineBytes), '\n'), 32768, nil, 1},
		{"over-line", append(bytes.Repeat([]byte{'x'}, MaxLineBytes+1), '\n'), 32768, ErrLineLimit, 1},
		{"line-count", bytes.Repeat([]byte("x\n"), 10001), 32768, ErrLineCountLimit, 10000},
		{"empty", nil, 32768, ErrRecordCount, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &outputReader{left: len(c.p), pattern: c.p, chunk: c.chunk, end: io.EOF}
			lines, e := consume(r, uint64(len(c.p)), descriptor(0, c.count), "device-a")
			if !errors.Is(e, c.want) || e != nil && lines != nil {
				t.Fatalf("err=%v want=%v", e, c.want)
			}
		})
	}
	// 64 lines each contain 1 MiB including LF. The next byte hits both output and count-independent limits.
	pattern := append(bytes.Repeat([]byte{'x'}, MaxLineBytes-1), '\n')
	r := &outputReader{left: int(MaxDecodedBytes) + 1, pattern: pattern, end: cause}
	lines, e := consume(r, uint64(MaxDecodedBytes+1), descriptor(0, 64), "device-a")
	if !errors.Is(e, ErrDecodedLimit) || lines != nil || r.left != 0 || r.calls != 2049 {
		t.Fatalf("overflow err=%v calls=%d left=%d", e, r.calls, r.left)
	}
	r = &outputReader{left: MaxLineBytes + 1, pattern: []byte{'x'}, end: ErrChecksum}
	if _, e := consume(r, MaxLineBytes+1, descriptor(0, 1), "a"); !errors.Is(e, ErrLineLimit) {
		t.Fatal(e)
	}
	r = &outputReader{left: 1, pattern: []byte{'\n'}, end: ErrChecksum}
	if _, e := consume(r, 1, descriptor(0, 1), "a"); !errors.Is(e, ErrChecksum) {
		t.Fatal(e)
	}
}
func BenchmarkDecodeLimits(b *testing.B) {
	f := loadFixtures(b)
	for _, name := range []string{"decoded-bytes-67108864", "bomb-claimed-1GiB", "bomb-small-claim"} {
		for _, c := range f.Cases {
			if c.Name != name {
				continue
			}
			data, e := c.body()
			if e != nil {
				b.Fatal(e)
			}
			d, e := c.descriptor()
			if e != nil {
				b.Fatal(e)
			}
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					lines, e := Decode(&io.LimitedReader{R: bytes.NewReader(data), N: remainingBudget}, d, c.Device)
					if !errors.Is(e, batchSentinel(c.Expected.Error)) {
						b.Fatal(e)
					}
					_ = lines
				}
			})
		}
	}
}

// Both limits become true on the byte after 10,000 complete lines totaling
// exactly 64 MiB. The output ceiling must win before the line-count check.
func TestConsumeOutputBeforeLineCount(t *testing.T) {
	shortSize := int(MaxDecodedBytes) / MaxLines
	longCount := int(MaxDecodedBytes) % MaxLines
	short := append(bytes.Repeat([]byte{'x'}, shortSize-1), '\n')
	long := append(bytes.Repeat([]byte{'x'}, shortSize), '\n')
	r := io.MultiReader(
		&outputReader{left: longCount * len(long), pattern: long, end: io.EOF},
		&outputReader{left: (MaxLines - longCount) * len(short), pattern: short, end: io.EOF},
		bytes.NewReader([]byte{'x'}),
	)
	lines, err := consume(r, uint64(MaxDecodedBytes+1), descriptor(0, MaxLines), "device-a")
	if !errors.Is(err, ErrDecodedLimit) || lines != nil {
		t.Fatalf("err=%v want=%v, nil lines=%v", err, ErrDecodedLimit, lines == nil)
	}
}

func TestConsumeContentSizeBeforeFraming(t *testing.T) {
	lines, err := consume(bytes.NewReader([]byte("x")), 2, descriptor(0, 1), "device-a")
	if !errors.Is(err, ErrContentSize) || lines != nil {
		t.Fatalf("err=%v want=%v, nil lines=%v", err, ErrContentSize, lines == nil)
	}
}
