package loader

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func archiveReader(b []byte, f uint64) *io.LimitedReader {
	return &io.LimitedReader{R: bytes.NewReader(b), N: int64(f + (9 << 20) + 1)}
}
func TestReadArchive(t *testing.T) {
	raw := tarFixture(t, controlEntries()...)
	compressed := compressFixture(t, raw)
	r := archiveReader(compressed, 3)
	got, m, err := readArchive(r, 3)
	if err != nil || !bytes.Equal(got, compressed) || len(m) != 2 || r.N != int64(3+(9<<20)+1-len(compressed)) {
		t.Fatalf("snapshot/inventory: %v", err)
	}
}

type scriptedReader struct {
	data              []byte
	err               error
	zeros, calls, max int
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	r.calls++
	r.max = max(r.max, len(p))
	if r.zeros > 0 {
		r.zeros--
		return 0, nil
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}
func TestReadBoundaries(t *testing.T) {
	valid := compressFixture(t, tarFixture(t, controlEntries()...))
	cause := errors.New("source cause")
	for _, tc := range []struct {
		name      string
		data      []byte
		err, want error
		zeros     int
	}{{"EOF bytes", valid, io.EOF, nil, 0}, {"error bytes", valid, cause, ErrRead, 0}, {"no progress", nil, nil, ErrRead, 100}, {"overflow error", make([]byte, (9<<20)+2), cause, ErrCompressedLimit, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedReader{data: tc.data, err: tc.err, zeros: tc.zeros}
			r := &io.LimitedReader{R: s, N: (9 << 20) + 2}
			a, m, e := readArchive(r, 1)
			if !errors.Is(e, tc.want) {
				t.Fatalf("got %v want %v", e, tc.want)
			}
			if e != nil && (a != nil || m != nil) {
				t.Fatal("partial")
			}
			if s.max > 32768 {
				t.Fatal("read chunk")
			}
			if tc.zeros == 100 && (s.calls != 100 || !errors.Is(e, io.ErrNoProgress)) {
				t.Fatal("no progress cause/count")
			}
			if tc.name == "error bytes" && !errors.Is(e, cause) {
				t.Fatal("lost cause")
			}
			if tc.name == "overflow error" && (r.N != 0 || len(s.data) != 0) {
				t.Fatal("extra-byte stop")
			}
		})
	}
}
func TestFrameProfile(t *testing.T) {
	valid := compressFixture(t, tarFixture(t, controlEntries()...))
	cases := []struct {
		name string
		b    []byte
		want error
	}{{"valid", valid, nil}, {"truncated", valid[:len(valid)-1], ErrCompression}, {"suffix", append(bytes.Clone(valid), 0), ErrCompression}, {"second", append(bytes.Clone(valid), valid...), ErrCompression}, {"skippable", []byte{0x50, 0x2a, 0x4d, 0x18}, ErrCompression}}
	for _, mask := range []byte{8, 16, 1, 4} {
		b := bytes.Clone(valid)
		if mask == 4 {
			b[4] &= ^mask
		} else {
			b[4] |= mask
		}
		cases = append(cases, struct {
			name string
			b    []byte
			want error
		}{"descriptor", b, ErrCompression})
	}
	b := bytes.Clone(valid)
	b[len(b)-1] ^= 1
	cases = append(cases, struct {
		name string
		b    []byte
		want error
	}{"checksum", b, ErrCompression})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, e := readArchive(archiveReader(tc.b, 1), 1)
			if !errors.Is(e, tc.want) {
				t.Fatalf("%v want %v", e, tc.want)
			}
		})
	}
}

// rawFrameHeader builds framing independently of the encoder and frame walker.
func rawFrameHeader(size uint64, single bool, window byte) []byte {
	b := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xc4}
	if single {
		b[4] |= 0x20
	} else {
		b = append(b, window)
	}
	for i := 0; i < 8; i++ {
		b = append(b, byte(size>>(8*i)))
	}
	return append(b, 1, 0, 0, 0, 0, 0, 0) // empty last raw block and checksum
}

func TestFrameHeaderBoundaries(t *testing.T) {
	const f = uint64(1)
	const limit = f + (8 << 20)
	for _, tc := range []struct {
		name string
		b    []byte
		want error
	}{
		{"T-1", rawFrameHeader(limit-1, false, 0x68), nil},
		{"T", rawFrameHeader(limit, false, 0x68), nil},
		{"T+1", rawFrameHeader(limit+1, false, 0x68), ErrArchiveLimit},
		{"uint64 maximum", rawFrameHeader(^uint64(0), false, 0x68), ErrArchiveLimit},
		{"window 8MiB", rawFrameHeader(0, false, 0x68), nil},
		{"window above 8MiB", rawFrameHeader(0, false, 0x69), ErrArchiveLimit},
		{"single 8MiB", rawFrameHeader(8<<20, true, 0), nil},
		{"single above 8MiB", rawFrameHeader((8<<20)+1, true, 0), ErrArchiveLimit},
		{"missing size", []byte{0x28, 0xb5, 0x2f, 0xfd, 4, 0x68, 1, 0, 0, 0, 0, 0, 0}, ErrCompression},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := frameSize(tc.b, limit)
			if !errors.Is(e, tc.want) {
				t.Fatalf("got %v want %v", e, tc.want)
			}
		})
	}
	for _, h := range []uint32{7, (128<<10+1)<<3 | 1, 2<<3 | 1} {
		b := rawFrameHeader(0, false, 0x68)
		off := len(b) - 7
		b[off], b[off+1], b[off+2] = byte(h), byte(h>>8), byte(h>>16)
		if _, e := frameSize(b, limit); !errors.Is(e, ErrCompression) {
			t.Fatalf("block %x: %v", h, e)
		}
	}
	valid := compressFixture(t, tarFixture(t, controlEntries()...))
	for i := 0; i < len(valid); i++ {
		if _, _, e := readArchive(archiveReader(valid[:i], f), f); !errors.Is(e, ErrCompression) {
			t.Fatalf("truncation %d: %v", i, e)
		}
	}
}

func TestReadSnapshotCeiling(t *testing.T) {
	const c = uint64(65536)
	cause := errors.New("read cause")
	for _, n := range []uint64{c - 1, c, c + 1, c + 2} {
		for _, end := range []error{io.EOF, cause} {
			s := &scriptedReader{data: make([]byte, n), err: end}
			r := &io.LimitedReader{R: s, N: int64(c + 1)}
			b, e := readSnapshot(r, c)
			want := error(nil)
			if n > c {
				want = ErrCompressedLimit
			} else if end == cause {
				want = ErrRead
			}
			if !errors.Is(e, want) {
				t.Fatalf("length %d: %v want %v", n, e, want)
			}
			if uint64(r.N) != c+1-min(n, c+1) || len(s.data) != int(n-min(n, c+1)) {
				t.Fatal("consumed past ceiling")
			}
			if e == nil && (len(b) != int(n) || cap(b) > int(c+1)) {
				t.Fatal("snapshot size/capacity")
			}
			if e != nil && b != nil {
				t.Fatal("partial snapshot")
			}
		}
	}
	// Positive reads reset the consecutive no-progress counter.
	s := &progressReader{}
	b, e := readSnapshot(&io.LimitedReader{R: s, N: 3}, 2)
	if e != nil || !bytes.Equal(b, []byte{'a', 'b'}) || s.calls != 200 {
		t.Fatalf("progress reset: %q %v calls=%d", b, e, s.calls)
	}
}

type progressReader struct{ calls int }

func (r *progressReader) Read(p []byte) (int, error) {
	r.calls++
	switch r.calls {
	case 100:
		p[0] = 'a'
		return 1, nil
	case 200:
		p[0] = 'b'
		return 1, io.EOF
	default:
		return 0, nil
	}
}

func TestReadArithmetic(t *testing.T) {
	// Internal checks must reject overflow before allocating or reading.
	for _, f := range []uint64{^uint64(0), ^uint64(0) - (9 << 20)} {
		r := &io.LimitedReader{R: bytes.NewReader(nil), N: 1}
		if _, _, e := readArchive(r, f); !errors.Is(e, ErrArchiveLimit) || r.N != 1 {
			t.Fatalf("ceiling overflow: %v N=%d", e, r.N)
		}
	}
	if _, e := readSnapshot(&io.LimitedReader{R: bytes.NewReader(nil), N: 1}, ^uint64(0)); !errors.Is(e, ErrArchiveLimit) {
		t.Fatalf("sentinel byte overflow: %v", e)
	}
}

func TestReadArchiveLargeAndHardCeiling(t *testing.T) {
	// The output spans multiple blocks and exceeds the maximum zstd window.
	data := bytes.Repeat([]byte("x"), (8<<20)+1)
	entries := append(controlEntries(), archiveEntry{"opaque.bin", data})
	compressed := compressFixture(t, tarFixture(t, entries...))
	for _, f := range []uint64{uint64(len(data)), 64 << 20, 1 << 30} {
		a, m, e := readArchive(archiveReader(compressed, f), f)
		if e != nil || !bytes.Equal(a, compressed) || len(m) != 3 || !bytes.Equal(m[2].body, data) {
			t.Fatalf("file ceiling %d: %v", f, e)
		}
	}
}

func TestReadCompressedCeiling(t *testing.T) {
	const f = uint64(1)
	const c = f + (9 << 20)
	for _, n := range []uint64{c - 1, c, c + 1, c + 2} {
		s := &scriptedReader{data: make([]byte, n), err: io.EOF}
		r := &io.LimitedReader{R: s, N: int64(c + 1)}
		a, m, e := readArchive(r, f)
		want := ErrCompression
		if n > c {
			want = ErrCompressedLimit
		}
		if !errors.Is(e, want) || a != nil || m != nil || r.N != int64(c+1-min(n, c+1)) || len(s.data) != int(n-min(n, c+1)) {
			t.Fatalf("C boundary %d: %v N=%d remaining=%d", n, e, r.N, len(s.data))
		}
	}
}

func TestReadShortChunks(t *testing.T) {
	b := compressFixture(t, tarFixture(t, controlEntries()...))
	r := &io.LimitedReader{R: &byteReader{b: bytes.Clone(b)}, N: 1 + (9 << 20) + 1}
	a, m, e := readArchive(r, 1)
	if e != nil || !bytes.Equal(a, b) || len(m) != 2 || r.N != int64(1+(9<<20)+1-len(b)) {
		t.Fatalf("one-byte reader: %v N=%d", e, r.N)
	}
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	p[0] = r.b[0]
	r.b = r.b[1:]
	return 1, nil
}

func TestFrameDictionaryFields(t *testing.T) {
	valid := compressFixture(t, tarFixture(t, controlEntries()...))
	for _, field := range []byte{1, 2, 3} {
		b := bytes.Clone(valid)
		b[4] |= field
		_, _, e := readArchive(archiveReader(b, 1), 1)
		if !errors.Is(e, ErrCompression) {
			t.Fatalf("dictionary field %d: %v", field, e)
		}
	}
	// A well-framed empty last block cannot satisfy nonzero content size.
	for _, n := range []uint64{1, (8 << 20) - 1, 8 << 20, (8 << 20) + 1} {
		b := rawFrameHeader(n, false, 0x68)
		a, m, e := readArchive(archiveReader(b, 1), 1)
		if !errors.Is(e, ErrCompression) || a != nil || m != nil {
			t.Fatalf("declared/actual mismatch %d: %v", n, e)
		}
	}
}
