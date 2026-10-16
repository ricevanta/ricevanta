package body

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
)

const remainingBudget int64 = 4999953

type readProbe struct {
	left  int
	chunk int
	calls int
	end   error
	zeros int
	reset bool
}

func (r *readProbe) Read(p []byte) (int, error) {
	r.calls++
	if r.left == 0 {
		if r.zeros > 0 {
			r.zeros--
			return 0, nil
		}
		return 0, r.end
	}
	if r.reset && r.calls%99 != 0 {
		return 0, nil
	}
	n := min(len(p), r.left)
	if r.chunk > 0 {
		n = min(n, r.chunk)
	}
	clear(p[:n])
	r.left -= n
	if r.left == 0 && r.end != nil && r.end != io.EOF {
		return n, r.end
	}
	return n, nil
}
func TestReadCompressed(t *testing.T) {
	for _, n := range []int{4999951, 4999952, 4999953} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := &readProbe{left: n, end: io.EOF}
			lr := &io.LimitedReader{R: r, N: remainingBudget}
			b, e := readCompressed(lr)
			if n == 4999953 {
				if !errors.Is(e, ErrCompressedLimit) || b != nil {
					t.Fatalf("overflow: %v", e)
				}
			} else if e != nil || len(b) != n || lr.N != remainingBudget-int64(n) {
				t.Fatalf("len=%d N=%d err=%v", len(b), lr.N, e)
			}
			if r.calls != (n+32767)/32768+boolInt(n < 4999953) {
				t.Fatalf("calls=%d", r.calls)
			}
		})
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func TestReadCompressedIO(t *testing.T) {
	cause := errors.New("injected")
	for _, c := range []struct {
		name  string
		r     *readProbe
		want  error
		cause error
	}{
		{"one-byte", &readProbe{left: 103, chunk: 1, end: io.EOF}, nil, nil},
		{"short", &readProbe{left: 103, chunk: 7, end: io.EOF}, nil, nil},
		{"error", &readProbe{left: 17, end: cause}, ErrRead, cause},
		{"overflow-error", &readProbe{left: 4999953, end: cause}, ErrCompressedLimit, nil},
		{"no-progress", &readProbe{zeros: 100, end: io.EOF}, ErrRead, io.ErrNoProgress},
		{"reset-progress", &readProbe{left: 2, chunk: 1, reset: true, end: io.EOF}, nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, e := readCompressed(&io.LimitedReader{R: c.r, N: remainingBudget})
			if !errors.Is(e, c.want) || c.cause != nil && !errors.Is(e, c.cause) {
				t.Fatalf("error=%v", e)
			}
			if e != nil && b != nil {
				t.Fatal("partial data")
			}
		})
	}
	b, e := readCompressed(&io.LimitedReader{R: dataEOF{[]byte("abc")}, N: remainingBudget})
	if e != nil || string(b) != "abc" {
		t.Fatalf("data EOF %q %v", b, e)
	}
}

type dataEOF struct{ b []byte }

func (r dataEOF) Read(p []byte) (int, error) { return copy(p, r.b), io.EOF }
func TestInspectFrameFixtures(t *testing.T) {
	f := loadFixtures(t)
	preflight := map[string]bool{"ErrFrame": true, "ErrChecksumRequired": true, "ErrContentSizeRequired": true, "ErrDecodedLimit": true, "ErrWindowLimit": true, "ErrTrailingData": true}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b, e := c.body()
			if e != nil {
				t.Fatal(e)
			}
			size, window, e := inspectFrame(b)
			want := ""
			if c.Name == "compressed-over-and-magic" {
				want = "event body frame"
			}
			if c.Expected.Error != nil && preflight[(*c.Expected.Error)[5:]] {
				want = expectedMessage(c.Expected.Error)
			}
			if errorName(e) != want {
				t.Fatalf("error=%v want=%s", e, want)
			}
			if e != nil && (size != 0 || window != 0) {
				t.Fatal("nonzero size or window on error")
			}
		})
	}
}
func rawFrame(size uint64, flags byte, wd byte, payload []byte) []byte {
	b := []byte{0x28, 0xb5, 0x2f, 0xfd, flags}
	if flags&32 == 0 {
		b = append(b, wd)
	}
	width := []int{0, 2, 4, 8}[flags>>6]
	if flags>>6 == 0 && flags&32 != 0 {
		width = 1
	}
	for i := 0; i < width; i++ {
		b = append(b, byte(size>>(8*i)))
	}
	h := uint32(len(payload))<<3 | 1
	b = append(b, byte(h), byte(h>>8), byte(h>>16))
	b = append(b, payload...)
	return append(b, 0, 0, 0, 0)
}
func TestInspectFramePrecedence(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want error
	}{
		{"missing-checksum-size", rawFrame(0, 0, 0, nil), ErrChecksumRequired},
		{"size-before-window", rawFrame(1<<30, 0xc4, 0xff, nil), ErrDecodedLimit},
		{"truncated-before-flags", []byte{0x28, 0xb5, 0x2f, 0xfd, 0xff}, ErrFrame},
		{"embedded-magic", rawFrame(4, 0x24, 0, []byte{0x28, 0xb5, 0x2f, 0xfd}), nil},
		{"zero", rawFrame(0, 0x24, 0, nil), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, e := inspectFrame(c.b)
			if !errors.Is(e, c.want) {
				t.Fatalf("error=%v want=%v", e, c.want)
			}
		})
	}
	b := rawFrame(3, 0x24, 0, []byte{10})
	binary.LittleEndian.PutUint32(b[6:10], 3<<3|3)
	b[9] = 10
	if _, _, e := inspectFrame(b); e != nil {
		t.Fatalf("RLE single byte: %v", e)
	}
	for n := 0; n < 6; n++ {
		if _, _, e := inspectFrame(rawFrame(1, 0x24, 0, []byte{0})[:n]); !errors.Is(e, ErrFrame) {
			t.Fatal(e)
		}
	}
}
func TestFixtureLoaderFailedOutcomeFields(t *testing.T) {
	data, e := readFixtureFile()
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]any
	if e = json.Unmarshal(data, &f); e != nil {
		t.Fatal(e)
	}
	for _, item := range f["cases"].([]any) {
		c := item.(map[string]any)
		if c["name"] == "bad-uid" {
			c["expected"].(map[string]any)["lines"].([]any)[0].(map[string]any)["event_uid"] = uid
		}
	}
	data, e = json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = parseFixtures(data); e == nil {
		t.Fatal("failed outcome accepted extracted fields")
	}
}

func TestFixtureLoaderRejectsInvalid(t *testing.T) {
	original, e := readFixtureFile()
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(map[string]any){
		func(f map[string]any) { delete(f, "kind") },
		func(f map[string]any) {
			c := f["cases"].([]any)
			c[1].(map[string]any)["name"] = c[0].(map[string]any)["name"]
		},
		func(f map[string]any) {
			c := f["cases"].([]any)[0].(map[string]any)
			c["expected"].(map[string]any)["batch_error"] = "body.ErrUnknown"
		},
		func(f map[string]any) {
			c := f["cases"].([]any)[0].(map[string]any)
			c["descriptor"].(map[string]any)["first"] = "18446744073709551616"
		},
		func(f map[string]any) {
			c := f["cases"].([]any)[0].(map[string]any)
			c["expected"].(map[string]any)["lines"].([]any)[0].(map[string]any)["count"] = 2
		},
	} {
		var f map[string]any
		if e := json.Unmarshal(original, &f); e != nil {
			t.Fatal(e)
		}
		change(f)
		b, _ := json.Marshal(f)
		if _, e := parseFixtures(b); e == nil {
			t.Fatal("invalid fixture accepted")
		}
	}
}

// readFrameSentinels are the stage 1 to 3 outcomes ReadFrame shares with Decode.
var readFrameSentinels = []error{ErrReaderBound, ErrRead, ErrCompressedLimit, ErrFrame, ErrChecksumRequired, ErrContentSizeRequired, ErrDecodedLimit, ErrWindowLimit, ErrTrailingData}

func TestReadFrameFixtures(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b, e := c.body()
			if e != nil {
				t.Fatal(e)
			}
			d, e := c.descriptor()
			if e != nil {
				t.Fatal(e)
			}
			split := &io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}
			frame, splitErr := ReadFrame(split)
			whole := &io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget}
			lines, wholeErr := Decode(whole, d, c.Device)
			if split.N != whole.N {
				t.Fatalf("consumed %d bytes, Decode consumed %d", remainingBudget-split.N, remainingBudget-whole.N)
			}
			if splitErr != nil {
				if !zeroFrame(frame) {
					t.Fatal("frame returned with an error")
				}
				if lines != nil {
					t.Fatal("Decode returned lines")
				}
				for _, sentinel := range readFrameSentinels {
					if errors.Is(splitErr, sentinel) != errors.Is(wholeErr, sentinel) {
						t.Fatalf("ReadFrame %v, Decode %v", splitErr, wholeErr)
					}
				}
				if !errors.Is(wholeErr, batchSentinel(c.Expected.Error)) {
					t.Fatalf("ReadFrame %v, fixture %v", splitErr, *c.Expected.Error)
				}
				return
			}
			if frame.ContentSize() > uint64(MaxDecodedBytes) || frame.Window() > MaxWindowBytes {
				t.Fatalf("frame exceeds EV-09 ceilings: size %d window %d", frame.ContentSize(), frame.Window())
			}
			for _, sentinel := range readFrameSentinels {
				if errors.Is(wholeErr, sentinel) && sentinel != ErrFrame {
					t.Fatalf("Decode failed in preflight with %v after ReadFrame accepted", wholeErr)
				}
			}
		})
	}
}

func TestReadFrameReaderPrecondition(t *testing.T) {
	for _, c := range []struct {
		name            string
		nilReader, nilR bool
		n               int64
	}{
		{"nil-reader", true, false, 0},
		{"nil-R", false, true, remainingBudget},
		{"reset", false, false, 5000001},
		{"reduced", false, false, remainingBudget - 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &readProbe{end: io.EOF}
			lr := &io.LimitedReader{R: r, N: c.n}
			if c.nilReader {
				lr = nil
			} else if c.nilR {
				lr.R = nil
			}
			frame, e := ReadFrame(lr)
			if !errors.Is(e, ErrReaderBound) || !zeroFrame(frame) || r.calls != 0 {
				t.Fatalf("err=%v calls=%d", e, r.calls)
			}
		})
	}
	cause := errors.New("injected")
	frame, e := ReadFrame(&io.LimitedReader{R: &readProbe{left: 17, end: cause}, N: remainingBudget})
	if !errors.Is(e, ErrRead) || !errors.Is(e, cause) || !zeroFrame(frame) {
		t.Fatalf("read failure %v", e)
	}
}

// Expected windows follow RFC 8878 section 3.1.1.1.2 from each fixture's header
// byte: single-segment frames use their content size.
func TestReadFrameWindow(t *testing.T) {
	want := map[string]struct{ window, size uint64 }{
		"valid-one":           {101, 101},
		"window-at-64MiB":     {64 << 20, 101},
		"window-below-64MiB":  {60 << 20, 101},
		"content-size-2-byte": {300, 300},
		"content-size-4-byte": {2 << 20, 101},
		"content-size-8-byte": {2 << 20, 101},
	}
	f := loadFixtures(t)
	seen := 0
	for _, c := range f.Cases {
		w, ok := want[c.Name]
		if !ok {
			continue
		}
		seen++
		b, e := c.body()
		if e != nil {
			t.Fatal(e)
		}
		frame, e := ReadFrame(&io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget})
		if e != nil {
			t.Fatalf("%s: %v", c.Name, e)
		}
		if frame.Window() != w.window || frame.ContentSize() != w.size || frame.ContentSize() != uint64(c.PlainBytes) {
			t.Fatalf("%s: window %d size %d, want %d %d", c.Name, frame.Window(), frame.ContentSize(), w.window, w.size)
		}
	}
	if seen != len(want) {
		t.Fatalf("found %d of %d window fixtures", seen, len(want))
	}
	for _, c := range []struct {
		b            []byte
		window, size uint64
	}{
		{rawFrame(0, 0x24, 0, nil), 0, 0},
		{rawFrame(4, 0x24, 0, []byte("abc\n")), 4, 4},
		{rawFrame(4, 0x44, 0x00, []byte("abc\n")), 1 << 10, 260},
		{rawFrame(4, 0x84, 0x07, []byte("abc\n")), 1<<10 + 7<<7, 4},
		{rawFrame(4, 0xc4, 0x58, []byte("abc\n")), 2 << 20, 4},
		{rawFrame(1<<26, 0xa4, 0, []byte("abc\n")), 1 << 26, 1 << 26},
	} {
		frame, e := ReadFrame(&io.LimitedReader{R: bytes.NewReader(c.b), N: remainingBudget})
		if e != nil || frame.Window() != c.window || frame.ContentSize() != c.size {
			t.Fatalf("%x: window %d size %d err %v, want %d %d", c.b[:8], frame.Window(), frame.ContentSize(), e, c.window, c.size)
		}
	}
}

func zeroFrame(f Frame) bool { return f.data == nil && f.size == 0 && f.window == 0 }

// blockFrame builds structural inputs independently of the codec. Even invalid
// entropy and zero-output RLE blocks must pay one header visit.
func blockFrame(size uint64, count int, kind byte) []byte {
	b := rawFrame(size, 0xc4, 0x68, nil)[:14]
	for i := 0; i < count; i++ {
		h := kind << 1
		if i == count-1 {
			h |= 1
		}
		b = append(b, h, 0, 0)
		if kind == 1 {
			b = append(b, 0)
		}
	}
	return append(b, 0, 0, 0, 0)
}

func TestBlockHeaderLimit(t *testing.T) {
	for _, size := range []uint64{0, 103, 128<<10 - 1, 128 << 10, 128<<10 + 1, 4 << 20, 64 << 20} {
		cap := int(1 + (max(size, 128<<10)+128<<10-1)/(128<<10))
		for _, kind := range []byte{0, 1, 2} {
			for _, extra := range []int{0, 1} {
				t.Run(fmt.Sprintf("%d/%d/%d", size, kind, extra), func(t *testing.T) {
					b := blockFrame(size, cap+extra, kind)
					var visits uint64
					_, _, err := inspectFrameCount(b, &visits)
					if visits != uint64(cap+extra) {
						t.Fatalf("header visits=%d", visits)
					}
					if extra == 0 && err != nil || extra == 1 && !errors.Is(err, ErrFrame) {
						t.Fatalf("headers=%d cap=%d: %v", cap+extra, cap, err)
					}
					if extra == 1 {
						// Overflow must win even when checksum is absent or trailing bytes follow.
						for _, broken := range [][]byte{b[:len(b)-4], append(b, 1)} {
							if _, _, err := inspectFrame(broken); !errors.Is(err, ErrFrame) {
								t.Fatalf("overflow precedence: %v", err)
							}
						}
					}
				})
			}
		}
	}
	b := blockFrame(103, 2, 0)
	for n := 0; n < 3; n++ {
		var visits uint64
		if _, _, err := inspectFrameCount(b[:17+n], &visits); !errors.Is(err, ErrFrame) || visits != 1 {
			t.Fatalf("truncated header %d: %v", n, err)
		}
	}
	attack := blockFrame(103, 1_660_000, 0)
	var visits uint64
	if _, _, err := inspectFrameCount(attack, &visits); !errors.Is(err, ErrFrame) || visits != 3 {
		t.Fatalf("empty-block attack: %v", err)
	}
}

func TestBlockFixtureStages(t *testing.T) {
	for _, c := range loadFixtures(t).Cases {
		if c.Name != "bomb-small-claim" && c.Name != "content-size-too-small" {
			continue
		}
		b, err := c.body()
		if err != nil {
			t.Fatal(err)
		}
		f, err := ReadFrame(&io.LimitedReader{R: bytes.NewReader(b), N: remainingBudget})
		if c.Name == "bomb-small-claim" {
			var visits uint64
			inspectFrameCount(b, &visits)
			if visits != 3 {
				t.Fatalf("bomb header visits=%d", visits)
			}
			if !errors.Is(err, ErrFrame) {
				t.Fatalf("bomb reached codec: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			var visits uint64
			inspectFrameCount(b, &visits)
			if visits != 1 {
				t.Fatalf("within-cap header visits=%d", visits)
			}
			d, err := c.descriptor()
			if err != nil {
				t.Fatal(err)
			}
			lines, err := DecodeFrame(f, d, c.Device)
			if !errors.Is(err, ErrContentSize) || lines != nil {
				t.Fatalf("within-cap size lie: %v", err)
			}
		}
	}
}
