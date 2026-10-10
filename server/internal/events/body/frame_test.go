package body

import (
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
			size, e := inspectFrame(b)
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
			if e != nil && size != 0 {
				t.Fatal("nonzero size on error")
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
			_, e := inspectFrame(c.b)
			if !errors.Is(e, c.want) {
				t.Fatalf("error=%v want=%v", e, c.want)
			}
		})
	}
	b := rawFrame(3, 0x24, 0, []byte{10})
	binary.LittleEndian.PutUint32(b[6:10], 3<<3|3)
	b[9] = 10
	if _, e := inspectFrame(b); e != nil {
		t.Fatalf("RLE single byte: %v", e)
	}
	for n := 0; n < 6; n++ {
		if _, e := inspectFrame(rawFrame(1, 0x24, 0, []byte{0})[:n]); !errors.Is(e, ErrFrame) {
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
