package celdecl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

type chunkReader struct {
	data  []byte
	chunk int
	end   error
	read  int
	calls int
	empty int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	r.calls++
	if r.empty > 0 {
		r.empty--
		return 0, nil
	}
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.read += n
	if len(r.data) == 0 {
		return n, r.end
	}
	return n, nil
}
func checkLoad(t testing.TB, r io.Reader, want, cause error) {
	t.Helper()
	d, err := Load(r)
	if want == nil {
		if d == nil || err != nil {
			t.Fatalf("Load: %v %v", d, err)
		}
		return
	}
	if d != nil || !errors.Is(err, want) {
		t.Fatalf("Load: %v %v, want %v", d, err, want)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("lost cause: %v", err)
	}
}
func TestLoadReaderErrors(t *testing.T) {
	cause := errors.New("test read")
	checkLoad(t, nil, ErrRead, nil)
	checkLoad(t, &chunkReader{data: canonical(t), chunk: 1, end: io.EOF}, nil, nil)
	checkLoad(t, &chunkReader{data: canonical(t), end: io.EOF}, nil, nil)
	checkLoad(t, &chunkReader{data: canonical(t), end: cause}, ErrRead, cause)
	checkLoad(t, &chunkReader{data: []byte("!"), end: cause}, ErrRead, cause)
	wrapped := fmt.Errorf("wrapped: %w", io.EOF)
	checkLoad(t, &chunkReader{data: canonical(t), end: wrapped}, ErrRead, wrapped)
}
func TestLoadReadLimit(t *testing.T) {
	cause := errors.New("test read")
	r := &chunkReader{data: bytes.Repeat([]byte("!"), MaxBytes+1), end: cause}
	checkLoad(t, r, ErrSize, nil)
	if r.read != 262145 {
		t.Fatalf("read %d", r.read)
	}
	r = &chunkReader{data: bytes.Repeat([]byte("!"), MaxBytes+100), end: io.EOF}
	checkLoad(t, r, ErrSize, nil)
	if r.read != 262145 {
		t.Fatalf("read %d", r.read)
	}
	b := canonical(t)
	checkLoad(t, bytes.NewReader(append(b, bytes.Repeat([]byte(" "), MaxBytes-len(b))...)), nil, nil)
}

type resetReader struct {
	positive int
	empty    int
	calls    int
}

func (r *resetReader) Read(p []byte) (int, error) {
	r.calls++
	if r.empty < 99 {
		r.empty++
		return 0, nil
	}
	if r.positive < 2 {
		r.positive++
		r.empty = 0
		p[0] = ' '
		return 1, nil
	}
	return 0, nil
}
func TestLoadNoProgress(t *testing.T) {
	r := &chunkReader{empty: 1000, end: io.EOF}
	checkLoad(t, r, ErrRead, io.ErrNoProgress)
	if r.calls != 100 {
		t.Fatalf("calls %d", r.calls)
	}
	s := &resetReader{}
	checkLoad(t, s, ErrRead, io.ErrNoProgress)
	if s.calls != 300 {
		t.Fatalf("reset calls %d", s.calls)
	}
}
