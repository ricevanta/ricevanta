package loader

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
)

type countedReadCause struct{ calls int }

func (e *countedReadCause) Error() string { e.calls++; return "small-cause-marker" }

type panicReadCause struct{}

func (*panicReadCause) Error() string          { panic("cause Error invoked") }
func (*panicReadCause) String() string         { panic("cause String invoked") }
func (*panicReadCause) Format(fmt.State, rune) { panic("cause Format invoked") }
func (*panicReadCause) Is(error) bool          { panic("cause Is invoked") }
func (*panicReadCause) As(any) bool            { panic("cause As invoked") }
func (*panicReadCause) Unwrap() error          { panic("cause Unwrap invoked") }

type boundedReadSource struct {
	data  []byte
	cause error
	zeros bool
}

func (r *boundedReadSource) Read(p []byte) (int, error) {
	if r.zeros {
		return 0, nil
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) > 0 {
		return n, nil
	}
	return n, r.cause
}

func TestReadErrorBounded(t *testing.T) {
	const f = uint64(1)
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for _, data := range [][]byte{nil, []byte("small bytes")} {
		cause := &countedReadCause{}
		p, err := Load(&io.LimitedReader{R: &boundedReadSource{data: data, cause: cause}, N: int64(f + archiveOverhead + compressedOverhead + 1)}, key, Options{MaxTotalFileBytes: f})
		if cause.calls != 0 {
			t.Fatalf("Load formatted cause %d times", cause.calls)
		}
		if !reflect.DeepEqual(p, Package{}) {
			t.Fatal("nonzero failed package")
		}
		if err == nil || !errors.Is(err, ErrRead) || !errors.Is(err, cause) || errors.Unwrap(err) != cause {
			t.Fatal("lost sentinel/cause identity")
		}
		for range 5 {
			if err.Error() != "extension read" || fmt.Sprintf("%v", err) != "extension read" {
				t.Fatal("nonstatic text")
			}
		}
		if cause.calls != 0 {
			t.Fatal("returned error formatted cause")
		}
	}
	t.Run("panic-cause", func(t *testing.T) {
		cause := &panicReadCause{}
		p, err := Load(&io.LimitedReader{R: &boundedReadSource{cause: cause}, N: int64(f + archiveOverhead + compressedOverhead + 1)}, key, Options{MaxTotalFileBytes: f})
		if !reflect.DeepEqual(p, Package{}) || err.Error() != "extension read" || !errors.Is(err, ErrRead) || !errors.Is(err, cause) || errors.Unwrap(err) != cause {
			t.Fatal("panic cause preservation")
		}
	})
	t.Run("no-progress", func(t *testing.T) {
		p, err := Load(&io.LimitedReader{R: &boundedReadSource{zeros: true}, N: int64(f + archiveOverhead + compressedOverhead + 1)}, key, Options{MaxTotalFileBytes: f})
		if !reflect.DeepEqual(p, Package{}) || err.Error() != "extension read" || !errors.Is(err, ErrRead) || !errors.Is(err, io.ErrNoProgress) || errors.Unwrap(err) != io.ErrNoProgress {
			t.Fatal("no-progress identity")
		}
	})
	t.Run("extra-byte-before-error", func(t *testing.T) {
		cause := &panicReadCause{}
		data := bytes.Repeat([]byte{'x'}, int(f+archiveOverhead+compressedOverhead+1))
		p, err := Load(&io.LimitedReader{R: &boundedReadSource{data: data, cause: cause}, N: int64(len(data))}, key, Options{MaxTotalFileBytes: f})
		if !reflect.DeepEqual(p, Package{}) || err != ErrCompressedLimit {
			t.Fatal("byte/error precedence")
		}
	})
	t.Run("bytes-plus-EOF", func(t *testing.T) {
		payload := jsonPayload(t, baseDocument(t))
		archive := packageArchive(t, payload, signedEnvelope(t, payload), fixtureFiles(t)...)
		body := archiveReader(nil, 64<<20)
		body.R = &boundedReadSource{data: archive, cause: io.EOF}
		p, err := Load(body, keyPublic(t), Options{})
		if err != nil || len(p.Archive) != len(archive) {
			t.Fatalf("bytes/EOF: %v", err)
		}
	})
}
