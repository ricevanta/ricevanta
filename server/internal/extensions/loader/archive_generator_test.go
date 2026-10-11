package loader

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

type archiveEntry struct {
	name string
	data []byte
}

func tarFixture(t testing.TB, entries ...archiveEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Size: int64(len(e.data)), Mode: 0644, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func compressFixture(t testing.TB, b []byte) []byte {
	t.Helper()
	w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(8<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	return w.EncodeAll(b, nil)
}
func controlEntries() []archiveEntry {
	return []archiveEntry{{"extension.yaml", []byte("a: b\n")}, {"envelope.json", []byte("{}")}}
}
func checksumHeader(h []byte) {
	for i := 148; i < 156; i++ {
		h[i] = ' '
	}
	sum := 0
	for _, c := range h[:512] {
		sum += int(c)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
}
func fieldHeader(h []byte, start, end int, value string) {
	clear(h[start:end])
	copy(h[start:end], value)
	checksumHeader(h)
}
