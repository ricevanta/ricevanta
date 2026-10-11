package loader

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestTarMembers(t *testing.T) {
	entries := append([]archiveEntry{{"a", []byte("abc")}}, controlEntries()...)
	raw := tarFixture(t, entries...)
	m, e := walkTar(raw, 3)
	if e != nil || len(m) != 3 {
		t.Fatalf("%v", e)
	}
	r := tar.NewReader(bytes.NewReader(raw))
	for i := range m {
		h, e := r.Next()
		if e != nil || h.Name != m[i].path {
			t.Fatal("independent inventory")
		}
		b, e := io.ReadAll(r)
		if e != nil || !bytes.Equal(b, m[i].body) {
			t.Fatal("independent body")
		}
	}
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"checksum", func(b []byte) []byte { b[0] ^= 1; return b }, ErrArchive},
		{"trailer short", func(b []byte) []byte { return b[:len(b)-512] }, ErrArchive},
		{"trailer extra", func(b []byte) []byte { return append(b, make([]byte, 512)...) }, ErrArchive},
		{"padding", func(b []byte) []byte { b[515] = 1; return b }, ErrArchive},
		{"STAR", func(b []byte) []byte { b[500] = 1; checksumHeader(b); return b }, ErrArchive},
		{"base256", func(b []byte) []byte { b[124] = 128; checksumHeader(b); return b }, ErrArchive},
		{"negative", func(b []byte) []byte { fieldHeader(b, 124, 136, "-1"); return b }, ErrArchive},
		{"embedded numeric space", func(b []byte) []byte { fieldHeader(b, 124, 136, "1 1"); return b }, ErrArchive},
		{"extent", func(b []byte) []byte { fieldHeader(b, 124, 136, "00000000010"); return b }, ErrArchiveLimit},
		{"name padding", func(b []byte) []byte { b[2] = 'a'; checksumHeader(b); return b }, ErrArchive},
		{"device", func(b []byte) []byte { fieldHeader(b, 329, 337, "1"); return b }, ErrArchive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := walkTar(tc.edit(bytes.Clone(raw)), 3)
			if !errors.Is(e, tc.want) {
				t.Fatalf("%v want %v", e, tc.want)
			}
		})
	}
	for _, typ := range []byte{'1', '2', '3', '4', '5', '6', 'x', 'g', 'L', 'K', 'S'} {
		b := bytes.Clone(raw)
		b[156] = typ
		checksumHeader(b)
		_, e := walkTar(b, 3)
		if !errors.Is(e, ErrMember) {
			t.Fatalf("type %c: %v", typ, e)
		}
	}
	for _, path := range []string{"/a", "A", "a\\b", "a/../b", "con.txt", "lpt1", "a.", "extension.yaml/a", "envelope.json/a", strings.Repeat("a", 64), ""} {
		b := bytes.Clone(raw)
		fieldHeader(b, 0, 100, path)
		_, e := walkTar(b, 3)
		if !errors.Is(e, ErrMember) {
			t.Fatalf("path %q: %v", path, e)
		}
	}
	_, e = walkTar(raw, 2)
	if !errors.Is(e, ErrArchiveLimit) {
		t.Fatal(e)
	}
	_, e = walkTar(tarFixture(t, archiveEntry{"a", nil}), 1)
	if !errors.Is(e, ErrControls) {
		t.Fatal(e)
	}
}
func TestTarAliases(t *testing.T) {
	for _, names := range [][]string{{"a", "a"}, {"a", "a/b"}, {"a/b", "a"}, {"extension.yaml", "extension.yaml"}, {"a/b", "a/b"}} {
		entries := controlEntries()
		for _, n := range names {
			entries = append(entries, archiveEntry{n, nil})
		}
		raw := tarFixture(t, entries...)
		if names[0] == "a/b" && names[1] == "a/b" {
			fieldHeader(raw[2560:], 0, 100, "b")
			fieldHeader(raw[2560:], 345, 500, "a")
		}
		_, e := walkTar(raw, 1)
		if !errors.Is(e, ErrMemberDuplicate) {
			t.Fatalf("%v: %v", names, e)
		}
	}
}
func TestArchivePrecedence(t *testing.T) {
	raw := tarFixture(t, append([]archiveEntry{{"a", []byte("abc")}}, controlEntries()...)...)
	b := bytes.Clone(raw)
	b[156] = 'x'
	fieldHeader(b, 124, 136, "77777777777")
	_, e := walkTar(b, 1)
	if !errors.Is(e, ErrArchiveLimit) {
		t.Fatal(e)
	}
	b[0] ^= 1
	_, e = walkTar(b, 1)
	if !errors.Is(e, ErrArchive) {
		t.Fatal(e)
	}
}

func TestTarInventoryBound(t *testing.T) {
	entries := controlEntries()
	prefix := strings.Repeat("a", 60) + "/" + strings.Repeat("b", 60) + "/"
	for i := 0; i < 4096; i++ {
		entries = append(entries, archiveEntry{fmt.Sprintf("%sf%04d", prefix, i), nil})
	}
	m, e := walkTar(tarFixture(t, entries...), 1)
	if e != nil || len(m) != 4098 {
		t.Fatalf("inventory: %d %v", len(m), e)
	}
	if cap(m) > 4098 {
		t.Fatalf("inventory capacity %d exceeds 4098", cap(m))
	}
	for _, names := range [][]string{{"a", "a-keep", "a/b"}, {"a/b", "a-keep", "a"}, {"envelope.json", "envelope.json"}} {
		entries = controlEntries()
		for _, n := range names {
			entries = append(entries, archiveEntry{n, []byte("x")})
		}
		raw := tarFixture(t, entries...)
		// Controls occupy four blocks. Each later member occupies two blocks.
		duplicateOffset := 2048 + (len(names)-1)*1024
		raw[duplicateOffset+513] = 1
		raw[len(raw)-1024] = 1
		if _, e = walkTar(raw, 10); !errors.Is(e, ErrMemberDuplicate) {
			t.Fatalf("first-header precedence: %v", e)
		}
	}
}

func TestTarRawMetadataProfile(t *testing.T) {
	raw := tarFixture(t, controlEntries()...)
	for _, edit := range []func([]byte){
		func(h []byte) { fieldHeader(h, 100, 108, "        ") },
		func(h []byte) { fieldHeader(h, 108, 116, "  0000  ") },
		func(h []byte) { fieldHeader(h, 265, 297, "\xff") },
	} {
		b := bytes.Clone(raw)
		edit(b)
		if _, e := walkTar(b, 1); e != nil {
			t.Fatalf("raw permitted metadata: %v", e)
		}
	}
}

func TestTarRoleBoundaries(t *testing.T) {
	for _, role := range []struct {
		name string
		cap  uint64
	}{{"extension.yaml", 1 << 20}, {"envelope.json", 2 << 20}, {"a", 3}} {
		for _, delta := range []int{-1, 0, 1} {
			size := int(role.cap) + delta
			entries := controlEntries()
			if role.name == "a" {
				entries = append(entries, archiveEntry{role.name, make([]byte, size)})
			} else {
				for i := range entries {
					if entries[i].name == role.name {
						entries[i].data = make([]byte, size)
					}
				}
			}
			_, e := walkTar(tarFixture(t, entries...), 3)
			want := error(nil)
			if delta > 0 {
				want = ErrArchiveLimit
			}
			if !errors.Is(e, want) {
				t.Fatalf("%s size %d: %v want %v", role.name, size, e, want)
			}
		}
	}
	for _, order := range [][]archiveEntry{
		{{"a", nil}, {"envelope.json", nil}, {"extension.yaml", nil}},
		{{"extension.yaml", nil}, {"a", nil}, {"envelope.json", nil}},
		{{"envelope.json", nil}, {"extension.yaml", nil}, {"a", nil}},
	} {
		if m, e := walkTar(tarFixture(t, order...), 1); e != nil || len(m) != 3 {
			t.Fatalf("controls order: %v", e)
		}
	}
	for _, entries := range [][]archiveEntry{nil, {{"extension.yaml", nil}}, {{"envelope.json", nil}}} {
		if _, e := walkTar(tarFixture(t, entries...), 1); !errors.Is(e, ErrControls) {
			t.Fatalf("missing controls: %v", e)
		}
	}
	entries := controlEntries()
	for i := 0; i < 4097; i++ {
		entries = append(entries, archiveEntry{fmt.Sprintf("f%04d", i), nil})
	}
	if _, e := walkTar(tarFixture(t, entries...), 1); !errors.Is(e, ErrArchiveLimit) {
		t.Fatalf("member count: %v", e)
	}
	entries = append(controlEntries(), archiveEntry{"a", []byte("ab")}, archiveEntry{"b", []byte("cd")})
	if _, e := walkTar(tarFixture(t, entries...), 3); !errors.Is(e, ErrArchiveLimit) {
		t.Fatalf("sum: %v", e)
	}
}

func TestTarPhysicalBoundaries(t *testing.T) {
	raw := tarFixture(t, append([]archiveEntry{{"a", []byte("abc")}}, controlEntries()...)...)
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"no trailer", func(b []byte) []byte { return b[:len(b)-1024] }, ErrArchive},
		{"nonzero second trailer", func(b []byte) []byte { b[len(b)-1] = 1; return b }, ErrArchive},
		{"partial header", func(b []byte) []byte { return b[:511] }, ErrArchive},
		{"body extent", func(b []byte) []byte { return b[:514] }, ErrArchive},
		{"padding extent", func(b []byte) []byte { return b[:1023] }, ErrArchive},
		{"GNU magic", func(b []byte) []byte { fieldHeader(b, 257, 265, "ustar  "); return b }, ErrArchive},
		{"bad version", func(b []byte) []byte { fieldHeader(b, 263, 265, "01"); return b }, ErrArchive},
		{"link target", func(b []byte) []byte { fieldHeader(b, 157, 257, "a"); return b }, ErrMember},
		{"group padding", func(b []byte) []byte { b[298] = 1; checksumHeader(b); return b }, ErrArchive},
		{"size overflow", func(b []byte) []byte { fieldHeader(b, 124, 136, "77777777777"); return b }, ErrArchiveLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.edit(bytes.Clone(raw))
			a, m, e := readArchive(archiveReader(compressFixture(t, b), 3), 3)
			if !errors.Is(e, tc.want) || a != nil || m != nil {
				t.Fatalf("got %v want %v, partial=%t", e, tc.want, a != nil || m != nil)
			}
		})
	}
	for _, typ := range []byte{'7', 'D', 'V', 'X', 0xff} {
		b := bytes.Clone(raw)
		b[156] = typ
		checksumHeader(b)
		if _, e := walkTar(b, 3); !errors.Is(e, ErrMember) {
			t.Fatalf("type %x: %v", typ, e)
		}
	}
	for _, path := range []string{"a//b", "a/", "a:b", "a/%62", "a/./b", "prn.foo", "aux", "nul", "com9.x", "lpt9.x", "_a", "-a", "a/CON", "a/é"} {
		b := bytes.Clone(raw)
		fieldHeader(b, 0, 100, path)
		if _, e := walkTar(b, 3); !errors.Is(e, ErrMember) {
			t.Fatalf("path %q: %v", path, e)
		}
	}
	// Every numeric field follows the same unsigned-octal profile.
	for _, span := range [][2]int{{100, 108}, {108, 116}, {116, 124}, {124, 136}, {136, 148}, {329, 337}, {337, 345}} {
		b := bytes.Clone(raw)
		fieldHeader(b, span[0], span[1], "8")
		if _, e := walkTar(b, 3); !errors.Is(e, ErrArchive) {
			t.Fatalf("numeric %v: %v", span, e)
		}
	}
}

func TestTarTextAndNumericPadding(t *testing.T) {
	entries := append(controlEntries(), archiveEntry{strings.Repeat("a", 63) + "/" + strings.Repeat("b", 63) + "/" + strings.Repeat("c", 27) + "/" + strings.Repeat("d", 63) + "/" + strings.Repeat("e", 20), nil})
	raw := tarFixture(t, entries...)
	if _, e := walkTar(raw, 1); e != nil {
		t.Fatalf("240-byte path: %v", e)
	}
	raw = tarFixture(t, controlEntries()...)
	for _, v := range []string{"\x00 0005 \x00", "000000000005"} {
		b := bytes.Clone(raw)
		fieldHeader(b, 124, 136, v)
		if m, e := walkTar(b, 1); e != nil || len(m[0].body) != 5 {
			t.Fatalf("padded size: %v", e)
		}
	}
	for _, span := range [][2]int{{0, 100}, {157, 257}, {265, 297}, {297, 329}, {345, 500}} {
		b := bytes.Clone(raw)
		b[span[0]] = 0
		b[span[0]+1] = 'a'
		checksumHeader(b)
		if _, e := walkTar(b, 1); !errors.Is(e, ErrArchive) {
			t.Fatalf("text padding %v: %v", span, e)
		}
	}
	b := bytes.Clone(raw)
	copy(b[265:297], strings.Repeat("a", 32))
	checksumHeader(b)
	if _, e := walkTar(b, 1); e != nil {
		t.Fatalf("full text field: %v", e)
	}
	b = bytes.Clone(raw)
	b[156] = 0
	checksumHeader(b)
	if _, e := walkTar(b, 1); e != nil {
		t.Fatalf("NUL regular type: %v", e)
	}
}

func TestTarDeclaredFileCeilings(t *testing.T) {
	raw := tarFixture(t, append([]archiveEntry{{"a", nil}}, controlEntries()...)...)
	for _, f := range []uint64{64 << 20, 1 << 30} {
		for _, n := range []uint64{f - 1, f, f + 1} {
			b := bytes.Clone(raw)
			fieldHeader(b, 124, 136, fmt.Sprintf("%011o", n))
			_, e := walkTar(b, f)
			want := ErrArchive
			if n > f {
				want = ErrArchiveLimit
			}
			if !errors.Is(e, want) {
				t.Fatalf("F=%d declared=%d: %v want %v", f, n, e, want)
			}
		}
	}
	// Duplicate detection precedes body truncation in the same header.
	b := tarFixture(t, archiveEntry{"a", nil}, archiveEntry{"a", []byte("x")})
	b = b[:1024]
	if _, e := walkTar(b, 1); !errors.Is(e, ErrMemberDuplicate) {
		t.Fatalf("duplicate before extent: %v", e)
	}
	// A path violation precedes missing controls and a broken trailer.
	b = tarFixture(t, archiveEntry{"a", nil})
	fieldHeader(b, 0, 100, "A")
	b[len(b)-1] = 1
	if _, e := walkTar(b, 1); !errors.Is(e, ErrMember) {
		t.Fatalf("path before trailer: %v", e)
	}
}
