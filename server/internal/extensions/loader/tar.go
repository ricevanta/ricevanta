package loader

import (
	"archive/tar"
	"bytes"
	"strings"
)

type member struct {
	path string
	body []byte
}

func zero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
func tarText(b []byte) (string, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), true
	}
	if !zero(b[i:]) {
		return "", false
	}
	return string(b[:i]), true
}
func tarOctal(b []byte) (uint64, bool) {
	padding := func(c byte) bool { return c == 0 || c == ' ' }
	for len(b) > 0 && padding(b[0]) {
		b = b[1:]
	}
	for len(b) > 0 && padding(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	var n uint64
	for _, c := range b {
		if c < '0' || c > '7' || n > (^uint64(0)-uint64(c-'0'))/8 {
			return 0, false
		}
		n = n*8 + uint64(c-'0')
	}
	return n, true
}
func portableMember(path string) bool {
	if len(path) == 0 || len(path) > 240 {
		return false
	}
	if path == "extension.yaml" || path == "envelope.json" {
		return true
	}
	if strings.HasPrefix(path, "extension.yaml/") || strings.HasPrefix(path, "envelope.json/") {
		return false
	}
	for _, s := range strings.Split(path, "/") {
		if len(s) == 0 || len(s) > 63 || s[0] < 'a' && (s[0] < '0' || s[0] > '9') || s[0] > 'z' || strings.HasSuffix(s, ".") {
			return false
		}
		for _, c := range []byte(s) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
		stem, _, _ := strings.Cut(s, ".")
		switch stem {
		case "con", "prn", "aux", "nul":
			return false
		}
		if len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9' {
			return false
		}
	}
	return true
}

func walkTar(b []byte, fileLimit uint64) ([]member, error) {
	var members []member
	var total uint64
	files, controls := 0, 0
	for off := 0; ; {
		if len(b)-off < 512 {
			return nil, ErrArchive
		}
		h := b[off : off+512]
		if zero(h) {
			if len(b)-off != 1024 || !zero(b[off:]) {
				return nil, ErrArchive
			}
			if controls != 2 {
				return nil, ErrControls
			}
			return members, nil
		}
		if string(h[257:263]) != "ustar\x00" || string(h[263:265]) != "00" || !zero(h[500:512]) {
			return nil, ErrArchive
		}
		var numbers [8]uint64
		spans := [8][2]int{{100, 108}, {108, 116}, {116, 124}, {124, 136}, {136, 148}, {148, 156}, {329, 337}, {337, 345}}
		for i, s := range spans {
			n, ok := tarOctal(h[s[0]:s[1]])
			if !ok {
				return nil, ErrArchive
			}
			numbers[i] = n
		}
		sum := uint64(0)
		for i, c := range h {
			if i >= 148 && i < 156 {
				sum += 32
			} else {
				sum += uint64(c)
			}
		}
		if sum != numbers[5] || numbers[6] != 0 || numbers[7] != 0 {
			return nil, ErrArchive
		}
		var texts [5]string
		textSpans := [5][2]int{{0, 100}, {157, 257}, {265, 297}, {297, 329}, {345, 500}}
		for i, s := range textSpans {
			v, ok := tarText(h[s[0]:s[1]])
			if !ok {
				return nil, ErrArchive
			}
			texts[i] = v
		}
		name := texts[0]
		if texts[4] != "" {
			name = texts[4] + "/" + name
		}
		size := numbers[3]
		switch name {
		case "extension.yaml":
			if size > 1<<20 {
				return nil, ErrArchiveLimit
			}
		case "envelope.json":
			if size > 2<<20 {
				return nil, ErrArchiveLimit
			}
		default:
			if files == 4096 || size > min(fileLimit, uint64(1<<30)) || size > fileLimit-total {
				return nil, ErrArchiveLimit
			}
			files++
			total += size
		}
		if len(members) == 4098 {
			return nil, ErrArchiveLimit
		}
		if (h[156] != 0 && h[156] != '0') || texts[1] != "" || !portableMember(name) {
			return nil, ErrMember
		}
		for _, existing := range members {
			if existing.path == name || pathAncestor(existing.path, name) || pathAncestor(name, existing.path) {
				return nil, ErrMemberDuplicate
			}
		}
		off += 512
		if size > uint64(len(b)-off) {
			return nil, ErrArchive
		}
		end := off + int(size)
		padding := (512 - size%512) % 512
		if padding > uint64(len(b)-end) || !zero(b[end:end+int(padding)]) {
			return nil, ErrArchive
		}
		// Only a checked regular header and its exact body reach archive/tar.
		r := tar.NewReader(bytes.NewReader(b[off-512 : end+int(padding)]))
		header, err := r.Next()
		if err != nil || header.Name != name || header.Size < 0 || uint64(header.Size) != size || (header.Format != tar.FormatUSTAR && header.Format != tar.FormatUnknown) {
			return nil, ErrArchive
		}
		if len(members) == cap(members) {
			capacity := min(4098, max(16, cap(members)*2))
			next := make([]member, len(members), capacity)
			copy(next, members)
			members = next
		}
		members = append(members, member{name, b[off:end:end]})
		if name == "extension.yaml" || name == "envelope.json" {
			controls++
		}
		off = end + int(padding)
	}
}

// pathAncestor compares literal paths without allocating a slash suffix.
func pathAncestor(parent, child string) bool {
	return len(child) > len(parent) && child[len(parent)] == '/' && strings.HasPrefix(child, parent)
}
