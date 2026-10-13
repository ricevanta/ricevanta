package loader

import (
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func assertPackageCommitments(t testing.TB, p Package, archive []byte) {
	t.Helper()
	if p.PackageSHA256 != sha256.Sum256(archive) || p.ManifestSHA256 != sha256.Sum256(p.Manifest) || p.EnvelopeSHA256 != sha256.Sum256(p.Envelope) {
		t.Fatal("exact hash disagreement")
	}
	for i, f := range p.Files {
		if f.Size != uint64(len(f.Bytes)) || f.SHA256 != sha256.Sum256(f.Bytes) || i > 0 && p.Files[i-1].Path >= f.Path {
			t.Fatal("file commitment/order disagreement")
		}
	}
}
func FuzzLoad(f *testing.F) {
	c := corpus(f)
	key := keyPublic(f)
	for _, v := range c.Cases {
		f.Add(packageArchive(f, []byte(v.ArchiveManifest), []byte(v.Envelope), fixtureFiles(f)...), uint64(0))
	}
	f.Add([]byte{}, uint64(1))
	f.Add([]byte("not zstd"), ^uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, limit uint64) {
		if len(b) > 1<<20 {
			return
		}
		p, e := loadBytes(b, key, Options{MaxTotalFileBytes: limit})
		if e != nil {
			if !reflect.DeepEqual(p, Package{}) {
				t.Fatal("partial package")
			}
			return
		}
		assertPackageCommitments(t, p, b)
		if e := manifest.Validate(p.Document, manifest.Options{MaxTotalFileBytes: limit}); e != nil {
			t.Fatal("accepted invalid manifest")
		}
	})
}
func FuzzVerifiedYAML(f *testing.F) {
	for _, s := range []string{"a: [1, true, {}]", "a: b\na: c", "a: ! x", "a: [", "a: null", "{}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > manifest.MaxManifestBytes+1 {
			return
		}
		// The independent scanner and pinned Node oracle run before the candidate.
		assertAgreement(t, b)
		m, u, e := decodeVerifiedYAMLAccounted(b)
		if u.bytes > 64<<20 || u.objects > 1000000 {
			t.Fatal("usage ceiling")
		}
		if e != nil {
			if m != nil {
				t.Fatal("partial map")
			}
			return
		}
		if m == nil {
			t.Fatal("nil successful map")
		}
		assertConvertedTypes(t, m)
	})
}
func FuzzTar(f *testing.F) {
	f.Add(tarFixture(f, controlEntries()...))
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	f.Add([]byte("ustar"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2<<20 {
			return
		}
		members, e := walkTar(b, 64<<20)
		if e != nil {
			if members != nil {
				t.Fatal("partial members")
			}
			return
		}
		if len(members) > 4098 {
			t.Fatal("member ceiling")
		}
		controls := 0
		for i, m := range members {
			if !portableMember(m.path) {
				t.Fatal("nonportable member")
			}
			if m.path == "extension.yaml" || m.path == "envelope.json" {
				controls++
			}
			for _, prior := range members[:i] {
				if m.path == prior.path || pathAncestor(m.path, prior.path) || pathAncestor(prior.path, m.path) {
					t.Fatal("member collision")
				}
			}
		}
		if controls != 2 {
			t.Fatal("control count")
		}
	})
}
