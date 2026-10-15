package console_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

var devIdentity = buildinfo.Identity{Version: "0.0.0-local", Commit: "unknown", Channel: "local", SourceEpoch: 0}

// fixture loads testdata/dist into a MapFS and returns it with the
// committed manifest.json.
func fixture(t testing.TB) (fstest.MapFS, []byte) {
	t.Helper()
	m := fstest.MapFS{}
	root := os.DirFS("testdata/dist")
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		m[p] = &fstest.MapFile{Data: data, Mode: 0o644}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return m, manifest
}

type manifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// canonical writes the manifest the way scripts/release/console_manifest.py
// does: sorted keys, no insignificant whitespace, one final LF.
func canonical(t testing.TB, entries []manifestEntry) []byte {
	t.Helper()
	data, err := json.Marshal(struct {
		Files  []manifestEntry `json:"files"`
		Schema string          `json:"schema"`
	}{entries, "ricevanta-console-manifest-v1"})
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func manifestFor(t testing.TB, m fstest.MapFS) []byte {
	t.Helper()
	var entries []manifestEntry
	for p, f := range m {
		sum := sha256.Sum256(f.Data)
		entries = append(entries, manifestEntry{p, hex.EncodeToString(sum[:]), len(f.Data)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return canonical(t, entries)
}

func TestCommittedManifestIsCanonical(t *testing.T) {
	m, manifest := fixture(t)
	if got := manifestFor(t, m); string(got) != string(manifest) {
		t.Fatalf("testdata/manifest.json is stale:\n%s\nwant\n%s", manifest, got)
	}
}

func TestVerifyFixture(t *testing.T) {
	m, manifest := fixture(t)
	if _, err := console.Verify(m, manifest, devIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := console.Verify(os.DirFS("testdata/dist"), manifest, devIdentity); err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ve *console.VerifyError
	if !errors.As(err, &ve) || ve.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestVerifyFailures(t *testing.T) {
	type mutate func(t *testing.T, m fstest.MapFS, manifest []byte) (fstest.MapFS, []byte, buildinfo.Identity)
	same := devIdentity
	cases := []struct {
		name string
		code string
		f    mutate
	}{
		{"changed byte", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			d := append([]byte(nil), m["assets/index-Bx1a2b3c.js"].Data...)
			d[0] ^= 1
			m["assets/index-Bx1a2b3c.js"].Data = d
			return m, mf, same
		}},
		{"changed size", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["index.html"].Data = append(m["index.html"].Data, ' ')
			return m, mf, same
		}},
		{"missing file", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			delete(m, "assets/unlisted.svg")
			return m, mf, same
		}},
		{"extra file", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/extra.js"] = &fstest.MapFile{Data: []byte("x")}
			return m, mf, same
		}},
		{"symlink in tree", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/link.js"] = &fstest.MapFile{Data: []byte("index-Bx1a2b3c.js"), Mode: fs.ModeSymlink}
			return m, mf, same
		}},
		{"identity version", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			id := devIdentity
			id.Version = "0.1.0-alpha.1"
			return m, mf, id
		}},
		{"identity commit", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			id := devIdentity
			id.Commit = "0123456789abcdef0123456789abcdef01234567"
			return m, mf, id
		}},
		{"identity channel", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			id := devIdentity
			id.Channel = "master"
			return m, mf, id
		}},
		{"identity epoch", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			id := devIdentity
			id.SourceEpoch = 1
			return m, mf, id
		}},
		{"missing build-info", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			delete(m, "build-info.json")
			return m, manifestFor(t, m), same
		}},
		{"build-info extra field", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["build-info.json"].Data = []byte(`{"channel":"local","commit":"unknown","sourceEpoch":0,"version":"0.0.0-local","x":1}`)
			return m, manifestFor(t, m), same
		}},
		{"build-info duplicate key", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["build-info.json"].Data = []byte(`{"channel":"local","channel":"local","commit":"unknown","sourceEpoch":0,"version":"0.0.0-local"}`)
			return m, manifestFor(t, m), same
		}},
		{"build-info string epoch", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["build-info.json"].Data = []byte(`{"channel":"local","commit":"unknown","sourceEpoch":"0","version":"0.0.0-local"}`)
			return m, manifestFor(t, m), same
		}},
		{"build-info float epoch", console.CodeIdentityMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["build-info.json"].Data = []byte(`{"channel":"local","commit":"unknown","sourceEpoch":0.0,"version":"0.0.0-local"}`)
			return m, manifestFor(t, m), same
		}},
		{"malformed vite manifest", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte(`{"index.html":{"file":"assets/index-Bx1a2b3c.js"}`)
			return m, manifestFor(t, m), same
		}},
		{"vite manifest trailing value", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte(`{"index.html":{"file":"assets/index-Bx1a2b3c.js"}} {}`)
			return m, manifestFor(t, m), same
		}},
		{"vite manifest duplicate key", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","file":"assets/unlisted.svg"}}`)
			return m, manifestFor(t, m), same
		}},
		{"vite manifest invalid utf8", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte("{\"index.html\":{\"file\":\"assets/index-Bx1a2b3c.js\",\"name\":\"\xff\"}}")
			return m, manifestFor(t, m), same
		}},
		{"vite manifest missing file field", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte(`{"index.html":{"src":"index.html"}}`)
			return m, manifestFor(t, m), same
		}},
		{"vite manifest lists absent file", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m[".vite/manifest.json"].Data = []byte(`{"index.html":{"file":"assets/absent.js"}}`)
			return m, manifestFor(t, m), same
		}},
		{"missing vite manifest", console.CodeViteManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			delete(m, ".vite/manifest.json")
			return m, manifestFor(t, m), same
		}},
		{"unknown extension", console.CodeUnknownType, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/index-Bx1a2b3c.js.map"] = &fstest.MapFile{Data: []byte("{}")}
			return m, manifestFor(t, m), same
		}},
		{"orphan sidecar", console.CodeUnknownType, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/orphan.js.br"] = &fstest.MapFile{Data: []byte("x")}
			return m, manifestFor(t, m), same
		}},
		{"unsorted manifest", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			var doc struct{ Files []manifestEntry }
			if err := json.Unmarshal(manifestFor(t, m), &doc); err != nil {
				t.Fatal(err)
			}
			doc.Files[0], doc.Files[1] = doc.Files[1], doc.Files[0]
			return m, canonical(t, doc.Files), same
		}},
		{"duplicate manifest entry", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			var doc struct{ Files []manifestEntry }
			if err := json.Unmarshal(manifestFor(t, m), &doc); err != nil {
				t.Fatal(err)
			}
			doc.Files = append(doc.Files[:1], doc.Files...)
			return m, canonical(t, doc.Files), same
		}},
		{"manifest wrong schema", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, []byte(strings.Replace(string(mf), "ricevanta-console-manifest-v1", "ricevanta-console-manifest-v2", 1)), same
		}},
		{"manifest extra field", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, []byte(strings.Replace(string(mf), `"size":15}`, `"size":15,"mtime":0}`, 1)), same
		}},
		{"manifest uppercase digest", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, []byte(strings.Replace(string(mf), "a3ea7e007d3d4dde", "A3EA7E007D3D4DDE", 1)), same
		}},
		{"manifest string size", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, []byte(strings.Replace(string(mf), `"size":15}`, `"size":"15"}`, 1)), same
		}},
		{"manifest trailing data", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, append(append([]byte(nil), mf...), "{}"...), same
		}},
		{"manifest empty files", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			return m, []byte(`{"files":[],"schema":"ricevanta-console-manifest-v1"}`), same
		}},
		{"device name path", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/con.txt"] = &fstest.MapFile{Data: []byte("x")}
			return m, manifestFor(t, m), same
		}},
		{"dot segment path", console.CodeManifestInvalid, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			m["assets/.hidden.js"] = &fstest.MapFile{Data: []byte("x")}
			return m, manifestFor(t, m), same
		}},
		{"missing index.html", console.CodeMismatch, func(t *testing.T, m fstest.MapFS, mf []byte) (fstest.MapFS, []byte, buildinfo.Identity) {
			delete(m, "index.html")
			return m, manifestFor(t, m), same
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, mf := fixture(t)
			m2, mf2, id := c.f(t, m, mf)
			_, err := console.Verify(m2, mf2, id)
			wantCode(t, err, c.code)
		})
	}
}

// schemaPath repeats the schema's path pattern. RE2 bounds repeat counts,
// so the 32-segment repetition is checked by splitting.
var schemaSegment = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9_.+-]{0,238}[A-Za-z0-9_+-])?\z`)

func schemaPath(p string) bool {
	if p == ".vite/manifest.json" {
		return true
	}
	segs := strings.Split(p, "/")
	if len(p) > 1024 || len(segs) > 32 {
		return false
	}
	for _, s := range segs {
		if !schemaSegment.MatchString(s) {
			return false
		}
	}
	return true
}

// validManifestSchema repeats schemas/server/console-manifest/v1/manifest.schema.json.
func validManifestSchema(t *testing.T, data []byte) {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 2 || string(doc["schema"]) != `"ricevanta-console-manifest-v1"` {
		t.Fatalf("top level %s", data)
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(doc["files"], &files); err != nil || len(files) < 1 || len(files) > 16384 {
		t.Fatalf("files: %v", err)
	}
	digest := regexp.MustCompile(`\A"[0-9a-f]{64}"\z`)
	size := regexp.MustCompile(`\A(0|[1-9][0-9]*)\z`)
	for _, f := range files {
		var p string
		if len(f) != 3 || json.Unmarshal(f["path"], &p) != nil || !schemaPath(p) ||
			!digest.Match(f["sha256"]) || !size.Match(f["size"]) {
			t.Fatalf("entry %v", f)
		}
	}
}

func TestManifestOutputValidatesAndIsUnchanged(t *testing.T) {
	m, manifest := fixture(t)
	tree, err := console.Verify(m, manifest, devIdentity)
	if err != nil {
		t.Fatal(err)
	}
	got := tree.Manifest()
	if string(got) != string(manifest) {
		t.Fatal("Manifest() changed the embedded bytes")
	}
	validManifestSchema(t, got)
}

func TestCSPMatchesRepositoryFile(t *testing.T) {
	data, err := os.ReadFile("../../../../console/security/csp.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("csp.txt must be one LF-terminated line")
	}
	if want := strings.TrimSuffix(string(data), "\n"); console.CSP != want {
		t.Fatalf("CSP constant differs from console/security/csp.txt:\n%q\n%q", console.CSP, want)
	}
}

// TestStrictJSONKeysAndEscapes covers release builds section 5.1 rules that
// encoding/json alone does not enforce: field names match byte for byte, keys
// equal under case or Unicode folding are duplicates, and an unpaired
// surrogate escape is invalid Unicode.
func TestStrictJSONKeysAndEscapes(t *testing.T) {
	type edit struct {
		file, data string
		code       string
	}
	buildInfo := func(s string) edit { return edit{"build-info.json", s, console.CodeIdentityMismatch} }
	vite := func(s string) edit { return edit{".vite/manifest.json", s, console.CodeViteManifestInvalid} }
	for name, e := range map[string]edit{
		"case variant field":     buildInfo(`{"Channel":"local","commit":"unknown","sourceEpoch":0,"version":"0.0.0-local"}`),
		"case-only duplicate":    buildInfo(`{"channel":"master","Channel":"local","commit":"unknown","sourceEpoch":0,"version":"0.0.0-local"}`),
		"unicode fold field":     buildInfo(`{"channel":"local","commit":"unknown","ſourceEpoch":0,"version":"0.0.0-local"}`),
		"lone high surrogate":    vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","name":"\ud800"}}`),
		"lone low surrogate":     vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","name":"\udc00x"}}`),
		"high then non-low":      vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","name":"\ud800A"}}`),
		"surrogate in key":       vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","\ud800":1}}`),
		"vite case variant file": vite(`{"index.html":{"File":"assets/index-Bx1a2b3c.js"}}`),
		"vite fold duplicate":    vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","FILE":"assets/unlisted.svg"}}`),
		"vite case variant css":  vite(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","CSS":["assets/absent.css"]}}`),
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := fixture(t)
			m[e.file].Data = []byte(strings.ReplaceAll(e.data, `ſ`, "ſ"))
			_, err := console.Verify(m, manifestFor(t, m), devIdentity)
			wantCode(t, err, e.code)
		})
	}
	// A valid surrogate pair stays accepted.
	m, _ := fixture(t)
	m[".vite/manifest.json"].Data = []byte(`{"index.html":{"file":"assets/index-Bx1a2b3c.js","css":["assets/index-Cx9y8z7w.css"],"name":"😀"}}`)
	if _, err := console.Verify(m, manifestFor(t, m), devIdentity); err != nil {
		t.Fatalf("valid surrogate pair: %v", err)
	}
	// manifest.json itself: a case variant duplicate of files.
	m, mf := fixture(t)
	bad := strings.Replace(string(mf), `{"files":`, `{"Files":[],"files":`, 1)
	_, err := console.Verify(m, []byte(bad), devIdentity)
	wantCode(t, err, console.CodeManifestInvalid)
	bad = strings.Replace(string(mf), `"path":"index.html"`, `"Path":"index.html"`, 1)
	_, err = console.Verify(m, []byte(bad), devIdentity)
	wantCode(t, err, console.CodeManifestInvalid)
}
