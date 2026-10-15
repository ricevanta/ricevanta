// Package console verifies the embedded console build and serves it from
// memory under the production header set (docs/specs/server-runtime.md
// section 6). The handler never touches a filesystem: every byte it can send
// is read and verified once at startup and kept in an immutable map.
package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
)

// CSP is console/security/csp.txt without its final LF. The package test
// requires equality with that file, which stays the single home of the value.
const CSP = "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'none'; manifest-src 'self'; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types vue"

// Verification failure codes (spec section 6.1).
const (
	CodeMissing             = "console_missing"
	CodeMismatch            = "console_mismatch"
	CodeIdentityMismatch    = "console_identity_mismatch"
	CodeViteManifestInvalid = "console_vite_manifest_invalid"
	CodeUnknownType         = "console_unknown_type"
	CodeManifestInvalid     = "console_manifest_invalid"
)

// VerifyError reports why the embedded console was refused.
type VerifyError struct {
	Code   string
	Reason string
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Reason }

func fail(code, format string, args ...any) error {
	return &VerifyError{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// ManifestSchema is the only accepted manifest schema value.
const ManifestSchema = "ricevanta-console-manifest-v1"

const (
	maxManifestFiles = 16384
	maxFileSize      = 2147483648
)

// mimeTypes is the closed map of console foundation section 3.
var mimeTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".svg":         "image/svg+xml; charset=utf-8",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
}

const (
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheBrand     = "public, max-age=86400"
	cacheNoCache   = "no-cache"
)

// representation is one byte sequence the handler may send.
type representation struct {
	body []byte
	etag string
}

// resource is a servable path with its uncoded bytes and optional sidecars.
type resource struct {
	identity    representation
	br, gz      *representation
	contentType string
	cache       string
}

// Tree is a verified console build held in memory. It is immutable after
// Verify returns.
type Tree struct {
	resources map[string]*resource // keyed by manifest path, e.g. "assets/x.js"
	index     *resource
	manifest  []byte
}

// Manifest returns the embedded manifest.json bytes unchanged.
func (t *Tree) Manifest() []byte { return append([]byte(nil), t.manifest...) }

var (
	reSegment = regexp.MustCompile(`\A[A-Za-z0-9](?:[A-Za-z0-9_.+-]{0,238}[A-Za-z0-9_+-])?\z`)
	reDigest  = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
	reUint    = regexp.MustCompile(`\A(?:0|[1-9][0-9]*)\z`)
	reInt     = regexp.MustCompile(`\A-?(?:0|[1-9][0-9]*)\z`)
	devices   = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
)

func init() {
	for i := 1; i <= 9; i++ {
		devices["COM"+strconv.Itoa(i)] = true
		devices["LPT"+strconv.Itoa(i)] = true
	}
}

// validMemberPath applies release builds section 5.1 member-path rules with
// the one exact exception for .vite/manifest.json.
func validMemberPath(p string) bool {
	if p == ".vite/manifest.json" {
		return true
	}
	if len(p) > 1024 {
		return false
	}
	segs := strings.Split(p, "/")
	if len(segs) > 32 {
		return false
	}
	for _, s := range segs {
		if !reSegment.MatchString(s) {
			return false
		}
		stem, _, _ := strings.Cut(s, ".")
		if devices[strings.ToUpper(stem)] {
			return false
		}
	}
	return true
}

type manifestDoc struct {
	Schema *string         `json:"schema"`
	Files  *[]manifestFile `json:"files"`
}

type manifestFile struct {
	Path   *string         `json:"path"`
	Size   json.RawMessage `json:"size"`
	SHA256 *string         `json:"sha256"`
}

type entry struct {
	size   int64
	digest string
}

func parseManifest(data []byte) (map[string]entry, []string, error) {
	var doc manifestDoc
	if err := decodeStrict(data, &doc, true); err != nil {
		return nil, nil, fail(CodeManifestInvalid, "manifest.json: %v", err)
	}
	if doc.Schema == nil || *doc.Schema != ManifestSchema {
		return nil, nil, fail(CodeManifestInvalid, "manifest.json: schema must be %s", ManifestSchema)
	}
	if doc.Files == nil || len(*doc.Files) < 1 || len(*doc.Files) > maxManifestFiles {
		return nil, nil, fail(CodeManifestInvalid, "manifest.json: files must list 1 to %d entries", maxManifestFiles)
	}
	entries := make(map[string]entry, len(*doc.Files))
	order := make([]string, 0, len(*doc.Files))
	prev := ""
	for i, f := range *doc.Files {
		if f.Path == nil || f.SHA256 == nil || f.Size == nil {
			return nil, nil, fail(CodeManifestInvalid, "manifest.json: entry %d lacks path, size or sha256", i)
		}
		p := *f.Path
		if !validMemberPath(p) {
			return nil, nil, fail(CodeManifestInvalid, "manifest.json: entry %d has an invalid path", i)
		}
		if i > 0 && p <= prev {
			return nil, nil, fail(CodeManifestInvalid, "manifest.json: entry %d is not sorted by path or repeats a path", i)
		}
		prev = p
		size, err := strconv.ParseInt(string(f.Size), 10, 64)
		if !reUint.Match(f.Size) || err != nil || size > maxFileSize {
			return nil, nil, fail(CodeManifestInvalid, "manifest.json: entry %d size must be an integer from 0 to %d", i, int64(maxFileSize))
		}
		if !reDigest.MatchString(*f.SHA256) {
			return nil, nil, fail(CodeManifestInvalid, "manifest.json: entry %d sha256 must be 64 lowercase hex digits", i)
		}
		entries[p] = entry{size: size, digest: *f.SHA256}
		order = append(order, p)
	}
	return entries, order, nil
}

// Verify reads every file of dist, compares it with manifest, checks the
// build identity and the Vite manifest, and returns the tree in memory.
func Verify(dist fs.FS, manifest []byte, id buildinfo.Identity) (*Tree, error) {
	entries, order, err := parseManifest(manifest)
	if err != nil {
		return nil, err
	}
	data := make(map[string][]byte, len(entries))
	err = fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fail(CodeMismatch, "cannot read the embedded tree")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fail(CodeMismatch, "%s is not a regular file", p)
		}
		e, ok := entries[p]
		if !ok {
			return fail(CodeMismatch, "%s is not listed in manifest.json", p)
		}
		b, err := fs.ReadFile(dist, p)
		if err != nil {
			return fail(CodeMismatch, "cannot read %s", p)
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != e.size || hex.EncodeToString(sum[:]) != e.digest {
			return fail(CodeMismatch, "%s differs from manifest.json", p)
		}
		data[p] = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range order {
		if _, ok := data[p]; !ok {
			return nil, fail(CodeMismatch, "%s is listed in manifest.json but missing", p)
		}
	}
	if _, ok := data["index.html"]; !ok {
		return nil, fail(CodeMismatch, "index.html is missing")
	}

	// Every entry is a known type or a .br/.gz sidecar of one.
	sidecar := map[string]bool{}
	for _, p := range order {
		if _, ok := mimeTypes[ext(p)]; ok {
			continue
		}
		base, isSidecar := sidecarBase(p)
		if isSidecar {
			if _, ok := data[base]; ok {
				if _, ok := mimeTypes[ext(base)]; ok {
					sidecar[p] = true
					continue
				}
			}
		}
		return nil, fail(CodeUnknownType, "%s has no type in the closed MIME map", p)
	}

	if err := checkIdentity(data["build-info.json"], id); err != nil {
		return nil, err
	}
	emitted, err := viteOutputs(data)
	if err != nil {
		return nil, err
	}

	t := &Tree{resources: map[string]*resource{}, manifest: append([]byte(nil), manifest...)}
	for _, p := range order {
		if sidecar[p] {
			continue
		}
		r := &resource{
			identity:    representation{data[p], etag(entries[p].digest)},
			contentType: mimeTypes[ext(p)],
			cache:       cacheNoCache,
		}
		if b, ok := data[p+".br"]; ok {
			r.br = &representation{b, etag(entries[p+".br"].digest)}
		}
		if b, ok := data[p+".gz"]; ok {
			r.gz = &representation{b, etag(entries[p+".gz"].digest)}
		}
		switch {
		case strings.HasPrefix(p, "assets/") && emitted[p]:
			r.cache = cacheImmutable
		case strings.HasPrefix(p, "brand/"):
			r.cache = cacheBrand
		}
		if p == "index.html" {
			t.index = r
		}
		if strings.HasPrefix(p, "assets/") || strings.HasPrefix(p, "brand/") {
			t.resources[p] = r
		}
	}
	return t, nil
}

func etag(digest string) string { return `"` + digest + `"` }

// ext returns the extension after the last dot of the final segment.
func ext(p string) string {
	base := p[strings.LastIndexByte(p, '/')+1:]
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		return base[i:]
	}
	return ""
}

func sidecarBase(p string) (string, bool) {
	for _, s := range []string{".br", ".gz"} {
		if strings.HasSuffix(p, s) {
			return strings.TrimSuffix(p, s), true
		}
	}
	return "", false
}

type buildInfo struct {
	Version     *string         `json:"version"`
	Commit      *string         `json:"commit"`
	Channel     *string         `json:"channel"`
	SourceEpoch json.RawMessage `json:"sourceEpoch"`
}

func checkIdentity(data []byte, id buildinfo.Identity) error {
	if data == nil {
		return fail(CodeIdentityMismatch, "build-info.json is missing")
	}
	var b buildInfo
	if err := decodeStrict(data, &b, true); err != nil {
		return fail(CodeIdentityMismatch, "build-info.json: %v", err)
	}
	if b.Version == nil || b.Commit == nil || b.Channel == nil || b.SourceEpoch == nil || !reInt.Match(b.SourceEpoch) {
		return fail(CodeIdentityMismatch, "build-info.json must hold version, commit, channel and an integer sourceEpoch")
	}
	epoch, err := strconv.ParseInt(string(b.SourceEpoch), 10, 64)
	if err != nil {
		return fail(CodeIdentityMismatch, "build-info.json sourceEpoch is out of range")
	}
	if *b.Version != id.Version || *b.Commit != id.Commit || *b.Channel != id.Channel || epoch != id.SourceEpoch {
		return fail(CodeIdentityMismatch, "build-info.json differs from the server build identity")
	}
	return nil
}

type viteChunk struct {
	File   *string  `json:"file"`
	CSS    []string `json:"css"`
	Assets []string `json:"assets"`
}

// viteOutputs parses .vite/manifest.json and returns the set of emitted
// files, chunks and assets it declares; each must be in the tree.
func viteOutputs(data map[string][]byte) (map[string]bool, error) {
	raw, ok := data[".vite/manifest.json"]
	if !ok {
		return nil, fail(CodeViteManifestInvalid, ".vite/manifest.json is missing")
	}
	var chunks map[string]viteChunk
	if err := decodeStrict(raw, &chunks, false); err != nil {
		return nil, fail(CodeViteManifestInvalid, ".vite/manifest.json: %v", err)
	}
	if chunks == nil {
		return nil, fail(CodeViteManifestInvalid, ".vite/manifest.json must be an object")
	}
	out := map[string]bool{}
	for _, c := range chunks {
		if c.File == nil {
			return nil, fail(CodeViteManifestInvalid, ".vite/manifest.json: a chunk lacks file")
		}
		for _, f := range append(append([]string{*c.File}, c.CSS...), c.Assets...) {
			if _, ok := data[f]; !ok {
				return nil, fail(CodeViteManifestInvalid, ".vite/manifest.json lists a file the tree does not hold")
			}
			out[f] = true
		}
	}
	return out, nil
}
