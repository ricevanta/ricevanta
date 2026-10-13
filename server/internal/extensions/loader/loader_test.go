package loader

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/qualificationfixture"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

func baseDocument(t testing.TB) map[string]any { return corpus(t).Cases[0].Document }
func jsonPayload(t testing.TB, d map[string]any) []byte {
	t.Helper()
	b, e := json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func keyPublic(t testing.TB) ed25519.PublicKey { return fixtureKey(t).Public().(ed25519.PublicKey) }
func TestLoadOrder(t *testing.T) {
	for _, v := range corpus(t).Cases {
		t.Run(v.Name, func(t *testing.T) {
			yc, vc := 0, 0
			deps := loadDependencies{decode: func(b []byte) (map[string]any, error) { yc++; return decodeVerifiedYAML(b) }, validate: func(d any, o manifest.Options) error { vc++; return manifest.Validate(d, o) }}
			a := packageArchive(t, []byte(v.ArchiveManifest), []byte(v.Envelope), fixtureFiles(t)...)
			_, e := loadWithDependencies(archiveReader(a, manifest.DefaultMaxTotalFileBytes), keyPublic(t), Options{}, deps)
			if v.Result == "dsse.ErrSignature" || v.Result == "ErrPayloadMismatch" {
				if yc != 0 || vc != 0 {
					t.Fatalf("YAML/validation before authentication: %d/%d", yc, vc)
				}
			} else if yc != 1 {
				t.Fatalf("YAML calls %d: %v", yc, e)
			}
			if v.Result == "ErrExplicitTag" && vc != 0 {
				t.Fatal("validation after YAML error")
			}
			if v.Result == "ok" && vc != 1 {
				t.Fatal("validation call count")
			}
		})
	}
}
func TestPublisherBinding(t *testing.T) {
	d := baseDocument(t)
	d["metadata"].(map[string]any)["publisher"].(map[string]any)["key"] = "sha256:" + strings.Repeat("0", 64)
	b := jsonPayload(t, d)
	p, e := loadBytes(packageArchive(t, b, signedEnvelope(t, b), fixtureFiles(t)...), keyPublic(t), Options{})
	assertLoadError(t, p, e, ErrPublisher)
	d["unknown-attacker-text"] = true
	b = jsonPayload(t, d)
	p, e = loadBytes(packageArchive(t, b, signedEnvelope(t, b), fixtureFiles(t)...), keyPublic(t), Options{})
	assertLoadError(t, p, e, manifest.ErrShape)
	if strings.Contains(e.Error(), "attacker") {
		t.Fatal("unsanitized error")
	}
}
func TestFileCommitments(t *testing.T) {
	d := baseDocument(t)
	fs := d["files"].([]any)
	first := fs[0].(map[string]any)
	d["files"] = append(fs, map[string]any{"path": "content/second", "size": json.Number("3"), "sha256": first["sha256"]})
	c := d["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
	c["files"] = append(c["files"].([]any), "content/second")
	b := jsonPayload(t, d)
	env := signedEnvelope(t, b)
	for _, reverse := range []bool{false, true} {
		for _, tc := range []struct {
			name  string
			files []archiveEntry
			want  error
		}{
			{"set", []archiveEntry{{"content/rules.yaml", []byte("wrong-size")}, {"content/extra", []byte("bad")}}, ErrFileSet},
			{"size-before-digest", []archiveEntry{{"content/rules.yaml", []byte("xyz")}, {"content/second", []byte("abcd")}}, ErrFileSize},
			{"digest", []archiveEntry{{"content/rules.yaml", []byte("xyz")}, {"content/second", []byte("abc")}}, ErrFileDigest},
			{"valid", []archiveEntry{{"content/rules.yaml", []byte("abc")}, {"content/second", []byte("abc")}}, nil},
		} {
			t.Run(tc.name+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
				if reverse {
					tc.files[0], tc.files[1] = tc.files[1], tc.files[0]
				}
				p, e := loadBytes(packageArchive(t, b, env, tc.files...), keyPublic(t), Options{})
				if tc.want != nil {
					assertLoadError(t, p, e, tc.want)
				} else {
					if e != nil {
						t.Fatal(e)
					}
					if p.Files[0].Path != "content/rules.yaml" || p.Files[1].Path != "content/second" {
						t.Fatal("unsorted files")
					}
				}
			})
		}
	}
	d = baseDocument(t)
	f := d["files"].([]any)[0].(map[string]any)
	f["size"] = json.Number("0")
	h := sha256.Sum256(nil)
	f["sha256"] = hex.EncodeToString(h[:])
	b = jsonPayload(t, d)
	p, e := loadBytes(packageArchive(t, b, signedEnvelope(t, b), archiveEntry{"content/rules.yaml", nil}), keyPublic(t), Options{})
	if e != nil {
		t.Fatal(e)
	}
	if p.Files[0].Size != 0 || len(p.Files[0].Bytes) != 0 || p.Files[0].SHA256 != h {
		t.Fatal("empty commitment")
	}
}
func TestLoadPrecedence(t *testing.T) {
	r := archiveReader([]byte("bad compression"), manifest.DefaultMaxTotalFileBytes)
	for _, tc := range []struct {
		name string
		body *io.LimitedReader
		key  ed25519.PublicKey
		opts Options
		want error
	}{
		{"options", nil, nil, Options{MaxTotalFileBytes: manifest.HardMaxTotalFileBytes + 1}, ErrOptions},
		{"reader", nil, nil, Options{}, ErrReader},
		{"nil-source", &io.LimitedReader{N: r.N}, nil, Options{}, ErrReader},
		{"reader-N", &io.LimitedReader{R: bytes.NewReader(nil), N: r.N - 1}, nil, Options{}, ErrReader},
		{"short-key", r, make([]byte, 31), Options{}, ErrKey}, {"long-key", r, make([]byte, 33), Options{}, ErrKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := Load(tc.body, tc.key, tc.opts)
			assertLoadError(t, p, e, tc.want)
			if r.N != int64(manifest.DefaultMaxTotalFileBytes+archiveOverhead+compressedOverhead+1) {
				t.Fatal("read before validation")
			}
		})
	}
	d := baseDocument(t)
	d["metadata"].(map[string]any)["publisher"].(map[string]any)["key"] = "sha256:" + strings.Repeat("0", 64)
	b := jsonPayload(t, d)
	p, e := loadBytes(packageArchive(t, b, signedEnvelope(t, b), archiveEntry{"content/rules.yaml", []byte("xyz")}), keyPublic(t), Options{})
	assertLoadError(t, p, e, ErrPublisher)
	for _, tag := range []string{"! bad", "a: b\na: c\n"} {
		p, e = loadBytes(packageArchive(t, []byte("different"), signedEnvelope(t, []byte(tag)), fixtureFiles(t)...), keyPublic(t), Options{})
		assertLoadError(t, p, e, ErrPayloadMismatch)
	}
}
func TestLoadPayloadPreflight(t *testing.T) {
	t.Run("decoded-character-regressions", testPayloadDecodedCharacters)
	const capChars = 1398104
	padded := strings.Repeat("A", capChars-2) + "=="
	for _, tc := range []struct {
		name, s string
		want    error
	}{
		{"cap-minus-one", `{"payload":"` + strings.Repeat("A", capChars-1) + `"}`, nil},
		{"cap", `{"payload":"` + padded + `"}`, nil},
		{"cap-plus-one", `{"payload":"` + padded + `A"}`, ErrPayloadLimit},
		{"one-padding", `{"payload":"` + strings.Repeat("A", capChars-1) + `="}`, ErrPayloadLimit},
		{"no-padding", `{"payload":"` + strings.Repeat("A", capChars) + `"}`, ErrPayloadLimit},
		{"escaped-cap", `{"payload":"` + strings.Repeat("A", capChars-2) + `\u003d\u003d"}`, nil},
		{"duplicate-first", `{"payload":"` + padded + `A","payload":""}`, ErrPayloadLimit},
		{"duplicate-last", `{"payload":"","payload":"` + padded + `A"}`, ErrPayloadLimit},
		{"nonroot", `{"other":{"payload":"` + padded + `A"}}`, nil},
		{"depth-four", `{"a":[{"b":[]}]}`, nil}, {"depth-five", `{"a":[{"b":[{}]}]}`, dsse.ErrEnvelope},
		{"syntax-before-limit", `{"bad":],"payload":"` + padded + `A"}`, dsse.ErrEnvelope},
		{"limit-before-syntax", `{"payload":"` + padded + `A","bad":]}`, ErrPayloadLimit},
		{"suffix", `{} {}`, dsse.ErrEnvelope}, {"truncated", `{"payload":`, dsse.ErrEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := checkPayloadBudget([]byte(tc.s))
			if tc.want == nil {
				if e != nil {
					t.Fatal(e)
				}
			} else if !errors.Is(e, tc.want) {
				t.Fatalf("%v want %v", e, tc.want)
			}
		})
	}
}
func TestLoadKinds(t *testing.T) {
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Cases []struct {
			Name     string
			Manifest map[string]any
			Error    string
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if e := dec.Decode(&c); e != nil {
		t.Fatal(e)
	}
	wanted := map[string]bool{"content": true, "browser-adapter": true, "classifier": true, "parser": true, "collector": true, "responder": true, "console-module": true, "service-connector": true, "first-party": true, "attestation": true}
	for _, v := range c.Cases {
		if !wanted[v.Name] {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			d := v.Manifest
			d["metadata"].(map[string]any)["publisher"].(map[string]any)["key"] = corpus(t).Fingerprint
			var files []archiveEntry
			for _, item := range d["files"].([]any) {
				f := item.(map[string]any)
				body := []byte("opaque")
				h := sha256.Sum256(body)
				f["size"] = json.Number("6")
				f["sha256"] = hex.EncodeToString(h[:])
				files = append(files, archiveEntry{f["path"].(string), body})
			}
			payload := jsonPayload(t, d)
			a := packageArchive(t, payload, signedEnvelope(t, payload), files...)
			o := Options{AllowReservedID: v.Name == "first-party", MaxTotalFileBytes: uint64(len(files) * 6)}
			p, e := loadBytes(a, keyPublic(t), o)
			if e != nil {
				t.Fatal(e)
			}
			if len(p.Files) != len(files) {
				t.Fatal("file count")
			}
			if v.Name == "first-party" {
				p, e = loadBytes(a, keyPublic(t), Options{})
				assertLoadError(t, p, e, manifest.ErrReserved)
			}
		})
	}
}

func TestLoadEvidenceIdentity(t *testing.T) {
	c := corpus(t)
	v := c.Cases[0]
	payload := []byte(v.Payload)
	env := []byte(v.Envelope)
	a := packageArchive(t, payload, env, fixtureFiles(t)...)
	entries := append(fixtureFiles(t), archiveEntry{"envelope.json", env}, archiveEntry{"extension.yaml", payload})
	different := compressFixture(t, tarFixture(t, entries...))
	writer, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true), zstd.WithWindowSize(8<<20), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		t.Fatal(err)
	}
	recompressed := writer.EncodeAll(tarFixture(t, append([]archiveEntry{{"extension.yaml", payload}, {"envelope.json", env}}, fixtureFiles(t)...)...), nil)
	writer.Close()
	if bytes.Equal(recompressed, a) {
		t.Fatal("recompression witness did not change exact bytes")
	}

	p, e := loadBytes(a, keyPublic(t), Options{})
	if e != nil {
		t.Fatal(e)
	}
	q, e := loadBytes(different, keyPublic(t), Options{})
	if e != nil {
		t.Fatal(e)
	}
	if p.PackageSHA256 == q.PackageSHA256 || p.ManifestSHA256 != q.ManifestSHA256 || p.EnvelopeSHA256 != q.EnvelopeSHA256 {
		t.Fatal("archive identity did not bind exact encoding")
	}

	recompressedPackage, err := loadBytes(recompressed, keyPublic(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if recompressedPackage.PackageSHA256 == p.PackageSHA256 || recompressedPackage.ManifestSHA256 != p.ManifestSHA256 || recompressedPackage.EnvelopeSHA256 != p.EnvelopeSHA256 {
		t.Fatal("recompression identity mismatch")
	}
	for _, v := range c.Cases {
		if v.Name != "changed-hint" {
			continue
		}
		q, e = loadBytes(packageArchive(t, []byte(v.ArchiveManifest), []byte(v.Envelope), fixtureFiles(t)...), keyPublic(t), Options{})
		if e != nil {
			t.Fatal(e)
		}
		if q.ManifestSHA256 != p.ManifestSHA256 || q.EnvelopeSHA256 == p.EnvelopeSHA256 || q.PackageSHA256 == p.PackageSHA256 || q.PublisherFingerprint != p.PublisherFingerprint {
			t.Fatal("hint became authority or lost envelope identity")
		}
	}
	// Control members cannot be substituted for component body commitments.
	p, e = loadBytes(packageArchive(t, payload, env), keyPublic(t), Options{})
	assertLoadError(t, p, e, ErrFileSet)
	d := baseDocument(t)
	d["files"].([]any)[0].(map[string]any)["path"] = "extension.yaml"
	b := jsonPayload(t, d)
	p, e = loadBytes(packageArchive(t, b, signedEnvelope(t, b)), keyPublic(t), Options{})
	assertLoadError(t, p, e, manifest.ErrPath)
}

func TestLoadSentinels(t *testing.T) {
	v := corpus(t).Cases[0]
	payload := []byte(v.Payload)
	env := v.Envelope
	for _, tc := range []struct {
		name, env string
		want      error
	}{
		{"shape", `{}`, dsse.ErrEnvelope},
		{"signature-count", strings.Replace(env, `"signatures":[{`, `"signatures":[],"extra":[{`, 1), dsse.ErrEnvelope},
		{"type-mismatch", strings.Replace(env, string(dsse.TypeExtensionManifest), string(dsse.TypeCommand), 1), dsse.ErrTypeMismatch},
		{"unsupported-type", strings.Replace(env, string(dsse.TypeExtensionManifest), "attacker-unknown-type", 1), dsse.ErrPayloadType},
		{"hint", strings.Replace(env, strings.Repeat("0", 64), "attacker-secret", 1), dsse.ErrKeyID},
		{"base64", strings.Replace(env, `"payload":"`, `"payload":"!`, 1), dsse.ErrBase64},
		{"zero-signatures", env[:strings.Index(env, `"signatures":`)] + `"signatures":[]}`, dsse.ErrSignatureCount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := loadBytes(packageArchive(t, payload, []byte(tc.env), fixtureFiles(t)...), keyPublic(t), Options{})
			assertLoadError(t, p, e, tc.want)
			if strings.Contains(e.Error(), "attacker") {
				t.Fatal("unsanitized DSSE error")
			}
		})
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32)).Public().(ed25519.PublicKey)
	p, e := loadBytes(packageArchive(t, payload, []byte(env), fixtureFiles(t)...), wrong, Options{})
	assertLoadError(t, p, e, dsse.ErrSignature)
	p, e = loadBytes(packageArchive(t, payload, []byte(env), fixtureFiles(t)...), make(ed25519.PublicKey, 32), Options{})
	assertLoadError(t, p, e, dsse.ErrPublicKey)
	for _, n := range []uint64{1, manifest.HardMaxTotalFileBytes} {
		p, e = loadBytes(packageArchive(t, payload, []byte(env), fixtureFiles(t)...), keyPublic(t), Options{MaxTotalFileBytes: n})
		if n == 1 {
			assertLoadError(t, p, e, ErrArchiveLimit)
		} else if e != nil {
			t.Fatal(e)
		}
	}
}

func TestLoadMapBoundaries(t *testing.T) {
	for _, arity := range []int{14, 896, 897} {
		d := baseDocument(t)
		extra := make(map[string]any, arity)
		for i := 0; i < arity; i++ {
			extra["key"+strconv.Itoa(i)] = "x"
		}
		d["unknown"] = extra
		b := jsonPayload(t, d)
		p, e := loadBytes(packageArchive(t, b, signedEnvelope(t, b), fixtureFiles(t)...), keyPublic(t), Options{})
		want := manifest.ErrShape
		if arity == 897 {
			want = ErrYAMLLimit
		}
		assertLoadError(t, p, e, want)
	}
}

func TestLoadMaximumManifest(t *testing.T) {
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		t.Run(name, func(t *testing.T) {
			b := qualificationfixture.MaximumPayload(name)
			b = bytes.Replace(b, []byte("sha256:"+strings.Repeat("0", 64)), []byte(corpus(t).Fingerprint), 1)
			d, e := decodeVerifiedYAML(b)
			if e != nil {
				t.Fatal(e)
			}
			var files []archiveEntry
			for _, item := range d["files"].([]any) {
				files = append(files, archiveEntry{item.(map[string]any)["path"].(string), nil})
			}
			p, e := loadBytes(packageArchive(t, b, signedEnvelope(t, b), files...), keyPublic(t), Options{})
			if e != nil {
				t.Fatal(e)
			}
			if len(p.Files) != 4096 || !bytes.Equal(p.Manifest, b) {
				t.Fatal("maximum capacity lost")
			}
		})
	}
}

func TestLoadArchiveStageErrors(t *testing.T) {
	v := corpus(t).Cases[0]
	payload, env := []byte(v.Payload), []byte(v.Envelope)
	validEntries := append([]archiveEntry{{"extension.yaml", payload}, {"envelope.json", env}}, fixtureFiles(t)...)
	raw := tarFixture(t, validEntries...)
	malformed := bytes.Clone(raw)
	malformed[0] ^= 1
	nonregular := bytes.Clone(raw)
	nonregular[156] = '2'
	checksumHeader(nonregular)
	duplicate := append(append([]archiveEntry{}, validEntries...), archiveEntry{"extension.yaml", payload})
	for _, tc := range []struct {
		name    string
		archive []byte
		want    error
	}{
		{"header", compressFixture(t, malformed), ErrArchive},
		{"type", compressFixture(t, nonregular), ErrMember},
		{"duplicate", compressFixture(t, tarFixture(t, duplicate...)), ErrMemberDuplicate},
		{"controls", compressFixture(t, tarFixture(t, fixtureFiles(t)...)), ErrControls},
		{"declared-limit", rawFrameHeader(manifest.DefaultMaxTotalFileBytes+archiveOverhead+1, false, 0), ErrArchiveLimit},
		{"payload-limit", packageArchive(t, payload, signedEnvelope(t, bytes.Repeat([]byte{'A'}, manifest.MaxManifestBytes+1)), fixtureFiles(t)...), ErrPayloadLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yc, vc := 0, 0
			deps := loadDependencies{
				decode:   func(b []byte) (map[string]any, error) { yc++; return decodeVerifiedYAML(b) },
				validate: func(d any, o manifest.Options) error { vc++; return manifest.Validate(d, o) },
			}
			p, e := loadWithDependencies(archiveReader(tc.archive, manifest.DefaultMaxTotalFileBytes), keyPublic(t), Options{}, deps)
			assertLoadError(t, p, e, tc.want)
			if yc != 0 || vc != 0 {
				t.Fatal("processing after early rejection")
			}
		})
	}
}

func TestLoadManifestSentinels(t *testing.T) {
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Cases []struct {
			Name     string
			Manifest map[string]any
			Error    string
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&c); e != nil {
		t.Fatal(e)
	}
	sentinels := map[string]error{"ErrShape": manifest.ErrShape, "ErrField": manifest.ErrField, "ErrReserved": manifest.ErrReserved, "ErrDuplicate": manifest.ErrDuplicate, "ErrPath": manifest.ErrPath, "ErrRequires": manifest.ErrRequires, "ErrReference": manifest.ErrReference, "ErrCapability": manifest.ErrCapability, "ErrLicense": manifest.ErrLicense, "ErrURL": manifest.ErrURL}
	wanted := map[string]bool{"unknown-top": true, "id-uppercase": true, "reserved-id": true, "duplicate-file": true, "device-path": true, "unused-requirement": true, "missing-file": true, "collector-cross-limit": true, "bad-license": true, "url-ip": true}
	for _, v := range c.Cases {
		if !wanted[v.Name] {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			v.Manifest["metadata"].(map[string]any)["publisher"].(map[string]any)["key"] = corpus(t).Fingerprint
			payload := jsonPayload(t, v.Manifest)
			p, e := loadBytes(packageArchive(t, payload, signedEnvelope(t, payload), fixtureFiles(t)...), keyPublic(t), Options{})
			assertLoadError(t, p, e, sentinels[v.Error])
		})
	}
}

// Byte counting would reject these below-character-cap malformed base64 values
// before DSSE can classify their base64 or Unicode defects.
func testPayloadDecodedCharacters(t *testing.T) {
	v := corpus(t).Cases[0]
	start := strings.Index(v.Envelope, `"payload":"`) + len(`"payload":"`)
	end := start + strings.Index(v.Envelope[start:], `"`)
	envelopeFor := func(text string) string { return v.Envelope[:start] + text + v.Envelope[end:] }
	prefix := strings.Repeat("A", maxPayloadCharacters-2)
	for _, tc := range []struct {
		name, encoded string
		dsseError     error
	}{
		{"raw-accent", prefix + "é", dsse.ErrBase64},
		{"escaped-accent", prefix + `\u00e9`, dsse.ErrBase64},
		{"raw-emoji", prefix + "😀", dsse.ErrBase64},
		{"escaped-pair", prefix + `\ud83d\ude00`, dsse.ErrBase64},
		{"unpaired-high", prefix + `\ud800`, dsse.ErrEnvelope},
		{"unpaired-low", prefix + `\udc00`, dsse.ErrEnvelope},
		{"accent-at-padded-cap", strings.Repeat("A", maxPayloadCharacters-3) + "é==", dsse.ErrBase64},
		{"emoji-at-padded-cap", strings.Repeat("A", maxPayloadCharacters-3) + `\ud83d\ude00==`, dsse.ErrBase64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := []byte(envelopeFor(tc.encoded))
			if _, e := dsse.Verify(env, dsse.TypeExtensionManifest, keyPublic(t)); e != tc.dsseError {
				t.Fatalf("DSSE oracle %v, want %v", e, tc.dsseError)
			}
			t.Run("preflight", func(t *testing.T) {
				if e := checkPayloadBudget(env); e != nil {
					t.Fatalf("below character ceiling: %v", e)
				}
			})
			t.Run("load", func(t *testing.T) {
				p, e := loadBytes(packageArchive(t, []byte(v.Payload), env, fixtureFiles(t)...), keyPublic(t), Options{})
				assertLoadError(t, p, e, tc.dsseError)
			})
		})
	}
	over := strings.Repeat("A", maxPayloadCharacters) + "é"
	short := prefix + `\ud800`
	for _, tc := range []struct {
		name, env string
		want      error
	}{
		{"accent-at-unpadded-cap", envelopeFor(strings.Repeat("A", maxPayloadCharacters-1) + "é"), ErrPayloadLimit},
		{"emoji-above-cap", envelopeFor(strings.Repeat("A", maxPayloadCharacters) + `\ud83d\ude00`), ErrPayloadLimit},
		{"short-multibyte-before-syntax", `{"payload":"` + prefix + `é","bad":]}`, dsse.ErrEnvelope},
		{"syntax-before-multibyte-limit", `{"bad":],"payload":"` + over + `"}`, dsse.ErrEnvelope},
		{"multibyte-limit-before-syntax", `{"payload":"` + over + `","bad":]}`, ErrPayloadLimit},
		{"short-surrogate-before-duplicate-limit", `{"payload":"\ud800","payload":"` + over + `"}`, ErrPayloadLimit},
		{"short-surrogate-before-depth", `{"payload":"` + short + `","nested":[[[[]]]]}`, dsse.ErrEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("preflight", func(t *testing.T) {
				if e := checkPayloadBudget([]byte(tc.env)); e != tc.want {
					t.Fatalf("%v want %v", e, tc.want)
				}
			})
			t.Run("load", func(t *testing.T) {
				p, e := loadBytes(packageArchive(t, []byte(v.Payload), []byte(tc.env), fixtureFiles(t)...), keyPublic(t), Options{})
				assertLoadError(t, p, e, tc.want)
			})
		})
	}
}
