package loader

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

type signedCorpus struct {
	Seed        string `json:"seed_hex"`
	Public      string `json:"public_key_hex"`
	Fingerprint string `json:"publisher_fingerprint"`
	Files       []struct {
		Path string
		UTF8 string `json:"utf8"`
	}
	Cases []struct {
		Name            string
		Payload         string
		ArchiveManifest string `json:"archive_manifest"`
		Envelope        string
		PayloadHash     string `json:"payload_sha256"`
		EnvelopeHash    string `json:"envelope_sha256"`
		SignatureValid  bool   `json:"signature_valid"`
		Result          string
		Document        map[string]any `json:"decoded_document"`
	}
}

func corpus(t testing.TB) signedCorpus {
	t.Helper()
	b, err := os.ReadFile("../../../../schemas/extension/v1alpha1/package-loader-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var c signedCorpus
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}
func fixtureKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	b, e := hex.DecodeString(corpus(t).Seed)
	if e != nil {
		t.Fatal(e)
	}
	return ed25519.NewKeyFromSeed(b)
}
func signedEnvelope(t testing.TB, payload []byte) []byte {
	t.Helper()
	b, e := dsse.Sign(dsse.TypeExtensionManifest, payload, [32]byte{}, fixtureKey(t))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func packageArchive(t testing.TB, payload, envelope []byte, files ...archiveEntry) []byte {
	t.Helper()
	entries := append([]archiveEntry{{"extension.yaml", payload}, {"envelope.json", envelope}}, files...)
	return compressFixture(t, tarFixture(t, entries...))
}
func fixtureFiles(t testing.TB) []archiveEntry {
	t.Helper()
	var out []archiveEntry
	for _, f := range corpus(t).Files {
		out = append(out, archiveEntry{f.Path, []byte(f.UTF8)})
	}
	return out
}
func loadBytes(b []byte, key ed25519.PublicKey, options Options) (Package, error) {
	f := options.MaxTotalFileBytes
	if f == 0 {
		f = 64 << 20
	}
	return Load(archiveReader(b, f), key, options)
}
func assertLoadError(t testing.TB, p Package, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
	if !reflect.DeepEqual(p, Package{}) {
		t.Fatal("nonzero result on error")
	}

	// Errors identify one owning stage and never include publisher-controlled text.
	for _, marker := range []string{"attacker-secret", "unknown-attacker-text"} {
		if strings.Contains(err.Error(), marker) {
			t.Fatal("unsanitized error")
		}
	}
	for _, sentinel := range []error{ErrOptions, ErrReader, ErrKey, ErrCompressedLimit, ErrRead, ErrCompression, ErrArchiveLimit, ErrArchive, ErrMember, ErrMemberDuplicate, ErrControls, ErrPayloadLimit, ErrPayloadMismatch, ErrYAML, ErrYAMLLimit, ErrExplicitTag, ErrDuplicateKey, ErrPublisher, ErrFileSet, ErrFileSize, ErrFileDigest, dsse.ErrEnvelope, dsse.ErrSignatureCount, dsse.ErrPayloadType, dsse.ErrTypeMismatch, dsse.ErrKeyID, dsse.ErrBase64, dsse.ErrSignature, dsse.ErrPublicKey, manifest.ErrShape, manifest.ErrField, manifest.ErrReserved, manifest.ErrDuplicate, manifest.ErrPath, manifest.ErrRequires, manifest.ErrReference, manifest.ErrCapability, manifest.ErrLicense, manifest.ErrURL} {
		if sentinel != want && errors.Is(err, sentinel) {
			t.Fatalf("error also matches unrelated sentinel %v", sentinel)
		}
	}
	for _, sentinel := range []error{dsse.ErrEnvelope, dsse.ErrSignatureCount, dsse.ErrPayloadType, dsse.ErrTypeMismatch, dsse.ErrKeyID, dsse.ErrBase64, dsse.ErrSignature, dsse.ErrPublicKey} {
		if sentinel == want && err != sentinel {
			t.Fatal("DSSE sentinel was wrapped")
		}
	}
}
func TestLoadVectors(t *testing.T) {
	c := corpus(t)
	raw, _ := hex.DecodeString(c.Public)
	key := ed25519.PublicKey(raw)
	outcomes := map[string]error{"ErrExplicitTag": ErrExplicitTag, "ErrPayloadMismatch": ErrPayloadMismatch, "ErrPublisher": ErrPublisher, "dsse.ErrSignature": dsse.ErrSignature}
	for _, v := range c.Cases {
		t.Run(v.Name, func(t *testing.T) {
			// Use the committed exact envelope, never reconstruct its signature.
			env := []byte(v.Envelope)
			verified, e := dsse.Verify(env, dsse.TypeExtensionManifest, key)
			if (e == nil) != v.SignatureValid {
				t.Fatalf("signature validity: %v", e)
			}
			if e == nil && !bytes.Equal(verified.Payload, []byte(v.Payload)) {
				t.Fatal("fixture payload disagreement")
			}
			archive := packageArchive(t, []byte(v.ArchiveManifest), env, fixtureFiles(t)...)
			p, err := loadBytes(archive, key, Options{})
			if v.Result != "ok" {
				want, ok := outcomes[v.Result]
				if !ok {
					t.Fatalf("unmapped outcome %s", v.Result)
				}
				assertLoadError(t, p, err, want)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(p.Manifest, []byte(v.Payload)) || !bytes.Equal(p.Envelope, env) || !bytes.Equal(p.Archive, archive) {
				t.Fatal("exact bytes lost")
			}
			if p.PackageSHA256 != sha256.Sum256(archive) || p.ManifestSHA256 != sha256.Sum256(p.Manifest) || p.EnvelopeSHA256 != sha256.Sum256(env) {
				t.Fatal("hash mismatch")
			}
			if hex.EncodeToString(p.ManifestSHA256[:]) != v.PayloadHash || hex.EncodeToString(p.EnvelopeSHA256[:]) != v.EnvelopeHash {
				t.Fatal("golden hash mismatch")
			}
			if !reflect.DeepEqual(p.Document, v.Document) || p.PublisherFingerprint != c.Fingerprint {
				t.Fatal("document or publisher mismatch")
			}
		})
	}
}
