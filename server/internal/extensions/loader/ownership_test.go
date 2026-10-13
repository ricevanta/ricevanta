package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

func TestLoadResultOwnership(t *testing.T) {
	d := baseDocument(t)
	fs := d["files"].([]any)
	d["files"] = append(fs, map[string]any{"path": "content/second", "size": json.Number("3"), "sha256": fs[0].(map[string]any)["sha256"]})
	component := d["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
	component["files"] = append(component["files"].([]any), "content/second")
	payload := jsonPayload(t, d)
	env := signedEnvelope(t, payload)
	body := []byte("abc")
	a := packageArchive(t, payload, env, archiveEntry{"content/rules.yaml", body}, archiveEntry{"content/second", body})
	p, e := loadBytes(a, keyPublic(t), Options{})
	if e != nil {
		t.Fatal(e)
	}
	q, e := loadBytes(a, keyPublic(t), Options{})
	if e != nil {
		t.Fatal(e)
	}
	slices := [][]byte{a, payload, env, body, p.Archive, p.Manifest, p.Envelope, p.Files[0].Bytes, q.Archive, q.Manifest, q.Envelope, q.Files[0].Bytes, p.Files[1].Bytes, q.Files[1].Bytes}
	copies := make([][]byte, len(slices))
	for i, b := range slices {
		copies[i] = bytes.Clone(b)
	}
	for i, b := range slices {
		b[0] ^= 1
		for j, peer := range slices {
			if i != j && !bytes.Equal(peer, copies[j]) {
				t.Fatalf("slice %d aliases %d", i, j)
			}
		}
		b[0] ^= 1
	}
	p.Document["metadata"].(map[string]any)["publisher"].(map[string]any)["name"] = "mutated"
	p.Document["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)["files"].([]any)[0] = "mutated"
	p.Files[0].Path = "mutated"
	if !reflect.DeepEqual(q.Document, d) || q.Files[0].Path != "content/rules.yaml" {
		t.Fatal("result tree aliases")
	}
}
func TestLoadZeroOnError(t *testing.T) {
	v := corpus(t).Cases[0]
	p, e := loadBytes([]byte("attacker-secret"), keyPublic(t), Options{})
	assertLoadError(t, p, e, ErrCompression)
	cause := errors.New("transport cause")
	r := &io.LimitedReader{R: &scriptedReader{err: cause}, N: int64(manifest.DefaultMaxTotalFileBytes + archiveOverhead + compressedOverhead + 1)}
	p, e = Load(r, keyPublic(t), Options{})
	assertLoadError(t, p, e, ErrRead)
	if !errors.Is(e, cause) {
		t.Fatal("I/O cause lost")
	}
	for _, tc := range []struct {
		payload, env []byte
		want         error
	}{
		{[]byte(v.Payload), []byte(`{}`), dsse.ErrEnvelope},
		{[]byte("a: b\na: c\n"), signedEnvelope(t, []byte("a: b\na: c\n")), ErrDuplicateKey},
		{[]byte("null"), signedEnvelope(t, []byte("null")), ErrYAML},
	} {
		p, e = loadBytes(packageArchive(t, tc.payload, tc.env, fixtureFiles(t)...), keyPublic(t), Options{})
		assertLoadError(t, p, e, tc.want)
	}
}
