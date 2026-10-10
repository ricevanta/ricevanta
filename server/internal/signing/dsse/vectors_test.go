package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

type recipe struct {
	Prefix string `json:"prefix_hex"`
	Repeat string `json:"repeat_hex"`
	Count  int    `json:"repeat_count"`
	Suffix string `json:"suffix_hex"`
}
type vectorKey struct {
	ID     string `json:"id"`
	Seed   string `json:"seed_hex"`
	Public string `json:"public_key_hex"`
}
type positive struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Type      string `json:"payload_type"`
	Payload   string `json:"payload_hex"`
	KeyID     string `json:"keyid"`
	PAE       string `json:"pae_hex"`
	Signature string `json:"signature_hex"`
	Canonical string `json:"canonical_envelope_hex"`
	Envelope  string `json:"envelope_hex"`
	Hash      string `json:"envelope_sha256_hex"`
	Style     string `json:"style"`
}
type negative struct {
	Name     string  `json:"name"`
	Type     string  `json:"expected_type"`
	Public   string  `json:"public_key_hex"`
	Error    string  `json:"expected_error"`
	Envelope string  `json:"envelope_hex"`
	Recipe   *recipe `json:"envelope_recipe"`
}
type signNegative struct {
	Name    string  `json:"name"`
	Type    string  `json:"payload_type"`
	Payload string  `json:"payload_hex"`
	Recipe  *recipe `json:"payload_recipe"`
	Private string  `json:"private_key_hex"`
	Error   string  `json:"expected_error"`
}
type corpus struct {
	Format       string         `json:"format"`
	Keys         []vectorKey    `json:"keys"`
	Positive     []positive     `json:"positive"`
	Negative     []negative     `json:"negative"`
	SignNegative []signNegative `json:"sign_negative"`
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func expand(t testing.TB, s string, r *recipe) []byte {
	t.Helper()
	if r == nil {
		return unhex(t, s)
	}
	return bytes.Join([][]byte{unhex(t, r.Prefix), bytes.Repeat(unhex(t, r.Repeat), r.Count), unhex(t, r.Suffix)}, nil)
}
func loadCorpus(t testing.TB) corpus {
	t.Helper()
	f, e := os.Open("../../../../schemas/dsse/v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	var c corpus
	if e = d.Decode(&c); e != nil {
		t.Fatal(e)
	}
	if d.Decode(new(any)) != io.EOF {
		t.Fatal("trailing fixture data")
	}
	if c.Format != "ricevanta-dsse-vectors-v1" || len(c.Keys) != 2 || len(c.Positive) != 20 || len(c.Negative) != 65 || len(c.SignNegative) != 4 {
		t.Fatal("unexpected corpus")
	}
	keys := map[string]bool{}
	for _, k := range c.Keys {
		if keys[k.ID] {
			t.Fatal("duplicate key")
		}
		keys[k.ID] = true
		if !bytes.Equal(ed25519.NewKeyFromSeed(unhex(t, k.Seed))[32:], unhex(t, k.Public)) {
			t.Fatal("RFC key mismatch")
		}
	}
	names := map[string]bool{}
	for _, v := range c.Positive {
		if !keys[v.Key] || names[v.Name] {
			t.Fatal("invalid positive reference")
		}
		names[v.Name] = true
	}
	for _, v := range c.Negative {
		if sentinels()[v.Error] == nil {
			t.Fatal("unknown sentinel")
		}
	}
	for _, v := range c.SignNegative {
		if sentinels()[v.Error] == nil {
			t.Fatal("unknown sentinel")
		}
	}
	return c
}
func keyFor(t testing.TB, c corpus, id string) ed25519.PrivateKey {
	t.Helper()
	for _, k := range c.Keys {
		if k.ID == id {
			return ed25519.NewKeyFromSeed(unhex(t, k.Seed))
		}
	}
	t.Fatal("missing key")
	return nil
}
func sentinels() map[string]error {
	return map[string]error{"ErrEnvelopeTooLarge": ErrEnvelopeTooLarge, "ErrEnvelope": ErrEnvelope, "ErrSignatureCount": ErrSignatureCount, "ErrPayloadType": ErrPayloadType, "ErrTypeMismatch": ErrTypeMismatch, "ErrKeyID": ErrKeyID, "ErrPayloadTooLarge": ErrPayloadTooLarge, "ErrBase64": ErrBase64, "ErrSignature": ErrSignature, "ErrPublicKey": ErrPublicKey, "ErrPrivateKey": ErrPrivateKey}
}
func checkError(t testing.TB, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
	if got != nil {
		for _, e := range sentinels() {
			if e != want && errors.Is(got, e) {
				t.Fatal("multiple sentinels")
			}
		}
	}
}
func TestSignVectors(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range c.Positive {
		t.Run(v.Name, func(t *testing.T) {
			var hint [32]byte
			copy(hint[:], unhex(t, v.KeyID))
			got, e := Sign(PayloadType(v.Type), unhex(t, v.Payload), hint, keyFor(t, c, v.Key))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, unhex(t, v.Canonical)) {
				t.Fatal("canonical bytes differ")
			}
			var wire struct{ Signatures []struct{ Sig string } }
			if e = json.Unmarshal(got, &wire); e != nil {
				t.Fatal(e)
			}
			if wire.Signatures[0].Sig != std64(unhex(t, v.Signature)) {
				t.Fatal("signature differs")
			}
		})
	}
}
func TestSignErrors(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range c.SignNegative {
		t.Run(v.Name, func(t *testing.T) {
			b, e := Sign(PayloadType(v.Type), expand(t, v.Payload, v.Recipe), [32]byte{}, unhex(t, v.Private))
			checkError(t, e, sentinels()[v.Error])
			if b != nil {
				t.Fatal("non-nil error result")
			}
		})
	}
	for _, n := range []int{0, 31, 32, 63, 65} {
		b, e := Sign(TypeCommand, nil, [32]byte{}, make([]byte, n))
		checkError(t, e, ErrPrivateKey)
		if b != nil {
			t.Fatal("non-nil error result")
		}
	}
}

func TestVerifyVectors(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range c.Positive {
		t.Run(v.Name, func(t *testing.T) {
			b := unhex(t, v.Envelope)
			key := keyFor(t, c, v.Key)
			got, e := Verify(b, PayloadType(v.Type), ed25519.PublicKey(key[32:]))
			if e != nil {
				t.Fatal(e)
			}
			if got.PayloadType != PayloadType(v.Type) || got.KeyID != v.KeyID || !bytes.Equal(got.Payload, unhex(t, v.Payload)) || hex.EncodeToString(got.EnvelopeSHA256[:]) != v.Hash || got.Payload == nil {
				t.Fatal("verified result differs")
			}
		})
	}
	for _, v := range c.Negative {
		t.Run(v.Name, func(t *testing.T) {
			checkVerifyError(t, expand(t, v.Envelope, v.Recipe), PayloadType(v.Type), unhex(t, v.Public), sentinels()[v.Error])
		})
	}
}
