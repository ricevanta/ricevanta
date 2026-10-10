package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/signing/ed25519key"
)

type admissionVector struct {
	Name, Expected string
	Public         string `json:"public_key_hex"`
}

func admissionVectors(t testing.TB) []admissionVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path")
	}
	b, e := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../schemas/dsse/v1/key-admission-vectors.json"))
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Format  string
		Vectors []admissionVector
	}
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	if c.Format != "ricevanta-ed25519-key-admission-v1" || len(c.Vectors) != 80 {
		t.Fatal("admission corpus")
	}
	return c.Vectors
}
func admissionSentinels() []error {
	return []error{ed25519key.ErrLength, ed25519key.ErrNonCanonical, ed25519key.ErrPoint, ed25519key.ErrSmallOrder, ed25519key.ErrMixedOrder}
}
func checkAdmissionFailure(t testing.TB, wire []byte, typ PayloadType, key []byte, want error) {
	t.Helper()
	checkVerifyError(t, wire, typ, key, want)
	_, err := Verify(wire, typ, key)
	for _, s := range admissionSentinels() {
		if errors.Is(err, s) {
			t.Fatal("DSSE exposed admission sentinel")
		}
	}
}
func admissionEnvelope(typ PayloadType, payload, signature []byte) []byte {
	return []byte(`{"payloadType":"` + string(typ) + `","payload":"` + std64(payload) + `","signatures":[{"keyid":"` + strings.Repeat("0", 64) + `","sig":"` + std64(signature) + `"}]}`)
}
func TestVerifyRejectsIdentityForgery(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	sig := make([]byte, 64)
	sig[0] = 1
	for i, typ := range []PayloadType{TypeCommand, TypeAssignment} {
		payload := []byte{byte(i), 255}
		if !ed25519.Verify(key, pae(typ, payload), sig) {
			t.Fatal("pinned standard library no longer accepts identity forgery")
		}
		checkAdmissionFailure(t, admissionEnvelope(typ, payload, sig), typ, key, ErrPublicKey)
	}
}
func TestVerifyKeyAdmissionVectors(t *testing.T) {
	wire := admissionEnvelope(TypeCommand, nil, bytes.Repeat([]byte{255}, 64))
	for _, v := range admissionVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			want := ErrPublicKey
			if v.Expected == "accept" {
				want = ErrSignature
			}
			checkAdmissionFailure(t, wire, TypeCommand, unhex(t, v.Public), want)
		})
	}
}
func TestSignKeysPassAdmission(t *testing.T) {
	c := loadCorpus(t)
	keys := []ed25519.PrivateKey{}
	for _, k := range c.Keys {
		keys = append(keys, ed25519.NewKeyFromSeed(unhex(t, k.Seed)))
	}
	for _, value := range []byte{0, 1, 127, 255} {
		keys = append(keys, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, 32)))
	}
	for _, key := range keys {
		if err := ed25519key.Validate(key[32:]); err != nil {
			t.Fatal(err)
		}
		wire, err := Sign(TypeCommand, []byte("generated key"), [32]byte{}, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Verify(wire, TypeCommand, ed25519.PublicKey(key[32:]))
		if err != nil || !bytes.Equal(got.Payload, []byte("generated key")) {
			t.Fatal("generated sign/verify failed", err)
		}
	}
}
func TestVerifyKeyAdmissionPrecedence(t *testing.T) {
	representatives := map[string][]byte{}
	for _, v := range admissionVectors(t) {
		if len(unhex(t, v.Public)) == 32 && representatives[v.Expected] == nil {
			representatives[v.Expected] = unhex(t, v.Public)
		}
	}
	// The fixture helper keeps large payloads at a fixed offset for both orders.
	for stage := 0; stage < 12; stage++ {
		var payload []byte
		switch stage {
		case 6:
			payload = bytes.Repeat([]byte("!"), 22369625)
		case 7:
			payload = []byte("!")
		case 8:
			payload = bytes.Repeat([]byte("A"), 22369624)
		}
		fixture := newPrecedenceFixture(payload)
		hint, sig := hintText, std64(bytes.Repeat([]byte{255}, 64))
		expected := TypeCommand
		count := 1
		wants := []error{ErrEnvelopeTooLarge, ErrEnvelope, ErrSignatureCount, ErrPayloadType, ErrTypeMismatch, ErrKeyID, ErrPayloadTooLarge, ErrBase64, ErrPayloadTooLarge, ErrBase64, ErrSignature, ErrPublicKey}
		switch stage {
		case 2:
			count = 2
		case 3:
			expected = ""
		case 4:
			expected = TypeAssignment
		case 5:
			hint = "bad"
		case 9:
			sig = "!"
		case 10:
			sig = std64(make([]byte, 63))
		}
		wires := fixture.members(hint, sig, count, stage == 1, stage == 0)
		for _, class := range []string{"ErrSmallOrder", "ErrNonCanonical", "ErrPoint", "ErrMixedOrder"} {
			key := representatives[class]
			if key == nil {
				t.Fatal("missing key class")
			}
			for order, wire := range wires {
				t.Run(class+"/"+string(rune('a'+stage))+"/"+string(rune('a'+order)), func(t *testing.T) { checkAdmissionFailure(t, wire, expected, key, wants[stage]) })
			}
		}
	}
}
