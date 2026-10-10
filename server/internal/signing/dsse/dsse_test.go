package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func std64(b []byte) string       { return base64.StdEncoding.EncodeToString(b) }
func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, 32)) }
func TestPayloadTypes(t *testing.T) {
	types := []PayloadType{TypeBundleManifest, TypeAssignment, TypeRulePackManifest, TypeCommand, TypeCommandDispatchGrant, TypeComplianceStatement, TypeIntelDelta, TypeRelease, TypeExtensionManifest, TypeExtensionIndex, TypeEscrowAck, TypeEscrowRetirementAuthorization}
	names := []string{"bundle-manifest+json", "assignment+json", "rulepack-manifest+json", "command+json", "command-dispatch-grant+json", "compliance-statement+json", "intel-delta+json", "release+json", "extension-manifest+yaml", "extension-index+json", "escrow-ack+json", "escrow-retirement-authorization+json"}
	for i, typ := range types {
		if string(typ) != "application/vnd.ricevanta."+names[i] {
			t.Fatal("type differs")
		}
		if _, e := Sign(typ, nil, [32]byte{}, testKey()); e != nil {
			t.Fatal(e)
		}
	}
	if MaxPayloadBytes != 16777216 || MaxEnvelopeBytes != 25165824 || MaxSignatures != 1 {
		t.Fatal("limits differ")
	}
	for _, s := range []string{"", "application/vnd.ricevanta.command+json; charset=utf-8", "Application/vnd.ricevanta.command+json", "*"} {
		_, e := Sign(PayloadType(s), nil, [32]byte{}, nil)
		checkError(t, e, ErrPayloadType)
	}
	messages := map[string]string{"ErrEnvelopeTooLarge": "dsse envelope too large", "ErrEnvelope": "dsse envelope format", "ErrSignatureCount": "dsse signature count", "ErrPayloadType": "dsse unsupported payload type", "ErrTypeMismatch": "dsse unexpected payload type", "ErrKeyID": "dsse keyid format", "ErrPayloadTooLarge": "dsse payload too large", "ErrBase64": "dsse base64 format", "ErrSignature": "dsse invalid signature", "ErrPublicKey": "dsse public key length", "ErrPrivateKey": "dsse private key format"}
	for n, e := range sentinels() {
		if e.Error() != messages[n] {
			t.Fatal("sentinel message differs")
		}
	}
}
func TestSignTypeBeforeSizeAndKey(t *testing.T) {
	b, e := Sign("", make([]byte, MaxPayloadBytes+1), [32]byte{}, nil)
	checkError(t, e, ErrPayloadType)
	if b != nil {
		t.Fatal("non-nil error result")
	}
}
func TestSignDeterministic(t *testing.T) {
	a, e := Sign(TypeCommand, nil, [32]byte{}, testKey())
	if e != nil {
		t.Fatal(e)
	}
	b, e := Sign(TypeCommand, []byte{}, [32]byte{}, testKey())
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
}
func TestSignOwnership(t *testing.T) {
	payload := []byte{255, 0, 1}
	key := testKey()
	saved := bytes.Clone(payload)
	savedKey := bytes.Clone(key)
	a, e := Sign(TypeCommand, payload, [32]byte{}, key)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(payload, saved) || !bytes.Equal(key, savedKey) {
		t.Fatal("input mutated")
	}
	b, _ := Sign(TypeCommand, payload, [32]byte{}, key)
	a[0] = 0
	payload[0] = 0
	key[0] = 1
	if b[0] != '{' {
		t.Fatal("aliased output")
	}
}
func TestSignBoundaries(t *testing.T) {
	b, e := Sign(TypeCommand, make([]byte, MaxPayloadBytes+1), [32]byte{}, testKey())
	checkError(t, e, ErrPayloadTooLarge)
	if b != nil {
		t.Fatal("non-nil error result")
	}
	// Successful signing boundaries also verify the resulting envelope below.
}

func checkVerifyError(t testing.TB, b []byte, typ PayloadType, key []byte, want error) {
	t.Helper()
	got, e := Verify(b, typ, key)
	checkError(t, e, want)
	if e != nil && (got.PayloadType != "" || got.Payload != nil || got.KeyID != "" || got.EnvelopeSHA256 != ([32]byte{})) {
		t.Fatal("nonzero error result")
	}
}
func TestVerifyErrors(t *testing.T) {
	b, e := Sign(TypeCommand, nil, [32]byte{}, testKey())
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		checkVerifyError(t, b, TypeCommand, make([]byte, n), ErrPublicKey)
	}
	checkVerifyError(t, b, TypeAssignment, testPublic(), ErrTypeMismatch)
	checkVerifyError(t, b, "", nil, ErrPayloadType)
}
func TestVerifyOwnership(t *testing.T) {
	p := []byte{255, 0, 1}
	key := testKey()
	b, _ := Sign(TypeCommand, p, [32]byte{}, key)
	saved := bytes.Clone(b)
	pub := bytes.Clone(key[32:])
	savedPub := bytes.Clone(pub)
	a, e := Verify(b, TypeCommand, pub)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, saved) || !bytes.Equal(pub, savedPub) {
		t.Fatal("input mutated")
	}
	second, e := Verify(b, TypeCommand, pub)
	if e != nil {
		t.Fatal(e)
	}
	clear(b)
	clear(pub)
	if !bytes.Equal(a.Payload, p) {
		t.Fatal("input aliases result")
	}
	a.Payload[0] = 0
	if !bytes.Equal(second.Payload, p) {
		t.Fatal("results alias")
	}
}
func TestEnvelopeHashBinding(t *testing.T) {
	b, _ := Sign(TypeCommand, []byte("same payload"), [32]byte{}, testKey())
	a, e := Verify(b, TypeCommand, testPublic())
	if e != nil {
		t.Fatal(e)
	}
	for _, formatted := range [][]byte{append([]byte(" \n"), b...), reorderWire(t, b)} {
		v, e := Verify(formatted, TypeCommand, testPublic())
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(a.Payload, v.Payload) || a.EnvelopeSHA256 == v.EnvelopeSHA256 || v.EnvelopeSHA256 != sha256.Sum256(formatted) {
			t.Fatal("received bytes not bound")
		}
	}
}
func TestKeyIDIsHint(t *testing.T) {
	b, _ := Sign(TypeCommand, nil, [32]byte{}, testKey())
	a, e := Verify(b, TypeCommand, testPublic())
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte(strings.Repeat("0", 64)), []byte(strings.Repeat("f", 64)), 1)
	v, e := Verify(b, TypeCommand, testPublic())
	if e != nil {
		t.Fatal(e)
	}
	if v.KeyID != strings.Repeat("f", 64) || a.EnvelopeSHA256 == v.EnvelopeSHA256 {
		t.Fatal("hint or hash differs")
	}
}
func TestSignatureCount(t *testing.T) {
	b, _ := Sign(TypeCommand, nil, [32]byte{}, testKey())
	var root map[string]json.RawMessage
	json.Unmarshal(b, &root)
	for _, n := range []int{0, 1, 2} {
		var sigs []json.RawMessage
		json.Unmarshal(root["signatures"], &sigs)
		one := sigs[0]
		sigs = make([]json.RawMessage, n)
		for i := range sigs {
			sigs[i] = one
		}
		root["signatures"], _ = json.Marshal(sigs)
		b, _ := json.Marshal(root)
		want := ErrSignatureCount
		if n == 1 {
			want = nil
		}
		checkVerifyError(t, b, TypeCommand, testPublic(), want)
		root["signatures"], _ = json.Marshal([]json.RawMessage{one})
	}
}
func TestVerifyBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, MaxPayloadBytes - 1, MaxPayloadBytes} {
		p := bytes.Repeat([]byte{255}, n)
		b, e := Sign(TypeCommand, p, [32]byte{}, testKey())
		if e != nil || len(b) > MaxEnvelopeBytes {
			t.Fatalf("signed payload length %d: %v", n, e)
		}
		got, e := Verify(b, TypeCommand, testPublic())
		if e != nil || !bytes.Equal(got.Payload, p) || got.Payload == nil {
			t.Fatalf("payload length %d: %v", n, e)
		}
	}
	b, _ := Sign(TypeCommand, nil, [32]byte{}, testKey())
	for _, n := range []int{MaxEnvelopeBytes - 1, MaxEnvelopeBytes, MaxEnvelopeBytes + 1} {
		padded := append(bytes.Clone(b), bytes.Repeat([]byte(" "), n-len(b))...)
		want := ErrEnvelopeTooLarge
		if n <= MaxEnvelopeBytes {
			want = nil
		}
		checkVerifyError(t, padded, TypeCommand, testPublic(), want)
	}
}
func reorderWire(t testing.TB, b []byte) []byte {
	t.Helper()
	var r map[string]json.RawMessage
	if e := json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	var ss []map[string]json.RawMessage
	if e := json.Unmarshal(r["signatures"], &ss); e != nil {
		t.Fatal(e)
	}
	var sigs []string
	for _, s := range ss {
		sigs = append(sigs, `{"sig":`+string(s["sig"])+`,"keyid":`+string(s["keyid"])+`}`)
	}
	extra := ""
	if x, ok := r["extra"]; ok {
		extra = `,"extra":` + string(x)
	}
	return []byte(`{"signatures":[` + strings.Join(sigs, ",") + `],"payload":` + string(r["payload"]) + `,"payloadType":` + string(r["payloadType"]) + extra + `}`)
}

// precedenceFixture keeps the payload at a fixed offset in each member order.
// Tests run serially; each wire view lasts until the next call to members.
type precedenceFixture struct {
	buffers [2][]byte
	end     int
}

func newPrecedenceFixture(payload []byte) *precedenceFixture {
	const offset = 1024
	f := &precedenceFixture{end: offset + len(payload)}
	for i := range f.buffers {
		f.buffers[i] = make([]byte, f.end+1024)
		copy(f.buffers[i][offset:], payload)
	}
	return f
}

func (f *precedenceFixture) members(hint, sig string, count int, extra, oversize bool) [2][]byte {
	const offset = 1024
	normal := `{"keyid":"` + hint + `","sig":"` + sig + `"}`
	reversed := `{"sig":"` + sig + `","keyid":"` + hint + `"}`
	if count == 2 {
		normal += "," + normal
		reversed += "," + reversed
	}
	unknown := ""
	if extra {
		unknown = `,"extra":0`
	}
	prefixes := [2]string{
		`{"payloadType":"` + string(TypeCommand) + `","payload":"`,
		`{"signatures":[` + reversed + `],"payload":"`,
	}
	suffixes := [2]string{
		`","signatures":[` + normal + `]` + unknown + `}`,
		`","payloadType":"` + string(TypeCommand) + `"` + unknown + `}`,
	}
	var wires [2][]byte
	for i := range wires {
		start := offset - len(prefixes[i])
		end := f.end + len(suffixes[i])
		if oversize && start+MaxEnvelopeBytes+1 > len(f.buffers[i]) {
			f.buffers[i] = append(f.buffers[i], make([]byte, start+MaxEnvelopeBytes+1-len(f.buffers[i]))...)
		}
		copy(f.buffers[i][start:offset], prefixes[i])
		copy(f.buffers[i][f.end:end], suffixes[i])
		if oversize {
			paddedEnd := start + MaxEnvelopeBytes + 1
			for j := end; j < paddedEnd; j++ {
				f.buffers[i][j] = ' '
			}
			end = paddedEnd
		}
		wires[i] = f.buffers[i][start:end]
	}
	return wires
}

func TestVerifyPrecedence(t *testing.T) {
	// Each mutation represents one ordered check, including the base64 sub-stages.
	wants := []error{ErrEnvelopeTooLarge, ErrEnvelope, ErrSignatureCount, ErrPayloadType, ErrTypeMismatch, ErrKeyID, ErrPayloadTooLarge, ErrBase64, ErrPayloadTooLarge, ErrBase64, ErrSignature, ErrPublicKey, ErrSignature}
	fixtures := map[int]*precedenceFixture{}
	fixture := func(stage int) *precedenceFixture {
		if f := fixtures[stage]; f != nil {
			return f
		}
		var payload []byte
		switch stage {
		case 6:
			payload = bytes.Repeat([]byte("!"), 22369625)
		case 7:
			payload = []byte("!")
		case 8:
			payload = bytes.Repeat([]byte("A"), 22369624)
		}
		f := newPrecedenceFixture(payload)
		fixtures[stage] = f
		return f
	}
	for i := range wants {
		for j := i + 1; j < len(wants); j++ {
			t.Run(fmt.Sprintf("%d-before-%d", i, j), func(t *testing.T) {
				payloadStage := -1
				hint := hintText
				sig := std64(make([]byte, 64))
				expected := TypeCommand
				pub := testPublic()
				count := 1
				extra := false
				oversize := false
				for _, stage := range []int{j, i} {
					switch stage {
					case 0:
						oversize = true
					case 1:
						extra = true
					case 2:
						count = 2
					case 3:
						expected = ""
					case 4:
						expected = TypeBundleManifest
					case 5:
						hint = "bad"
					case 6:
						payloadStage = 6
					case 7:
						payloadStage = 7
					case 8:
						payloadStage = 8
					case 9:
						sig = "!"
					case 10:
						sig = ""
					case 11:
						pub = nil
					case 12:
						sig = std64(make([]byte, 64))
					}
				}
				for _, ordered := range fixture(payloadStage).members(hint, sig, count, extra, oversize) {
					checkVerifyError(t, ordered, expected, pub, wants[i])
				}
			})
		}
	}
}

func testPublic() ed25519.PublicKey { return ed25519.PublicKey(testKey()[32:]) }
