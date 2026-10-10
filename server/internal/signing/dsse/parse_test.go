package dsse

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const hintText = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func wire(typ, payload, hint, sig string) []byte {
	b, _ := json.Marshal(struct {
		Type       string              `json:"payloadType"`
		Payload    string              `json:"payload"`
		Signatures []map[string]string `json:"signatures"`
	}{typ, payload, []map[string]string{{"keyid": hint, "sig": sig}}})
	return b
}
func validWire() []byte { return wire(string(TypeCommand), "", hintText, std64(make([]byte, 64))) }
func parseError(t *testing.T, b []byte, expected PayloadType, want error) {
	t.Helper()
	_, e := parseEnvelope(b, expected)
	checkError(t, e, want)
}
func TestParseVectors(t *testing.T) {
	c := loadCorpus(t)
	for _, v := range c.Positive {
		t.Run(v.Name, func(t *testing.T) {
			p, e := parseEnvelope(unhex(t, v.Envelope), PayloadType(v.Type))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(p.payload, unhex(t, v.Payload)) || p.keyID != v.KeyID || !bytes.Equal(p.signature, unhex(t, v.Signature)) {
				t.Fatal("parsed bytes differ")
			}
		})
	}
	for _, v := range c.Negative {
		// Verify executes these full-size recipes through parseEnvelope too.
		if v.Recipe != nil {
			continue
		}
		if v.Error == "ErrPublicKey" || v.Error == "ErrSignature" && !strings.Contains(v.Name, "short-signature") && !strings.Contains(v.Name, "long-signature") && v.Name != "empty-signature" && v.Name != "signature-shape-before-public-key" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			parseError(t, expand(t, v.Envelope, v.Recipe), PayloadType(v.Type), sentinels()[v.Error])
		})
	}
}
func TestParseShape(t *testing.T) {
	base := string(validWire())
	for _, b := range []string{"null", "[]", "{}", base + "{}", "\ufeff" + base, strings.Replace(base, `"payload":`, `"Payload":`, 1), strings.Replace(base, `"payload":""`, `"payload":null`, 1), strings.Replace(base, `"payload":""`, `"payload":{}`, 1), strings.Replace(base, `"payload":""`, `"payload":"","pa\u0079load":""`, 1), strings.Replace(base, `"keyid":`, `"Keyid":`, 1), strings.Replace(base, `"sig":`, `"extra":`, 1)} {
		parseError(t, []byte(b), TypeCommand, ErrEnvelope)
	}
	for _, field := range []string{"payloadType", "payload", "signatures"} {
		var m map[string]json.RawMessage
		json.Unmarshal(validWire(), &m)
		delete(m, field)
		b, _ := json.Marshal(m)
		parseError(t, b, TypeCommand, ErrEnvelope)
	}
	for _, field := range []string{"keyid", "sig"} {
		var m map[string]json.RawMessage
		json.Unmarshal(validWire(), &m)
		var ss []map[string]string
		json.Unmarshal(m["signatures"], &ss)
		delete(ss[0], field)
		m["signatures"], _ = json.Marshal(ss)
		b, _ := json.Marshal(m)
		parseError(t, b, TypeCommand, ErrEnvelope)
	}
}
func TestParseUnicode(t *testing.T) {
	for _, s := range []string{`\ud800`, `\udc00`, `\ud800\u0041`, `\ud800\ud800`} {
		parseError(t, []byte(strings.Replace(string(validWire()), hintText, s, 1)), TypeCommand, ErrEnvelope)
	}
	parseError(t, []byte(strings.Replace(string(validWire()), hintText, `\ud83d\ude00`, 1)), TypeCommand, ErrKeyID)
	b := validWire()
	b[2] = 255
	parseError(t, b, TypeCommand, ErrEnvelope)
	b = []byte(strings.Replace(string(validWire()), `"payloadType"`, `"payload\u0054ype"`, 1))
	parseError(t, b, TypeCommand, nil)
}
func TestParseBase64(t *testing.T) {
	for _, s := range []string{"A", "AA", "AAA", "AAAA=", "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "-w==", "_w==", "Zg==\r", "Zg==\n", "Zg== "} {
		parseError(t, wire(string(TypeCommand), s, hintText, std64(make([]byte, 64))), TypeCommand, ErrBase64)
	}
	for _, s := range []string{"", "Zg==", "Zm8=", "Zm9v"} {
		parseError(t, wire(string(TypeCommand), s, hintText, std64(make([]byte, 64))), TypeCommand, nil)
	}
	for _, n := range []int{0, 63, 64, 65} {
		want := ErrSignature
		if n == 64 {
			want = nil
		}
		parseError(t, wire(string(TypeCommand), "", hintText, std64(make([]byte, n))), TypeCommand, want)
	}
}
func TestParseLimits(t *testing.T) {
	// TestVerifyBoundaries covers received-size limits through parseEnvelope.
	parseError(t, wire(string(TypeCommand), strings.Repeat("!", 22369624), hintText, "!"), TypeCommand, ErrBase64)
	parseError(t, wire(string(TypeCommand), strings.Repeat("!", 22369625), hintText, "!"), TypeCommand, ErrPayloadTooLarge)
	parseError(t, wire(string(TypeCommand), strings.Repeat("A", 22369624), hintText, "!"), TypeCommand, ErrPayloadTooLarge)
}
func TestParsePrecedence(t *testing.T) {
	for _, b := range []string{`{"payloadType":"","payload":"","signatures":[],"extra":0}`, `{"extra":0,"signatures":[],"payload":"","payloadType":""}`, `{"payloadType":"","payload":"","signatures":[{},{}]}`, `{"payloadType":"","payload":"","signatures":[],"extra":"\ud800"}`} {
		parseError(t, []byte(b), TypeCommand, ErrEnvelope)
	}
}
