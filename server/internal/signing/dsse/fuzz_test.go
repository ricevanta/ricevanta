package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/signing/ed25519key"
)

func FuzzVerify(f *testing.F) {
	c := loadCorpus(f)
	for _, v := range c.Positive {
		key := keyFor(f, c, v.Key)
		f.Add(unhex(f, v.Envelope), v.Type, []byte(key[32:]))
	}
	for _, v := range c.Negative {
		if v.Recipe == nil {
			f.Add(unhex(f, v.Envelope), v.Type, unhex(f, v.Public))
		}
	}
	for _, v := range admissionVectors(f) {
		if v.Expected != "accept" {
			f.Add(admissionEnvelope(TypeCommand, nil, bytes.Repeat([]byte{255}, 64)), string(TypeCommand), unhex(f, v.Public))
		}
	}
	f.Fuzz(func(t *testing.T, envelope []byte, expected string, key []byte) {
		if len(envelope) > 1024*1024 || len(expected) > 1024 || len(key) > 1024 {
			t.Skip()
		}
		checkVerifyInvariants(t, envelope, expected, key)
	})
}

func checkVerifyInvariants(t *testing.T, envelope []byte, expected string, key []byte) {
	t.Helper()
	before := bytes.Clone(envelope)
	beforeKey := bytes.Clone(key)
	got, e := Verify(envelope, PayloadType(expected), key)
	if !bytes.Equal(envelope, before) || !bytes.Equal(key, beforeKey) {
		t.Fatal("input changed")
	}
	if e != nil {
		if got.PayloadType != "" || got.Payload != nil || got.KeyID != "" || got.EnvelopeSHA256 != ([32]byte{}) {
			t.Fatal("nonzero error result")
		}
		matches := 0
		for _, sentinel := range sentinels() {
			if errors.Is(e, sentinel) {
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("error must match exactly one sentinel")
		}
		return
	}
	if ed25519key.Validate(key) != nil {
		t.Fatal("success with inadmissible key")
	}
	allowed := false
	for _, suffix := range []string{"bundle-manifest+json", "assignment+json", "rulepack-manifest+json", "command+json", "command-dispatch-grant+json", "compliance-statement+json", "intel-delta+json", "release+json", "extension-manifest+yaml", "extension-index+json", "escrow-ack+json", "escrow-retirement-authorization+json"} {
		if expected == "application/vnd.ricevanta."+suffix {
			allowed = true
		}
	}
	if !allowed || string(got.PayloadType) != expected || got.Payload == nil || len(got.Payload) > 16777216 || got.EnvelopeSHA256 != sha256.Sum256(before) {
		t.Fatal("success boundary violated")
	}
	// Unmarshal extracts fields only after Verify succeeds. It does not check
	// strict JSON acceptance, including duplicate names or invalid Unicode.
	var wire struct {
		Type       string `json:"payloadType"`
		Payload    string `json:"payload"`
		Signatures []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if e := json.Unmarshal(before, &wire); e != nil {
		t.Fatal(e)
	}
	if wire.Type != expected || len(wire.Signatures) != 1 || wire.Signatures[0].KeyID != got.KeyID || len(got.KeyID) != 64 || strings.Trim(got.KeyID, "0123456789abcdef") != "" {
		t.Fatal("wire fields differ")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(wire.Payload)
	if e != nil || !bytes.Equal(payload, got.Payload) || base64.StdEncoding.EncodeToString(payload) != wire.Payload {
		t.Fatal("payload differs")
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(wire.Signatures[0].Sig)
	if e != nil || base64.StdEncoding.EncodeToString(sig) != wire.Signatures[0].Sig {
		t.Fatal("signature encoding differs")
	}
	// Construct PAE independently of the production helper.
	message := append([]byte(fmt.Sprintf("DSSEv1 %d %s %d ", len([]byte(expected)), expected, len(got.Payload))), got.Payload...)
	if len(key) != 32 || !ed25519.Verify(key, message, sig) {
		t.Fatal("independent signature check failed")
	}
	saved := bytes.Clone(got.Payload)
	hash := got.EnvelopeSHA256
	hint := got.KeyID
	clear(envelope)
	clear(key)
	if !bytes.Equal(got.Payload, saved) || got.EnvelopeSHA256 != hash || got.KeyID != hint {
		t.Fatal("result aliases input")
	}
}
