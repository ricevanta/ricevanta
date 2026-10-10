package dsse

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

type parsed struct {
	typ                PayloadType
	keyID              string
	payload, signature []byte
}
type rawFields struct {
	typ, payload, keyID, signature string
	count                          int
}

func parseEnvelope(envelope []byte, expected PayloadType) (parsed, error) {
	if len(envelope) > MaxEnvelopeBytes {
		return parsed{}, ErrEnvelopeTooLarge
	}
	if !json.Valid(envelope) || !utf8.Valid(envelope) || !validSurrogates(envelope) {
		return parsed{}, ErrEnvelope
	}
	r, e := readFields(envelope)
	if e != nil {
		return parsed{}, e
	}
	if r.count != MaxSignatures {
		return parsed{}, ErrSignatureCount
	}
	typ := PayloadType(r.typ)
	if !supported(expected) || !supported(typ) {
		return parsed{}, ErrPayloadType
	}
	if typ != expected {
		return parsed{}, ErrTypeMismatch
	}
	if len(r.keyID) != 64 {
		return parsed{}, ErrKeyID
	}
	for _, c := range []byte(r.keyID) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return parsed{}, ErrKeyID
		}
	}
	if len(r.payload) > 22369624 {
		return parsed{}, ErrPayloadTooLarge
	}
	payload, e := decode64(r.payload)
	if e != nil {
		return parsed{}, e
	}
	if len(payload) > MaxPayloadBytes {
		return parsed{}, ErrPayloadTooLarge
	}
	signature, e := decode64(r.signature)
	if e != nil {
		return parsed{}, e
	}
	if len(signature) != 64 {
		return parsed{}, ErrSignature
	}
	return parsed{typ, r.keyID, payload, signature}, nil
}

func decode64(text string) ([]byte, error) {
	b, e := base64.StdEncoding.Strict().DecodeString(text)
	if e != nil || base64.StdEncoding.EncodeToString(b) != text {
		return nil, ErrBase64
	}
	return b, nil
}

// JSON syntax is checked first, so escape spans have known bounds here.
// encoding/json otherwise replaces unpaired surrogates with U+FFFD.
func validSurrogates(b []byte) bool {
	inString := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || b[i] != '\\' {
			continue
		}
		i++
		if b[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
		if e != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

func delimiter(d *json.Decoder, want json.Delim) bool {
	v, e := d.Token()
	return e == nil && v == want
}
func stringToken(d *json.Decoder) (string, bool) {
	v, e := d.Token()
	s, ok := v.(string)
	return s, e == nil && ok
}

func readFields(b []byte) (rawFields, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	var r rawFields
	if !delimiter(d, '{') {
		return r, ErrEnvelope
	}
	seen := uint8(0)
	for d.More() {
		name, ok := stringToken(d)
		if !ok {
			return rawFields{}, ErrEnvelope
		}
		var bit uint8
		switch name {
		case "payloadType":
			bit = 1
		case "payload":
			bit = 2
		case "signatures":
			bit = 4
		default:
			return rawFields{}, ErrEnvelope
		}
		if seen&bit != 0 {
			return rawFields{}, ErrEnvelope
		}
		seen |= bit
		if bit != 4 {
			value, ok := stringToken(d)
			if !ok {
				return rawFields{}, ErrEnvelope
			}
			if bit == 1 {
				r.typ = value
			} else {
				r.payload = value
			}
			continue
		}
		if !delimiter(d, '[') {
			return rawFields{}, ErrEnvelope
		}
		for d.More() {
			keyID, sig, e := readSignature(d)
			if e != nil {
				return rawFields{}, e
			}
			if r.count == 0 {
				r.keyID = keyID
				r.signature = sig
			}
			r.count++
		}
		if !delimiter(d, ']') {
			return rawFields{}, ErrEnvelope
		}
	}
	if seen != 7 || !delimiter(d, '}') {
		return rawFields{}, ErrEnvelope
	}
	return r, nil
}

func readSignature(d *json.Decoder) (string, string, error) {
	if !delimiter(d, '{') {
		return "", "", ErrEnvelope
	}
	seen := uint8(0)
	var keyID, sig string
	for d.More() {
		name, ok := stringToken(d)
		if !ok {
			return "", "", ErrEnvelope
		}
		var bit uint8
		switch name {
		case "keyid":
			bit = 1
		case "sig":
			bit = 2
		default:
			return "", "", ErrEnvelope
		}
		if seen&bit != 0 {
			return "", "", ErrEnvelope
		}
		seen |= bit
		value, ok := stringToken(d)
		if !ok {
			return "", "", ErrEnvelope
		}
		if bit == 1 {
			keyID = value
		} else {
			sig = value
		}
	}
	if seen != 3 || !delimiter(d, '}') {
		return "", "", ErrEnvelope
	}
	return keyID, sig, nil
}
