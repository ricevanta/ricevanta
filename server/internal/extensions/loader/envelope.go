package loader

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

const maxPayloadCharacters = 1398104

// checkPayloadBudget measures decoded root payload strings only. It does not
// decode base64, construct a generic tree, or grant authority to any JSON field.
func checkPayloadBudget(envelope []byte) error {
	d := json.NewDecoder(bytes.NewReader(envelope))
	d.UseNumber()
	token, err := d.Token()
	if err != nil {
		return dsse.ErrEnvelope
	}
	if err = walkEnvelopeValue(d, token, 0); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return dsse.ErrEnvelope
	}
	return nil
}

// The recursion is bounded to four containers, including the root container.
func walkEnvelopeValue(d *json.Decoder, token json.Token, depth int) error {
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return dsse.ErrEnvelope
	}
	depth++
	if depth > 4 {
		return dsse.ErrEnvelope
	}
	for d.More() {
		rootPayload := false
		if delimiter == '{' {
			key, err := d.Token()
			if err != nil {
				return dsse.ErrEnvelope
			}
			name, ok := key.(string)
			if !ok {
				return dsse.ErrEnvelope
			}
			rootPayload = depth == 1 && name == "payload"
		}
		value, err := d.Token()
		if err != nil {
			return dsse.ErrEnvelope
		}
		if rootPayload {
			if text, ok := value.(string); ok {
				// Token has decoded JSON escapes. Count Unicode characters without
				// copying or allocating; DSSE owns malformed Unicode/base64 checks.
				characters := utf8.RuneCountInString(text)
				if characters > maxPayloadCharacters || (characters == maxPayloadCharacters && !strings.HasSuffix(text, "==")) {
					return ErrPayloadLimit
				}
			}
		}
		if err = walkEnvelopeValue(d, value, depth); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil {
		return dsse.ErrEnvelope
	}
	expected := json.Delim('}')
	if delimiter == '[' {
		expected = ']'
	}
	if end != expected {
		return dsse.ErrEnvelope
	}
	return nil
}
