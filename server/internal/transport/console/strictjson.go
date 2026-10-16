package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// checkStrictJSON applies release builds section 5.1 to one JSON document:
// UTF-8 without a byte-order mark, no unpaired surrogate escape, exactly one
// value, and no duplicate object key at any depth. encoding/json alone would
// replace invalid UTF-8 and lone surrogates with U+FFFD, keep the last
// duplicate and stop at the first value.
func checkStrictJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return errors.New("starts with a byte order mark")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return checkSurrogates(data)
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return fmt.Errorf("malformed JSON: %w", err)
			}
			key, ok := k.(string)
			if !ok {
				return errors.New("malformed JSON: object key")
			}
			if seen[key] {
				return errors.New("duplicate object key")
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("malformed JSON: %w", err)
		}
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("malformed JSON: %w", err)
		}
	}
	return nil
}

// checkSurrogates rejects a \u escape in the surrogate range that is not a
// high surrogate immediately followed by a low surrogate escape. data has
// already passed the token walk, so it is well-formed JSON.
func checkSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 < len(data) && data[i+1] == 'u' {
				v := hex4(data, i+2)
				switch {
				case v >= 0xD800 && v <= 0xDBFF:
					if i+11 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
						if w := hex4(data, i+8); w >= 0xDC00 && w <= 0xDFFF {
							i += 11
							continue
						}
					}
					return errors.New("unpaired surrogate escape")
				case v >= 0xDC00 && v <= 0xDFFF:
					return errors.New("unpaired surrogate escape")
				}
				i += 5
			} else {
				i++
			}
		}
	}
	return nil
}

func hex4(data []byte, at int) int {
	if at+4 > len(data) {
		return -1
	}
	v, err := strconv.ParseUint(string(data[at:at+4]), 16, 16)
	if err != nil {
		return -1
	}
	return int(v)
}

// fields checks one strict JSON object and returns its members. Every key
// must be one of allowed byte for byte, so a case or Unicode-folding variant
// of a contract field is an unknown field rather than an alias, as it would
// be under encoding/json's struct decoding.
func fields(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errors.New("expected a JSON object")
	}
	for k := range m {
		known := false
		for _, a := range allowed {
			known = known || k == a
		}
		if !known {
			return nil, fmt.Errorf("unknown field %q", k)
		}
	}
	return m, nil
}

// noFoldAlias rejects a key that folds to one of names without being equal
// to it, in an object whose other keys are open.
func noFoldAlias(m map[string]json.RawMessage, names ...string) error {
	for k := range m {
		for _, n := range names {
			if k != n && strings.EqualFold(k, n) {
				return fmt.Errorf("field %q is a case or folding variant of %q", k, n)
			}
		}
	}
	return nil
}

// stringField decodes a required JSON string member.
func stringField(m map[string]json.RawMessage, name string) (string, error) {
	raw, ok := m[name]
	if !ok {
		return "", fmt.Errorf("missing %s", name)
	}
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return s, nil
}
