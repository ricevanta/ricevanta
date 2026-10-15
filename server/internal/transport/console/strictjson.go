package console

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// checkStrictJSON applies release builds section 5.1 to one JSON document:
// UTF-8 without a byte-order mark, exactly one value, and no duplicate object
// key at any depth. encoding/json alone would replace invalid UTF-8, keep the
// last duplicate and ignore nothing after the value only when asked.
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
	return nil
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

// decodeStrict checks data with checkStrictJSON and decodes it into v,
// rejecting unknown fields when closed is true.
func decodeStrict(data []byte, v any, closed bool) error {
	if err := checkStrictJSON(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if closed {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("unexpected structure: %w", err)
	}
	return nil
}
