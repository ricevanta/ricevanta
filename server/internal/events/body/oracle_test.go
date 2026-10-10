package body

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
	"github.com/ricevanta/ricevanta/server/internal/events/eventid"
)

var referenceStrings = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
var referenceSequence = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// referenceValue builds a test-only tree. It keeps parsing after key defects so
// malformed JSON takes precedence, and never calls the production JSON helpers.
func referenceValue(d *json.Decoder, depth int, scope string, badKeys *bool) (any, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	if depth > MaxJSONDepth {
		return nil, ErrJSON
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, ErrJSON
			}
			if _, exists := object[key]; exists {
				*badKeys = true
			}
			var recognized []string
			switch scope {
			case "root":
				recognized = []string{"metadata", "device"}
			case "metadata":
				recognized = []string{"uid", "sequence"}
			case "device":
				recognized = []string{"uid"}
			}
			for _, exact := range recognized {
				if key != exact && strings.EqualFold(key, exact) {
					*badKeys = true
				}
			}
			childScope := ""
			if scope == "root" && (key == "metadata" || key == "device") {
				childScope = key
			}
			value, err := referenceValue(d, depth+1, childScope, badKeys)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrJSON
		}
		return object, nil
	case '[':
		for d.More() {
			if _, err := referenceValue(d, depth+1, "", badKeys); err != nil {
				return nil, err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrJSON
		}
		return []any{}, nil
	default:
		return nil, ErrJSON
	}
}

// encoding/json repairs unpaired surrogates. Inspect original string lexemes
// separately, while allowing literal U+FFFD and escaped backslashes.
func referenceSurrogates(raw []byte) bool {
	for _, quoted := range referenceStrings.FindAll(raw, -1) {
		for i := 1; i < len(quoted)-1; i++ {
			if quoted[i] != '\\' {
				continue
			}
			i++
			if quoted[i] != 'u' {
				continue
			}
			code, err := strconv.ParseUint(string(quoted[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if code >= 0xdc00 && code <= 0xdfff {
				return false
			}
			if code >= 0xd800 && code <= 0xdbff {
				if len(quoted)-1-i < 7 || string(quoted[i+1:i+3]) != "\\u" {
					return false
				}
				low, err := strconv.ParseUint(string(quoted[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

func referenceLine(raw []byte, number uint32, d batch.Descriptor, device string) Line {
	want := Line{}
	reject := func(err error) Line {
		want.Err = err
		return want
	}
	if !utf8.Valid(raw) {
		return reject(ErrJSON)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	badKeys := false
	value, err := referenceValue(decoder, 1, "root", &badKeys)
	if err != nil {
		return reject(ErrJSON)
	}
	root, object := value.(map[string]any)
	if _, err := decoder.Token(); err != io.EOF || !object || !referenceSurrogates(raw) {
		return reject(ErrJSON)
	}
	if badKeys {
		return reject(ErrJSONKeys)
	}
	metadata, metadataOK := root["metadata"].(map[string]any)
	deviceObject, deviceOK := root["device"].(map[string]any)
	deviceUID, deviceUIDOK := deviceObject["uid"].(string)
	want.DeviceMismatch = deviceOK && deviceUIDOK && deviceUID != device
	uid, uidOK := metadata["uid"].(string)
	sequenceToken, sequenceOK := metadata["sequence"].(json.Number)
	if !metadataOK || !deviceOK || !uidOK || !deviceUIDOK || !sequenceOK || !referenceSequence.MatchString(string(sequenceToken)) {
		return reject(ErrFields)
	}
	sequence, err := strconv.ParseUint(string(sequenceToken), 10, 64)
	if err != nil {
		return reject(ErrFields)
	}
	id, err := eventid.Parse(uid)
	if err != nil {
		return reject(errors.Join(ErrEventID, err))
	}
	if sequence < d.FirstSequence || sequence > d.LastSequence {
		return reject(ErrSequenceRange)
	}
	if number == 0 || number > d.RecordCount || sequence != d.FirstSequence+uint64(number-1) {
		return reject(ErrSequencePosition)
	}
	if want.DeviceMismatch {
		return reject(ErrDeviceBinding)
	}
	want.EventID, want.Sequence, want.DeviceUID = id, sequence, deviceUID
	return want
}

func assertReferenceLine(t testing.TB, got Line, raw []byte, number uint32, d batch.Descriptor, device string) {
	t.Helper()
	want := referenceLine(raw, number, d, device)
	if (got.Err == nil) != (want.Err == nil) {
		t.Fatalf("acceptance: got %v, reference %v", got.Err, want.Err)
	}
	for _, class := range []error{ErrJSON, ErrJSONKeys, ErrFields, ErrEventID, ErrSequenceRange, ErrSequencePosition, ErrDeviceBinding, eventid.ErrFormat, eventid.ErrNonCanonical, eventid.ErrVersion, eventid.ErrVariant} {
		if errors.Is(got.Err, class) != errors.Is(want.Err, class) {
			t.Fatalf("error class %v: got %v, reference %v", class, got.Err, want.Err)
		}
	}
	if got.EventID != want.EventID || got.Sequence != want.Sequence || got.DeviceUID != want.DeviceUID || got.DeviceMismatch != want.DeviceMismatch {
		t.Fatal("identities or device mismatch differ from raw input")
	}
}

// Fixture expectations come from the approved contract, not the extractor.
func TestReferenceLineFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	for _, c := range fixtures.Cases {
		if c.Expected.Error != nil {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			_, plain, d := fixtureBytes(t, c, fixtures.Template)
			rawLines := bytes.Split(plain[:len(plain)-1], []byte{'\n'})
			i := 0
			for _, expected := range c.Expected.Lines {
				for offset := 0; offset < expected.Count; offset++ {
					raw := rawLines[i]
					number := uint32(i + 1)
					got := referenceLine(raw, number, d, c.Device)
					got.Raw, got.Number = raw, number
					assertLine(t, got, raw, number, expected, offset)
					i++
				}
			}
		})
	}
}
