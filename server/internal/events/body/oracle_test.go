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

// referenceFields derives the walker's identity fields from the reference tree.
// The line must already pass validLineJSON.
func referenceFields(t testing.TB, raw []byte) (identityFields, bool) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	badKeys := false
	value, err := referenceValue(decoder, 1, "root", &badKeys)
	if err != nil {
		t.Fatalf("reference rejected a valid line: %v", err)
	}
	var fields identityFields
	if badKeys {
		return fields, false
	}
	root := value.(map[string]any)
	capture := func(object map[string]any, name string) referenceValueKind {
		v, ok := object[name]
		switch {
		case !ok:
			return referenceValueKind{kind: valueAbsent}
		default:
			switch x := v.(type) {
			case string:
				return referenceValueKind{kind: valueString, text: x}
			case json.Number:
				return referenceValueKind{kind: valueNumber, text: string(x)}
			}
		}
		return referenceValueKind{kind: valueOther}
	}
	metadata, metadataOK := root["metadata"].(map[string]any)
	device, deviceOK := root["device"].(map[string]any)
	fields.metadata, fields.device = metadataOK, deviceOK
	if metadataOK {
		fields.uid = capture(metadata, "uid").value()
		fields.sequence = capture(metadata, "sequence").value()
	}
	if deviceOK {
		fields.deviceUID = capture(device, "uid").value()
	}
	return fields, true
}

type referenceValueKind struct {
	kind valueKind
	text string
}

// value encodes the reference result as a walker value whose decoded text is
// text; string tokens are re-quoted so decoding them yields text exactly.
func (r referenceValueKind) value() identityValue {
	switch r.kind {
	case valueString:
		quoted, _ := json.Marshal(r.text)
		return identityValue{kind: valueString, token: quoted[1 : len(quoted)-1]}
	case valueNumber:
		return identityValue{kind: valueNumber, token: []byte(r.text)}
	}
	return identityValue{kind: r.kind}
}

func sameIdentity(a, b identityFields) bool {
	same := func(x, y identityValue) bool {
		return x.kind == y.kind && x.text() == y.text()
	}
	return a.metadata == b.metadata && a.device == b.device && same(a.uid, b.uid) && same(a.sequence, b.sequence) && same(a.deviceUID, b.deviceUID)
}

func assertWalkOracle(t testing.TB, w *lineWalker, line []byte) {
	t.Helper()
	want, wantOK := referenceFields(t, line)
	got, gotOK := w.walkFields(line)
	if gotOK != wantOK || wantOK && !sameIdentity(got, want) {
		shown := line
		if len(shown) > 200 {
			shown = shown[:200]
		}
		t.Fatalf("walker %v %+v, reference %v %+v for %q", gotOK, got, wantOK, want, shown)
	}
}

var walkParityLines = []string{
	`{"metadata":{"u\u0069d":"a","uid":"b","sequence":1},"device":{"uid":"x"}}`,
	`{"metadata":{"\u0075id":"a","sequence":1},"device":{"uid":"x"}}`,
	`{"m\u0065tadata":{"uid":"a","sequence":1},"device":{"uid":"x"}}`,
	`{"metadata":{"uid":"a","sequence":1},"d\u0065vice":{"\u0075\u0069\u0064":"x"}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"\u006d\u0065\u0074\u0061\u0064\u0061\u0074\u0061":{}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"Z":1,"z":1}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"ſequence":1,"SEQUENCE":2}`,
	`{"metadata":{"uid":"a","ſequence":1,"sequence":1},"device":{"uid":"x"}}`,
	`{"metadata":{"uid":"a","ſequence":1},"device":{"uid":"x"}}`,
	`{"metadata":{"uid":"a","sequence":1,"UID":"c"},"device":{"uid":"x"}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x","\u212Aey":1,"Kelvin":2}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"DEVİCE":1}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":[{"a":1},{"a":2}]}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":[{"a":1,"a":2}]}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":[[{"q":1,"r":2,"q":3}]]}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":{"a":1,"a":2}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":{"a":{"a":1},"b":{"a":1}}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"z":{"a":{"a":{"a":{}}}}}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"a":1,"a":2}`,
	`{"metadata":{"uid":"a","sequence":1},"device":{"uid":"x"},"metadata":{}}`,
	`{"metadata":{"uid":"\ud83d\ude00","sequence":1},"device":{"uid":"\u00e9\ud834\udd1e"}}`,
	`{"metadata":{"uid":"😀","sequence":1},"device":{"uid":"é"}}`,
	`{"metadata":{"uid":"a\"b\\c\/d\b\f\n\r\t","sequence":1},"device":{"uid":"\u0000"}}`,
	`{"metadata":{"uid":null,"sequence":"1"},"device":{"uid":true}}`,
	`{"metadata":{"uid":false,"sequence":-0},"device":{"uid":1e5}}`,
	`{"metadata":{"uid":{"a":1},"sequence":[1]},"device":{"uid":[1]}}`,
	`{"metadata":{"uid":"a","sequence":1.5e+10},"device":{"uid":{}}}`,
	`{"metadata":[],"device":{"uid":"x"}}`,
	`{"metadata":"x","device":null}`,
	`{"metadata":[{"uid":"a","sequence":1}],"device":[{"uid":"x"}]}`,
	`{"z":{"metadata":{"uid":"a"}},"device":{"uid":"x","metadata":{"uid":"q"}}}`,
	`{"metadata":{"uid":"a","sequence":1,"device":{"uid":"y"}},"device":{"uid":"x"}}`,
	` { "metadata" : { "uid" : "a" , "sequence" : 1 } , "device" : { "uid" : "x" } } `,
	"{\t\"metadata\":{\"uid\":\"a\",\"sequence\":1},\"device\":{\"uid\":\"x\"}}",
	`{"":0,"":1}`,
	`{"":0,"\u0000":1,"\\":2,"\"":3}`,
	`{"a\\":1,"a\\\\":2,"a\"":3,"a\\\"":4}`,
	`{}`,
	`{"metadata":{}}`,
}

func TestWalkFieldsOracle(t *testing.T) {
	shared := newLineWalker(MaxLineBytes)
	checked := 0
	check := func(line []byte) {
		t.Helper()
		if !validLineJSON(line) {
			return
		}
		assertWalkOracle(t, shared, line)
		assertWalkOracle(t, newLineWalker(uint64(len(line))), line)
		checked++
	}
	f := loadFixtures(t)
	for _, c := range f.Cases {
		plain, err := c.plain(f.Template)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(plain, []byte{'\n'}) {
			check(line)
		}
	}
	fixtureLines := checked
	for _, shape := range walkShapes {
		for _, size := range []int{256, 4096, 65536, MaxLineBytes} {
			line := firstLine(shape.gen(1, size))
			if !validLineJSON(line) {
				t.Fatalf("%s/%d: generated line invalid", shape.name, size)
			}
			check(line)
		}
	}
	for _, plain := range [][]byte{genRealistic(3), genBadID(2), genMinOK(2), genFlat(2, 32770), genFlat(2, 5378)} {
		for _, line := range bytes.Split(bytes.TrimSuffix(plain, []byte{'\n'}), []byte{'\n'}) {
			check(line)
		}
	}
	check(dupEmptyLine())
	for _, line := range walkParityLines {
		if !validLineJSON([]byte(line)) {
			t.Fatalf("parity line invalid: %s", line)
		}
		check([]byte(line))
	}
	t.Logf("checked %d lines, %d from fixtures", checked, fixtureLines)
}
