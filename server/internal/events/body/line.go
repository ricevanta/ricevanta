package body

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
	"github.com/ricevanta/ricevanta/server/internal/events/eventid"
)

// Line owns a raw payload and preliminary identity checks, not an ingest result.
type Line struct {
	Number         uint32
	Raw            []byte
	EventID        eventid.ID
	Sequence       uint64
	DeviceUID      string
	Err            error
	DeviceMismatch bool
}

type objectState struct {
	object  bool
	keyNext bool
	key     string
	scope   uint8
	names   map[string]struct{}
}
type identityFields struct {
	metadata, device         bool
	uid, sequence, deviceUID any
}

func extractLine(raw []byte, number uint32, d batch.Descriptor, authenticatedDevice string) Line {
	line := Line{Number: number, Raw: raw}
	if !validLineJSON(raw) {
		line.Err = ErrJSON
		return line
	}
	fields, ok := walkFields(raw)
	if !ok {
		line.Err = ErrJSONKeys
		return line
	}
	device, deviceOK := fields.deviceUID.(string)
	line.DeviceMismatch = fields.device && deviceOK && device != authenticatedDevice
	uid, uidOK := fields.uid.(string)
	token, numberOK := fields.sequence.(json.Number)
	if !fields.metadata || !fields.device || !uidOK || !deviceOK || !numberOK {
		line.Err = ErrFields
		return line
	}
	text := string(token)
	if len(text) == 0 || len(text) > 1 && text[0] == '0' {
		line.Err = ErrFields
		return line
	}
	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			line.Err = ErrFields
			return line
		}
	}
	sequence, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		line.Err = ErrFields
		return line
	}
	id, err := eventid.Parse(uid)
	if err != nil {
		line.Err = fmt.Errorf("%w: %w", ErrEventID, err)
		return line
	}
	if sequence < d.FirstSequence || sequence > d.LastSequence {
		line.Err = ErrSequenceRange
		return line
	}
	if number == 0 || number > d.RecordCount || sequence != d.FirstSequence+uint64(number-1) {
		line.Err = ErrSequencePosition
		return line
	}
	if line.DeviceMismatch {
		line.Err = ErrDeviceBinding
		return line
	}
	line.EventID = id
	line.Sequence = sequence
	line.DeviceUID = device
	return line
}

func validLineJSON(raw []byte) bool {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return false
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	depth := 0
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			if c == '"' {
				inString = false
				continue
			}
			if c != '\\' {
				continue
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			value := hexEscape(raw[i+1 : i+5])
			i += 4
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value >= 0xd800 && value <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low := hexEscape(raw[i+3 : i+7])
				if low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > MaxJSONDepth {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}
func hexEscape(b []byte) uint16 {
	var value uint16
	for _, c := range b {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value += uint16(c - 'a' + 10)
		default:
			value += uint16(c - 'A' + 10)
		}
	}
	return value
}

// walkFields retains only active object keys and the three identity tokens.
func walkFields(raw []byte) (identityFields, bool) {
	var fields identityFields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	stack := make([]objectState, 0, MaxJSONDepth)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fields, false
		}
		delimiter, isDelimiter := token.(json.Delim)
		if isDelimiter && (delimiter == '}' || delimiter == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		var scope uint8
		var key string
		if len(stack) > 0 {
			parent := &stack[len(stack)-1]
			if parent.object && parent.keyNext {
				name := token.(string)
				if _, exists := parent.names[name]; exists {
					return fields, false
				}
				parent.names[name] = struct{}{}
				recognized := []string(nil)
				switch parent.scope {
				case 1:
					recognized = []string{"metadata", "device"}
				case 2:
					recognized = []string{"uid", "sequence"}
				case 3:
					recognized = []string{"uid"}
				}
				for _, canonical := range recognized {
					if name != canonical && strings.EqualFold(name, canonical) {
						return fields, false
					}
				}
				parent.key = name
				parent.keyNext = false
				continue
			}
			scope = parent.scope
			key = parent.key
			parent.keyNext = parent.object
			if parent.object {
				switch scope {
				case 2:
					switch key {
					case "uid":
						fields.uid = token
					case "sequence":
						fields.sequence = token
					}
				case 3:
					if key == "uid" {
						fields.deviceUID = token
					}
				}
			}
			if !parent.object {
				scope = 0
				key = ""
			}
		}
		if isDelimiter {
			childScope := uint8(0)
			if len(stack) == 0 {
				childScope = 1
			} else if scope == 1 && delimiter == '{' {
				switch key {
				case "metadata":
					fields.metadata = true
					childScope = 2
				case "device":
					fields.device = true
					childScope = 3
				}
			}
			child := objectState{object: delimiter == '{', keyNext: delimiter == '{', scope: childScope}
			if child.object {
				child.names = make(map[string]struct{})
			}
			stack = append(stack, child)
		}
	}
	return fields, true
}
