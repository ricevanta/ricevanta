package body

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
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

// identityValue is a captured recognized value. For a string, token holds the
// escaped bytes between the quotes; for a number, the original number token.
// It aliases the line and is decoded only by text.
type identityValue struct {
	kind  valueKind
	token []byte
}

type valueKind uint8

const (
	valueAbsent valueKind = iota
	valueString
	valueNumber
	valueOther // null, booleans and containers
)

// text returns the decoded string or the number token.
func (v identityValue) text() string {
	if v.kind == valueString && bytes.IndexByte(v.token, '\\') >= 0 {
		return string(appendUnescaped(make([]byte, 0, len(v.token)), v.token))
	}
	return string(v.token)
}

type identityFields struct {
	metadata, device         bool
	uid, sequence, deviceUID identityValue
}

// extractLine checks one line with walker state sized for that line alone.
// Decode sizes one walker per call instead (see consume).
func extractLine(raw []byte, number uint32, d batch.Descriptor, authenticatedDevice string) Line {
	return newLineWalker(uint64(len(raw))).extract(raw, number, d, authenticatedDevice)
}

func (w *lineWalker) extract(raw []byte, number uint32, d batch.Descriptor, authenticatedDevice string) Line {
	line := Line{Number: number, Raw: raw}
	if !validLineJSON(raw) {
		line.Err = ErrJSON
		return line
	}
	fields, ok := w.walkFields(raw)
	if !ok {
		line.Err = ErrJSONKeys
		return line
	}
	deviceOK := fields.deviceUID.kind == valueString
	var device string
	if deviceOK {
		device = fields.deviceUID.text()
	}
	line.DeviceMismatch = fields.device && deviceOK && device != authenticatedDevice
	if !fields.metadata || !fields.device || fields.uid.kind != valueString || !deviceOK || fields.sequence.kind != valueNumber {
		line.Err = ErrFields
		return line
	}
	text := fields.sequence.token
	if len(text) == 0 || len(text) > 1 && text[0] == '0' {
		line.Err = ErrFields
		return line
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			line.Err = ErrFields
			return line
		}
	}
	sequence, err := strconv.ParseUint(string(text), 10, 64)
	if err != nil {
		line.Err = ErrFields
		return line
	}
	id, err := eventid.Parse(fields.uid.text())
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

// walkEntry records one member: its object number and the decoded name's
// offset and length in the arena. It occupies 12 bytes.
type walkEntry struct {
	object, start, length uint32
}

type walkFrame struct {
	object, keyNext bool
	scope           uint8
	id              uint32
	keyStart        uint32
	keyLength       uint32
}

// lineWalker holds the key-walk state of one Decode call. With
// L = min(declared content size, MaxLineBytes), the arena holds L bytes and the
// entry slice L/5+1 entries, because the shortest member "":0, takes 5 bytes;
// the stack holds MaxJSONDepth containers. A line no longer than L never grows
// any of them. The state is never pooled across calls.
type lineWalker struct {
	limit   int
	stack   []walkFrame
	arena   []byte
	entries []walkEntry
}

func newLineWalker(size uint64) *lineWalker {
	return walkerOfLimit(int(min(size, MaxLineBytes)))
}

func walkerOfLimit(l int) *lineWalker {
	return &lineWalker{limit: l, stack: make([]walkFrame, 0, MaxJSONDepth), arena: make([]byte, 0, l), entries: make([]walkEntry, 0, l/5+1)}
}

// Recognized names per scope: 1 root, 2 metadata, 3 device.
var (
	nameMetadata    = []byte("metadata")
	nameDevice      = []byte("device")
	nameUID         = []byte("uid")
	nameSequence    = []byte("sequence")
	recognizedNames = [4][][]byte{nil, {nameMetadata, nameDevice}, {nameUID, nameSequence}, {nameUID}}
)

// walkFields scans a line that validLineJSON accepted. It records every member
// name of every object, rejects case-fold collisions with the recognized names
// of the current scope, captures the three identity values, and at the end
// sorts the names by object number, then bytes, and compares neighbours. It
// uses no hash and no encoding/json tokens.
func (w *lineWalker) walkFields(raw []byte) (identityFields, bool) {
	var fields identityFields
	if len(raw) > w.limit {
		// Unreachable from consume, which extracts only lines within the
		// declared content size; kept so the state never grows.
		return walkerOfLimit(len(raw)).walkFields(raw)
	}
	w.stack, w.arena, w.entries = w.stack[:0], w.arena[:0], w.entries[:0]
	var objects uint32
	for i := 0; i < len(raw); {
		c := raw[i]
		switch c {
		case ' ', '\t', '\n', '\r', ',', ':':
			i++
			continue
		case '}', ']':
			w.stack = w.stack[:len(w.stack)-1]
			i++
			continue
		}
		top := len(w.stack) - 1
		if top >= 0 && w.stack[top].keyNext {
			end := skipString(raw, i)
			start := len(w.arena)
			w.arena = appendUnescaped(w.arena, raw[i+1:end-1])
			name := w.arena[start:]
			parent := &w.stack[top]
			w.entries = append(w.entries, walkEntry{object: parent.id, start: uint32(start), length: uint32(len(name))})
			for _, recognized := range recognizedNames[parent.scope] {
				if !bytes.Equal(name, recognized) && bytes.EqualFold(name, recognized) {
					return fields, false
				}
			}
			parent.keyStart, parent.keyLength, parent.keyNext = uint32(start), uint32(len(name)), false
			i = end
			continue
		}
		var scope uint8
		var key []byte
		if top >= 0 && w.stack[top].object {
			parent := &w.stack[top]
			scope, key = parent.scope, w.arena[parent.keyStart:parent.keyStart+parent.keyLength]
			parent.keyNext = true
		}
		target := fields.target(scope, key)
		switch c {
		case '{', '[':
			child := uint8(0)
			if top < 0 {
				child = 1
			} else if scope == 1 && c == '{' {
				if bytes.Equal(key, nameMetadata) {
					fields.metadata, child = true, 2
				} else if bytes.Equal(key, nameDevice) {
					fields.device, child = true, 3
				}
			}
			if target != nil {
				*target = identityValue{kind: valueOther}
			}
			frame := walkFrame{object: c == '{', keyNext: c == '{', scope: child}
			if c == '{' {
				objects++
				frame.id = objects
			}
			w.stack = append(w.stack, frame)
			i++
		case '"':
			end := skipString(raw, i)
			if target != nil {
				*target = identityValue{kind: valueString, token: raw[i+1 : end-1]}
			}
			i = end
		default:
			end := skipLiteral(raw, i)
			if target != nil {
				kind := valueNumber
				if c == 't' || c == 'f' || c == 'n' {
					kind = valueOther
				}
				*target = identityValue{kind: kind, token: raw[i:end]}
				if kind == valueOther {
					target.token = nil
				}
			}
			i = end
		}
	}
	return fields, w.unique()
}

// target returns the identity value a member value in scope under key fills.
func (f *identityFields) target(scope uint8, key []byte) *identityValue {
	switch {
	case scope == 2 && bytes.Equal(key, nameUID):
		return &f.uid
	case scope == 2 && bytes.Equal(key, nameSequence):
		return &f.sequence
	case scope == 3 && bytes.Equal(key, nameUID):
		return &f.deviceUID
	}
	return nil
}

// unique sorts the entries by object number, then decoded name bytes, and
// reports whether no two neighbours are equal. slices.SortFunc is
// pattern-defeating quicksort with a heapsort fallback, O(n log n) comparisons
// for every input.
func (w *lineWalker) unique() bool {
	arena := w.arena
	slices.SortFunc(w.entries, func(a, b walkEntry) int {
		if a.object != b.object {
			return cmp.Compare(a.object, b.object)
		}
		return bytes.Compare(arena[a.start:a.start+a.length], arena[b.start:b.start+b.length])
	})
	for i := 1; i < len(w.entries); i++ {
		a, b := w.entries[i-1], w.entries[i]
		if a.object == b.object && bytes.Equal(arena[a.start:a.start+a.length], arena[b.start:b.start+b.length]) {
			return false
		}
	}
	return true
}

// skipString returns the index after the string that starts with the quote at
// raw[i]. Each byte is examined a bounded number of times.
func skipString(raw []byte, i int) int {
	j := i + 1
	for {
		q := j + bytes.IndexByte(raw[j:], '"')
		for {
			b := bytes.IndexByte(raw[j:q], '\\')
			if b < 0 {
				return q + 1
			}
			j += b + 2
			if j > q {
				break // the escape consumed the quote at q
			}
		}
	}
}

func skipLiteral(raw []byte, i int) int {
	for i < len(raw) {
		switch raw[i] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return i
		}
		i++
	}
	return i
}

// appendUnescaped appends the decoded form of the escaped string body s. The
// line has passed validLineJSON, so every escape is complete and every high
// surrogate escape is followed by a low one. The result is never longer than s.
func appendUnescaped(dst, s []byte) []byte {
	for {
		b := bytes.IndexByte(s, '\\')
		if b < 0 {
			return append(dst, s...)
		}
		dst = append(dst, s[:b]...)
		s = s[b+1:]
		switch s[0] {
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case 't':
			dst = append(dst, '\t')
		case 'u':
			r := rune(hexEscape(s[1:5]))
			s = s[4:]
			if r >= 0xd800 && r <= 0xdbff {
				r = 0x10000 + (r-0xd800)<<10 + (rune(hexEscape(s[3:7])) - 0xdc00)
				s = s[6:]
			}
			dst = utf8.AppendRune(dst, r)
		default: // '"', '\\', '/'
			dst = append(dst, s[0])
		}
		s = s[1:]
	}
}
