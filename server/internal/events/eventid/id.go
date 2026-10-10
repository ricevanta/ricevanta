// Package eventid validates and formats UUIDv7 event identifiers.
package eventid

import "errors"

var (
	ErrFormat       = errors.New("event id format")
	ErrNonCanonical = errors.New("event id is not lowercase canonical text")
	ErrVersion      = errors.New("event id is not UUIDv7")
	ErrVariant      = errors.New("event id has an unsupported UUID variant")
)

// ID is the 16-byte representation of an event identifier.
type ID [16]byte

// Parse validates and decodes a lowercase canonical UUIDv7 string.
func Parse(text string) (ID, error) {
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return ID{}, ErrFormat
	}

	for i := range len(text) {
		if text[i] >= 'A' && text[i] <= 'F' {
			return ID{}, ErrNonCanonical
		}
	}
	for i := range len(text) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if _, ok := hexValue(text[i]); !ok {
			return ID{}, ErrFormat
		}
	}

	var id ID
	byteIndex := 0
	for i := 0; i < len(text); {
		if text[i] == '-' {
			i++
			continue
		}

		high, ok := hexValue(text[i])
		if !ok {
			return ID{}, ErrFormat
		}
		low, ok := hexValue(text[i+1])
		if !ok {
			return ID{}, ErrFormat
		}
		id[byteIndex] = high<<4 | low
		byteIndex++
		i += 2
	}

	if id[6]>>4 != 7 {
		return ID{}, ErrVersion
	}
	if id[8]&0xc0 != 0x80 {
		return ID{}, ErrVariant
	}

	return id, nil
}

// String formats all 16 bytes of id as a lowercase canonical UUID string.
func (id ID) String() string {
	const digits = "0123456789abcdef"

	var text [36]byte
	text[8] = '-'
	text[13] = '-'
	text[18] = '-'
	text[23] = '-'

	textIndex := 0
	for _, value := range id {
		if text[textIndex] == '-' {
			textIndex++
		}
		text[textIndex] = digits[value>>4]
		text[textIndex+1] = digits[value&0x0f]
		textIndex += 2
	}

	return string(text[:])
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}
