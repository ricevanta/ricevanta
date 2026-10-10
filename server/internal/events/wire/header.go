// Package wire validates event upload headers and descriptor prefixes.
package wire

import (
	"strconv"
	"strings"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

const (
	MaxHeaderBytes             = 139
	DescriptorFrameBytes       = 48
	MaxCompressedBytes   int64 = 5_000_000
)

// ParseHeader validates every supplied value without trimming or normalization.
func ParseHeader(values []string) (batch.Descriptor, error) {
	if len(values) != 1 {
		return batch.Descriptor{}, ErrHeaderCount
	}
	if len(values[0]) > MaxHeaderBytes {
		return batch.Descriptor{}, ErrHeaderSize
	}
	parts := strings.Split(values[0], ";")
	keys := [...]string{"v=", "class=", "epoch=", "segment=", "first=", "last=", "count="}
	if len(parts) != len(keys) {
		return batch.Descriptor{}, ErrHeaderSyntax
	}
	var numbers [7]uint64
	for i, key := range keys {
		if !strings.HasPrefix(parts[i], key) {
			return batch.Descriptor{}, ErrHeaderSyntax
		}
		token := parts[i][len(key):]
		if token == "" {
			return batch.Descriptor{}, ErrHeaderSyntax
		}
		if i == 1 {
			for j := range len(token) {
				if token[j] < 'a' || token[j] > 'z' {
					return batch.Descriptor{}, ErrHeaderSyntax
				}
			}
			continue
		}
		if len(token) > 1 && token[0] == '0' {
			return batch.Descriptor{}, ErrHeaderSyntax
		}
		for j := range len(token) {
			if token[j] < '0' || token[j] > '9' {
				return batch.Descriptor{}, ErrHeaderSyntax
			}
		}
		bits := 64
		if i == 0 {
			bits = 8
		} else if i == 6 {
			bits = 32
		}
		number, err := strconv.ParseUint(token, 10, bits)
		if err != nil {
			return batch.Descriptor{}, ErrHeaderSyntax
		}
		numbers[i] = number
	}
	if numbers[0] != 1 {
		return batch.Descriptor{}, ErrVersion
	}
	var class batch.SpoolClass
	for c := batch.ClassRaw; c <= batch.ClassAudit; c++ {
		if c.String() == parts[1][len(keys[1]):] {
			class = c
			break
		}
	}
	d := batch.Descriptor{Class: class, StreamEpoch: numbers[2], SegmentID: numbers[3], FirstSequence: numbers[4], LastSequence: numbers[5], RecordCount: uint32(numbers[6])}
	if err := d.Validate(); err != nil {
		return batch.Descriptor{}, err
	}
	return d, nil
}
