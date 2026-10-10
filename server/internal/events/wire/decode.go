package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

// Decode validates the descriptor prefix and leaves the following body unread.
// The caller retains the reader and its remaining budget for full-body checks.
func Decode(values []string, body *io.LimitedReader) (batch.Descriptor, error) {
	header, err := ParseHeader(values)
	if err != nil {
		return batch.Descriptor{}, err
	}
	if body == nil || body.R == nil || body.N < 0 || body.N > MaxCompressedBytes+1 {
		return batch.Descriptor{}, ErrReaderBound
	}
	var framing [4]byte
	if _, err := io.ReadFull(body, framing[:]); err != nil {
		return batch.Descriptor{}, fmt.Errorf("%w: %w", ErrFrameRead, err)
	}
	if binary.LittleEndian.Uint32(framing[:]) != 0x184d2a50 {
		return batch.Descriptor{}, ErrFrameMagic
	}
	if _, err := io.ReadFull(body, framing[:]); err != nil {
		return batch.Descriptor{}, fmt.Errorf("%w: %w", ErrFrameRead, err)
	}
	if binary.LittleEndian.Uint32(framing[:]) != 40 {
		return batch.Descriptor{}, ErrFrameSize
	}
	var payload [40]byte
	if _, err := io.ReadFull(body, payload[:]); err != nil {
		return batch.Descriptor{}, fmt.Errorf("%w: %w", ErrFrameRead, err)
	}
	if payload[0] != 1 {
		return batch.Descriptor{}, ErrVersion
	}
	if payload[2] != 0 || payload[3] != 0 {
		return batch.Descriptor{}, ErrFrameReserved
	}
	frame := batch.Descriptor{
		Class:         batch.SpoolClass(payload[1]),
		StreamEpoch:   binary.LittleEndian.Uint64(payload[4:12]),
		SegmentID:     binary.LittleEndian.Uint64(payload[12:20]),
		FirstSequence: binary.LittleEndian.Uint64(payload[20:28]),
		LastSequence:  binary.LittleEndian.Uint64(payload[28:36]),
		RecordCount:   binary.LittleEndian.Uint32(payload[36:40]),
	}
	if err := frame.Validate(); err != nil {
		return batch.Descriptor{}, err
	}
	if frame != header {
		return batch.Descriptor{}, ErrDescriptorMismatch
	}
	return header, nil
}
