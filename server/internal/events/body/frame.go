// Package body decodes bounded event batch bodies into provisional raw lines.
package body

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ricevanta/ricevanta/server/internal/events/wire"
)

const (
	MaxDecodedBytes  int64  = 64 << 20
	MaxWindowBytes   uint64 = 64 << 20
	MaxLineBytes            = 1 << 20
	MaxLines                = 10000
	MaxJSONDepth            = 128
	compressedBudget        = wire.MaxCompressedBytes + 1 - wire.DescriptorFrameBytes
)

// Frame is one preflighted compressed frame. Its fields are unexported, so code
// outside this package can construct only the zero Frame, which DecodeFrame
// rejects with ErrReaderBound.
type Frame struct {
	data   []byte
	size   uint64
	window uint64
}

// ContentSize returns the declared Frame_Content_Size.
func (f Frame) ContentSize() uint64 { return f.size }

// Window returns the effective window: the content size for a single-segment
// frame, else the Window_Descriptor value.
func (f Frame) Window() uint64 { return f.window }

// ReadFrame checks the reader precondition, then reads the remaining compressed
// body and preflights its single frame, so a caller can charge the request
// before decompression. It consumes the same bytes as Decode.
func ReadFrame(r *io.LimitedReader) (Frame, error) {
	if !canonicalReader(r) {
		return Frame{}, ErrReaderBound
	}
	data, err := readCompressed(r)
	if err != nil {
		return Frame{}, err
	}
	size, window, err := inspectFrame(data)
	if err != nil {
		return Frame{}, err
	}
	return Frame{data: data, size: size, window: window}, nil
}

func canonicalReader(r *io.LimitedReader) bool {
	return r != nil && r.R != nil && r.N == compressedBudget
}

func readCompressed(r *io.LimitedReader) ([]byte, error) {
	b := make([]byte, compressedBudget)
	used, empty := 0, 0
	for {
		n, err := r.Read(b[used:min(used+32768, len(b))])
		used += n
		if used == len(b) {
			return nil, ErrCompressedLimit
		}
		if n > 0 {
			empty = 0
		} else if err == nil {
			empty++
			if empty == 100 {
				return nil, fmt.Errorf("%w: %w", ErrRead, io.ErrNoProgress)
			}
		}
		if err == io.EOF {
			return b[:used], nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRead, err)
		}
	}
}

// inspectFrame returns the declared content size and the effective window.
func inspectFrame(b []byte) (uint64, uint64, error) {
	return inspectFrameCount(b, nil)
}

// inspectFrameCount exposes header visits to package qualification tests.
func inspectFrameCount(b []byte, visits *uint64) (uint64, uint64, error) {
	if len(b) < 5 || binary.LittleEndian.Uint32(b[:4]) != 0xfd2fb528 {
		return 0, 0, ErrFrame
	}
	flags := b[4]
	single := flags&32 != 0
	pos := 5
	var window uint64
	if !single {
		if pos == len(b) {
			return 0, 0, ErrFrame
		}
		wd := b[pos]
		pos++
		base := uint64(1) << (10 + (wd >> 3))
		window = base + base/8*uint64(wd&7)
	}
	dictionaryWidth := []int{0, 1, 2, 4}[flags&3]
	width := []int{0, 2, 4, 8}[flags>>6]
	if flags>>6 == 0 && single {
		width = 1
	}
	if dictionaryWidth+width > len(b)-pos {
		return 0, 0, ErrFrame
	}
	pos += dictionaryWidth
	var size uint64
	for i := 0; i < width; i++ {
		size |= uint64(b[pos+i]) << (8 * i)
	}
	pos += width
	if width == 2 {
		size += 256
	}
	if flags&0x18 != 0 || flags&3 != 0 {
		return 0, 0, ErrFrame
	}
	if flags&4 == 0 {
		return 0, 0, ErrChecksumRequired
	}
	if width == 0 {
		return 0, 0, ErrContentSizeRequired
	}
	if size > uint64(MaxDecodedBytes) {
		return 0, 0, ErrDecodedLimit
	}
	if single {
		window = size
	}
	if window > MaxWindowBytes {
		return 0, 0, ErrWindowLimit
	}
	blockLimit := 1 + (max(size, uint64(128<<10))+(128<<10)-1)/(128<<10)
	for blocks := uint64(1); ; blocks++ {
		if len(b)-pos < 3 {
			return 0, 0, ErrFrame
		}
		if visits != nil {
			*visits = blocks
		}
		if blocks > blockLimit {
			return 0, 0, ErrFrame
		}
		h := uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16
		pos += 3
		kind := (h >> 1) & 3
		block := uint64(h >> 3)
		if kind == 3 || block > min(window, uint64(128<<10)) {
			return 0, 0, ErrFrame
		}
		stored := block
		if kind == 1 {
			stored = 1
		}
		if stored > uint64(len(b)-pos) {
			return 0, 0, ErrFrame
		}
		pos += int(stored)
		if h&1 != 0 {
			break
		}
	}
	if len(b)-pos < 4 {
		return 0, 0, ErrFrame
	}
	pos += 4
	if pos != len(b) {
		return 0, 0, ErrTrailingData
	}
	return size, window, nil
}
