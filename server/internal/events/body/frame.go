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

func inspectFrame(b []byte) (uint64, error) {
	if len(b) < 5 || binary.LittleEndian.Uint32(b[:4]) != 0xfd2fb528 {
		return 0, ErrFrame
	}
	flags := b[4]
	single := flags&32 != 0
	pos := 5
	var window uint64
	if !single {
		if pos == len(b) {
			return 0, ErrFrame
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
		return 0, ErrFrame
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
		return 0, ErrFrame
	}
	if flags&4 == 0 {
		return 0, ErrChecksumRequired
	}
	if width == 0 {
		return 0, ErrContentSizeRequired
	}
	if size > uint64(MaxDecodedBytes) {
		return 0, ErrDecodedLimit
	}
	if single {
		window = size
	}
	if window > MaxWindowBytes {
		return 0, ErrWindowLimit
	}
	for {
		if len(b)-pos < 3 {
			return 0, ErrFrame
		}
		h := uint32(b[pos]) | uint32(b[pos+1])<<8 | uint32(b[pos+2])<<16
		pos += 3
		kind := (h >> 1) & 3
		block := uint64(h >> 3)
		if kind == 3 || block > min(window, uint64(128<<10)) {
			return 0, ErrFrame
		}
		stored := block
		if kind == 1 {
			stored = 1
		}
		if stored > uint64(len(b)-pos) {
			return 0, ErrFrame
		}
		pos += int(stored)
		if h&1 != 0 {
			break
		}
	}
	if len(b)-pos < 4 {
		return 0, ErrFrame
	}
	pos += 4
	if pos != len(b) {
		return 0, ErrTrailingData
	}
	return size, nil
}
