package body

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

type streamDecoder interface {
	io.Reader
	Close()
}
type decoderFactory func(io.Reader, ...zstd.DOption) (streamDecoder, error)

// Decode consumes the canonical reader left by wire.Decode. Every batch failure
// discards all provisional lines. The caller retains ownership of r.R.
func Decode(r *io.LimitedReader, d batch.Descriptor, authenticatedDevice string) ([]Line, error) {
	return decodeWithFactory(r, d, authenticatedDevice, func(r io.Reader, options ...zstd.DOption) (streamDecoder, error) {
		return zstd.NewReader(r, options...)
	})
}

func decodeWithFactory(r *io.LimitedReader, d batch.Descriptor, authenticatedDevice string, factory decoderFactory) ([]Line, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if r == nil || r.R == nil || r.N != compressedBudget {
		return nil, ErrReaderBound
	}
	if authenticatedDevice == "" || !utf8.ValidString(authenticatedDevice) {
		return nil, ErrDevice
	}
	frame, err := readCompressed(r)
	if err != nil {
		return nil, err
	}
	size, err := inspectFrame(frame)
	if err != nil {
		return nil, err
	}
	decoder, err := factory(bytes.NewReader(frame), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(MaxDecodedBytes)), zstd.WithDecoderMaxWindow(MaxWindowBytes), zstd.WithDecoderLowmem(true), zstd.WithDecodeBuffersBelow(0), zstd.IgnoreChecksum(false))
	if err != nil {
		return nil, codecError(err)
	}
	defer decoder.Close()
	return consume(codecReader{decoder}, size, d, authenticatedDevice)
}

type codecReader struct{ io.Reader }

func (r codecReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		err = codecError(err)
	}
	return n, err
}
func codecError(err error) error {
	switch {
	case errors.Is(err, zstd.ErrFrameSizeMismatch), errors.Is(err, zstd.ErrFrameSizeExceeded):
		return ErrContentSize
	case errors.Is(err, zstd.ErrCRCMismatch):
		return ErrChecksum
	case errors.Is(err, zstd.ErrWindowSizeExceeded), errors.Is(err, zstd.ErrDecoderSizeExceeded):
		return ErrWindowLimit
	default:
		return ErrFrame
	}
}

func consume(decoded io.Reader, size uint64, d batch.Descriptor, authenticatedDevice string) ([]Line, error) {
	var output [32768]byte
	scratch := make([]byte, 0, MaxLineBytes)
	lines := make([]Line, 0, d.RecordCount)
	var total int64
	count, length := 0, 0
	nonblank := false
	var framing error
	for {
		request := min(int64(len(output)), MaxDecodedBytes-total+1)
		n, err := decoded.Read(output[:int(request)])
		for _, value := range output[:n] {
			total++
			if total > MaxDecodedBytes {
				return nil, ErrDecodedLimit
			}
			if count == MaxLines {
				return nil, ErrLineCountLimit
			}
			if value != '\n' {
				length++
				if length > MaxLineBytes {
					return nil, ErrLineLimit
				}
				if value != ' ' && value != '\t' {
					nonblank = true
				}
				if value == '\r' {
					framing = ErrLineFraming
					lines = nil
				}
				if framing == nil {
					scratch = append(scratch, value)
					if len(scratch) == 3 && bytes.Equal(scratch, []byte{0xef, 0xbb, 0xbf}) {
						framing = ErrLineFraming
						lines = nil
					}
				}
				continue
			}
			count++
			if length == 0 || !nonblank {
				framing = ErrLineFraming
				lines = nil
			}
			if framing == nil && uint32(count) <= d.RecordCount {
				raw := bytes.Clone(scratch)
				lines = append(lines, extractLine(raw, uint32(count), d, authenticatedDevice))
			}
			scratch = scratch[:0]
			length = 0
			nonblank = false
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			if uint64(total) != size {
				return nil, ErrContentSize
			}
			if framing != nil || length != 0 {
				return nil, ErrLineFraming
			}
			if uint32(count) != d.RecordCount {
				return nil, ErrRecordCount
			}
			return lines, nil
		}
	}
}
