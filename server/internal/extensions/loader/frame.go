package loader

import (
	"encoding/binary"
	"io"

	"github.com/klauspost/compress/zstd"
)

const archiveOverhead uint64 = 8 << 20
const compressedOverhead uint64 = 1 << 20
const maxSnapshotInt = uint64(^uint(0) >> 1)

// readArchive retains a private snapshot. The caller has validated the ceiling.
func readArchive(body *io.LimitedReader, fileLimit uint64) ([]byte, []member, error) {
	// Bound both additions and the sentinel byte before int/int64 conversion.
	if fileLimit > maxSnapshotInt-archiveOverhead-compressedOverhead-1 {
		return nil, nil, ErrArchiveLimit
	}
	t := fileLimit + archiveOverhead
	c := t + compressedOverhead
	archive, err := readSnapshot(body, c)
	if err != nil {
		return nil, nil, err
	}
	size, err := frameSize(archive, t)
	if err != nil {
		return nil, nil, err
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(t), zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, nil, ErrCompression
	}
	defer decoder.Close()
	decoded, err := decoder.DecodeAll(archive, make([]byte, 0, int(size)))
	if err != nil || uint64(len(decoded)) != size {
		return nil, nil, ErrCompression
	}
	members, err := walkTar(decoded, fileLimit)
	if err != nil {
		return nil, nil, err
	}
	return archive, members, nil
}

func readSnapshot(body *io.LimitedReader, ceiling uint64) ([]byte, error) {
	if ceiling >= maxSnapshotInt {
		return nil, ErrArchiveLimit
	}
	limit := ceiling + 1
	var out []byte
	var chunk [32768]byte
	zeros := 0
	for {
		n, err := body.Read(chunk[:min(uint64(len(chunk)), limit-uint64(len(out)))])
		if n > 0 {
			zeros = 0
			length := len(out) + n
			if length > cap(out) {
				// cap(out) is at most MaxInt, so doubling cannot overflow uint64.
				capacity := min(limit, max(uint64(length), max(32768, uint64(cap(out))*2)))
				next := make([]byte, len(out), int(capacity))
				copy(next, out)
				out = next
			}
			out = append(out, chunk[:n]...)
			if uint64(len(out)) > ceiling {
				return nil, ErrCompressedLimit
			}
		} else if err == nil {
			zeros++
			if zeros == 100 {
				return nil, &readError{cause: io.ErrNoProgress}
			}
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, &readError{cause: err}
		}
	}
}

// frameSize walks exactly one RFC 8878 frame before any decoder allocation.
func frameSize(b []byte, ceiling uint64) (uint64, error) {
	if len(b) < 5 || binary.LittleEndian.Uint32(b) != 0xfd2fb528 {
		return 0, ErrCompression
	}
	d := b[4]
	if d&0x18 != 0 || d&3 != 0 || d&4 == 0 {
		return 0, ErrCompression
	}
	off := 5
	single := d&0x20 != 0
	var window uint64
	if !single {
		if off == len(b) {
			return 0, ErrCompression
		}
		w := b[off]
		off++
		base := uint64(1) << (10 + (w >> 3))
		window = base + base/8*uint64(w&7)
		if window > 8<<20 {
			return 0, ErrArchiveLimit
		}
	}
	width := []int{0, 2, 4, 8}[d>>6]
	if width == 0 {
		if !single {
			return 0, ErrCompression
		}
		width = 1
	}
	if width > len(b)-off {
		return 0, ErrCompression
	}
	var size uint64
	for i := 0; i < width; i++ {
		size |= uint64(b[off+i]) << uint(8*i)
	}
	if width == 2 {
		size += 256
	}
	off += width
	if size > ceiling || size > maxSnapshotInt {
		return 0, ErrArchiveLimit
	}
	if single {
		window = size
		if window > 8<<20 {
			return 0, ErrArchiveLimit
		}
	}
	for {
		if len(b)-off < 3 {
			return 0, ErrCompression
		}
		h := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16
		off += 3
		last := h&1 != 0
		typ := (h >> 1) & 3
		n := uint64(h >> 3)
		if typ == 3 || n > 128<<10 || n > window {
			return 0, ErrCompression
		}
		if typ == 1 {
			n = 1
		}
		if n > uint64(len(b)-off) {
			return 0, ErrCompression
		}
		off += int(n)
		if last {
			break
		}
	}
	if len(b)-off != 4 {
		return 0, ErrCompression
	}
	return size, nil
}
