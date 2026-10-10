package wire

import "errors"

var (
	ErrHeaderCount        = errors.New("event batch header count")
	ErrHeaderSize         = errors.New("event batch header size")
	ErrHeaderSyntax       = errors.New("event batch header syntax")
	ErrVersion            = errors.New("event batch wire version")
	ErrReaderBound        = errors.New("event batch reader bound")
	ErrFrameRead          = errors.New("event batch frame read")
	ErrFrameMagic         = errors.New("event batch frame magic")
	ErrFrameSize          = errors.New("event batch frame size")
	ErrFrameReserved      = errors.New("event batch frame reserved bytes")
	ErrDescriptorMismatch = errors.New("event batch descriptor mismatch")
)
