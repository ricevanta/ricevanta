package body

import "errors"

var (
	ErrReaderBound         = errors.New("event body reader bound")
	ErrDevice              = errors.New("event body device")
	ErrRead                = errors.New("event body read")
	ErrCompressedLimit     = errors.New("event body compressed limit")
	ErrFrame               = errors.New("event body frame")
	ErrChecksumRequired    = errors.New("event body checksum required")
	ErrContentSizeRequired = errors.New("event body content size required")
	ErrDecodedLimit        = errors.New("event body decoded limit")
	ErrWindowLimit         = errors.New("event body window limit")
	ErrTrailingData        = errors.New("event body trailing data")
	ErrContentSize         = errors.New("event body content size")
	ErrChecksum            = errors.New("event body checksum")
	ErrLineLimit           = errors.New("event body line limit")
	ErrLineCountLimit      = errors.New("event body line count limit")
	ErrLineFraming         = errors.New("event body line framing")
	ErrRecordCount         = errors.New("event body record count")
)

var (
	ErrJSON             = errors.New("event body JSON")
	ErrJSONKeys         = errors.New("event body JSON keys")
	ErrFields           = errors.New("event body fields")
	ErrEventID          = errors.New("event body event id")
	ErrSequenceRange    = errors.New("event body sequence range")
	ErrSequencePosition = errors.New("event body sequence position")
	ErrDeviceBinding    = errors.New("event body device binding")
)
