package loader

import "errors"

var (
	ErrOptions         = errors.New("extension loader options")
	ErrReader          = errors.New("extension loader reader")
	ErrKey             = errors.New("extension loader key length")
	ErrCompressedLimit = errors.New("extension compressed limit")
	ErrRead            = errors.New("extension read")
	ErrCompression     = errors.New("extension compression")
	ErrArchiveLimit    = errors.New("extension archive limit")
	ErrArchive         = errors.New("extension archive format")
	ErrMember          = errors.New("extension archive member")
	ErrMemberDuplicate = errors.New("extension duplicate member")
	ErrControls        = errors.New("extension control members")
	ErrPayloadLimit    = errors.New("extension payload limit")
	ErrPayloadMismatch = errors.New("extension payload mismatch")
	ErrYAML            = errors.New("extension YAML profile")
	ErrYAMLLimit       = errors.New("extension YAML limit")
	ErrExplicitTag     = errors.New("extension YAML explicit tag")
	ErrDuplicateKey    = errors.New("extension YAML duplicate key")
	ErrPublisher       = errors.New("extension publisher binding")
	ErrFileSet         = errors.New("extension file set")
	ErrFileSize        = errors.New("extension file size")
	ErrFileDigest      = errors.New("extension file digest")
)
