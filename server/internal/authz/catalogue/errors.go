package catalogue

import "errors"

var (
	ErrLimit             = errors.New("permission catalogue limit")
	ErrJSON              = errors.New("permission catalogue JSON")
	ErrShape             = errors.New("permission catalogue shape")
	ErrVersion           = errors.New("permission catalogue version")
	ErrNameFormat        = errors.New("permission name format")
	ErrEntry             = errors.New("permission catalogue entry")
	ErrDuplicate         = errors.New("permission catalogue duplicate name")
	ErrOrder             = errors.New("permission catalogue order")
	ErrRevision          = errors.New("permission catalogue revision")
	ErrUnavailable       = errors.New("permission catalogue unavailable")
	ErrUnknownPermission = errors.New("unknown permission")
	ErrRetiredPermission = errors.New("retired permission")
)
