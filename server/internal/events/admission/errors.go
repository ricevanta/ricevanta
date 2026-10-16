package admission

import "errors"

var (
	ErrConfig   = errors.New("ingest admission config")
	ErrArgument = errors.New("ingest admission argument")
	ErrDevice   = errors.New("ingest admission device")
	ErrState    = errors.New("ingest admission state")
)
