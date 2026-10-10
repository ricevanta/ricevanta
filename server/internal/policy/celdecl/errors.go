package celdecl

import "errors"

var (
	ErrRead         = errors.New("cel declarations read")
	ErrSize         = errors.New("cel declarations size")
	ErrJSON         = errors.New("cel declarations json")
	ErrDuplicateKey = errors.New("cel declarations duplicate key")
	ErrShape        = errors.New("cel declarations shape")
	ErrVersion      = errors.New("cel declarations version")
	ErrProfile      = errors.New("cel declarations profile")
	ErrOCSF         = errors.New("cel declarations ocsf version")
	ErrName         = errors.New("cel declarations name")
	ErrType         = errors.New("cel declarations type")
	ErrLimit        = errors.New("cel declarations limit")
	ErrDomain       = errors.New("cel declarations domain")
	ErrReference    = errors.New("cel declarations reference")
	ErrCycle        = errors.New("cel declarations cycle")
	ErrCatalogue    = errors.New("cel declarations catalogue")
	ErrDocument     = errors.New("cel declarations document")
)
