// Package manifest validates immutable decoded extension declarations.
package manifest

import (
	"errors"
	"fmt"
)

type Options struct {
	AllowReservedID   bool
	MaxTotalFileBytes uint64
}

const (
	MaxManifestBytes                = 1 << 20
	MaxTreeDepth                    = 16
	MaxTreeNodes                    = 65536
	DefaultMaxTotalFileBytes uint64 = 64 << 20
	HardMaxTotalFileBytes    uint64 = 1 << 30
)

var (
	ErrOptions    = errors.New("manifest options")
	ErrTree       = errors.New("manifest decoded tree")
	ErrShape      = errors.New("manifest shape")
	ErrField      = errors.New("manifest field")
	ErrReserved   = errors.New("manifest reserved id")
	ErrDuplicate  = errors.New("manifest duplicate")
	ErrPath       = errors.New("manifest path")
	ErrLimit      = errors.New("manifest file total")
	ErrRequires   = errors.New("manifest interface requirements")
	ErrReference  = errors.New("manifest file reference")
	ErrCapability = errors.New("manifest capability relation")
	ErrLicense    = errors.New("manifest license expression")
	ErrURL        = errors.New("manifest URL")
)

// Validate checks structure only. Callers supply namespace authority separately.
func Validate(document any, options Options) error {
	if options.MaxTotalFileBytes > HardMaxTotalFileBytes {
		return fmt.Errorf("%w: ceiling", ErrOptions)
	}
	b := treeBudget{}
	if !b.visit(document, 0) {
		return fmt.Errorf("%w: preflight", ErrTree)
	}
	if !shape(document, rootRule) {
		return fmt.Errorf("%w: declaration", ErrShape)
	}
	if !fields(document, rootRule) {
		return fmt.Errorf("%w: declaration", ErrField)
	}
	if err := relations(document.(map[string]any), options); err != nil {
		return fmt.Errorf("%w: declaration", err)
	}
	if err := metadata(document.(map[string]any)); err != nil {
		return fmt.Errorf("%w: declaration", err)
	}
	return nil
}
