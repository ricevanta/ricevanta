package catalogue

import (
	_ "embed"
	"sync"
)

//go:embed catalogue.json
var embeddedCatalogue string

var builtin builtinLoader

type builtinLoader struct {
	once      sync.Once
	catalogue *Catalogue
	err       error
}

func (b *builtinLoader) load(data string) (*Catalogue, error) {
	b.once.Do(func() { b.catalogue, b.err = Parse([]byte(data)) })
	return b.catalogue, b.err
}

// Builtin returns the immutable embedded catalogue and its cached parse error.
func Builtin() (*Catalogue, error) { return builtin.load(embeddedCatalogue) }
