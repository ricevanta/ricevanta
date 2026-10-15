//go:build ricevanta_console

package console

import (
	"embed"
	"io/fs"
)

// The release recipe copies the console job's tree to dist/ and its
// manifest.json beside it, both gitignored, and builds with
// -tags ricevanta_console. all: keeps .vite/manifest.json.
//
//go:embed all:dist
var distFS embed.FS

//go:embed manifest.json
var manifestJSON []byte

// Embedded returns the embedded console tree rooted at dist and its
// manifest.json bytes.
func Embedded() (fs.FS, []byte, bool) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, nil, false
	}
	return sub, manifestJSON, true
}
