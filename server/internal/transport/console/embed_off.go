//go:build !ricevanta_console

package console

import "io/fs"

// Embedded reports that this build embeds no console; console.enabled true
// then fails startup with console_missing.
func Embedded() (fs.FS, []byte, bool) { return nil, nil, false }
