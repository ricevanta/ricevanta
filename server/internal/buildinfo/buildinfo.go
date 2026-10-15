// Package buildinfo holds the product identity compiled into ricevanta-server.
//
// This tracked file carries the development default. A release build copies
// the gitignored generated.go from scripts/release/version.py into this
// package; that file declares the constants Version, Commit, Channel and
// SourceEpoch and an init function that assigns them to the package default
// (docs/specs/server-runtime.md section 2), so no tracked file changes during a
// release build.
package buildinfo

import (
	"encoding/json"
	"strconv"
)

// Identity is the public build identity shared with build-info.json.
type Identity struct {
	Version     string
	Commit      string
	Channel     string
	SourceEpoch int64
}

// current is the development default; generated.go replaces it in init.
var current = Identity{Version: "0.0.0-local", Commit: "unknown", Channel: "local", SourceEpoch: 0}

// Current returns the identity this binary was built with.
func Current() Identity { return current }

// Line is the --version output without its final newline.
func (i Identity) Line() string {
	return "ricevanta-server " + i.Version + " (commit " + i.Commit + ", channel " + i.Channel + ")"
}

// JSON encodes the identity with sorted keys channel, commit, sourceEpoch and
// version, without insignificant whitespace.
func (i Identity) JSON() []byte {
	var b []byte
	b = append(b, `{"channel":`...)
	b = appendString(b, i.Channel)
	b = append(b, `,"commit":`...)
	b = appendString(b, i.Commit)
	b = append(b, `,"sourceEpoch":`...)
	b = strconv.AppendInt(b, i.SourceEpoch, 10)
	b = append(b, `,"version":`...)
	b = appendString(b, i.Version)
	return append(b, '}')
}

func appendString(b []byte, s string) []byte {
	enc, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail; invalid UTF-8 is replaced.
		panic(err)
	}
	return append(b, enc...)
}
