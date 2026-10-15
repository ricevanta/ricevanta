// Package buildinfo holds the product identity compiled into ricevanta-server
// (docs/specs/server-runtime.md section 2).
//
// The constants Version, Commit, Channel and SourceEpoch come from
// development.go in an ordinary build and from the gitignored generated.go
// that scripts/release/version.py writes in a build with the
// ricevanta_release tag. Either wrong combination fails to compile: the tag
// without generated.go leaves the constants undefined, and generated.go
// without the tag declares them twice.
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

// Current returns the identity this binary was built with.
func Current() Identity {
	return Identity{Version: Version, Commit: Commit, Channel: Channel, SourceEpoch: SourceEpoch}
}

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
