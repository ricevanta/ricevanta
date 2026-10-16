//go:build !ricevanta_release

package buildinfo

// The development identity. A release build passes -tags ricevanta_release,
// which drops this file, and supplies the same constants from generated.go.
const (
	Version           = "0.0.0-local"
	Commit            = "unknown"
	Channel           = "local"
	SourceEpoch int64 = 0
)
