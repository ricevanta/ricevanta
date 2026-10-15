//go:build !ricevanta_release

package buildinfo_test

import (
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
)

func TestCurrentReturnsDevelopmentDefault(t *testing.T) {
	got := buildinfo.Current()
	want := buildinfo.Identity{Version: "0.0.0-local", Commit: "unknown", Channel: "local", SourceEpoch: 0}
	if got != want {
		t.Fatalf("Current() = %+v, want %+v", got, want)
	}
}
