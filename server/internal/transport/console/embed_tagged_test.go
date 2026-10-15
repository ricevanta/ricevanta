//go:build ricevanta_console

package console_test

import (
	"os"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// TestEmbeddedTreeVerifies runs only in a tagged build; the untagged suite
// starts it in a temporary module that holds the fixture as dist/.
func TestEmbeddedTreeVerifies(t *testing.T) {
	dist, manifest, ok := console.Embedded()
	if !ok {
		t.Fatal("tagged build embeds nothing")
	}
	tree, err := console.Verify(dist, manifest, buildinfo.Current())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(tree.Manifest()) != string(want) {
		t.Fatal("embedded manifest differs from the copied file")
	}
	other := buildinfo.Current()
	other.Commit = "0123456789abcdef0123456789abcdef01234567"
	_, err = console.Verify(dist, manifest, other)
	wantCode(t, err, console.CodeIdentityMismatch)
}
