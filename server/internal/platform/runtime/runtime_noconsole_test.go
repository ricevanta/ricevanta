//go:build !ricevanta_console

package runtime

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

func TestConsoleMissingWithoutTag(t *testing.T) {
	logs := &syncBuffer{}
	code := Serve(context.Background(), Options{
		ConfigFlag: writeConfig(t, plaintextConfig(freePort(t), "")), ConfigFlagSet: true, Stderr: logs, Stdout: io.Discard,
	})
	if code != ExitStartup || !strings.Contains(logs.String(), console.CodeMissing) {
		t.Fatalf("exit %d logs %s", code, logs.String())
	}
	logMessages(t, logs.String())
}
