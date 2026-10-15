//go:build windows

package runtime

import (
	"context"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

// TestTLSKeyRefusedOnWindows: the key-file rule judges POSIX owner and mode
// bits, which Windows does not report, so every key is refused and serve
// exits 3 before binding.
func TestTLSKeyRefusedOnWindows(t *testing.T) {
	doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" + strconv.Itoa(freePort(t)) +
		"\"\n    tls:\n      mode: file\n      certificate_file: /ricevanta/api.crt\n      key_file: /ricevanta/api.key\nconsole: {enabled: false}\n"
	logs := &syncBuffer{}
	code := Serve(context.Background(), Options{ConfigFlag: writeConfig(t, doc), ConfigFlagSet: true, Stderr: logs, Stdout: io.Discard})
	if code != ExitStartup || !strings.Contains(logs.String(), config.CodeKeyFileRejected) {
		t.Fatalf("exit %d logs %s", code, logs.String())
	}
}
