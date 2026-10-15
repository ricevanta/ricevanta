//go:build unix && !ricevanta_console

package main_test

import (
	"bytes"
	"strings"
	"testing"
)

// Behaviour of a binary built without ricevanta_console.

func TestConsoleManifestWithoutTag(t *testing.T) {
	r := run(t, nil, "console-manifest")
	if r.code != 3 || len(r.stdout) != 0 || !bytes.Contains(r.stderr, []byte("console_missing")) {
		t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestConsoleEnabledWithoutTagFailsStartup(t *testing.T) {
	r := runConfig(t, serverBin, writeConfig(t, plaintext(freePort(t), "")))
	if r.code != 3 || !bytes.Contains(r.stderr, []byte("console_missing")) {
		t.Fatalf("exit %d:\n%s", r.code, r.stderr)
	}
	checkLogs(t, strings.Split(strings.TrimSpace(string(r.stderr)), "\n"), "starting", "startup_failed")
}
