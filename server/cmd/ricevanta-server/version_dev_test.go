//go:build !ricevanta_release

package main_test

import "testing"

// The development identity; a release build reports the generated one,
// which the release tooling compares with identity.json.

func TestVersionFlag(t *testing.T) {
	r := run(t, nil, "--version")
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	if want := "ricevanta-server 0.0.0-local (commit unknown, channel local)\n"; string(r.stdout) != want {
		t.Fatalf("stdout %q, want %q", r.stdout, want)
	}
	if len(r.stderr) != 0 {
		t.Fatalf("stderr %q", r.stderr)
	}
}

func TestVersionJSON(t *testing.T) {
	r := run(t, nil, "version", "--json")
	if r.code != 0 {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	want := `{"channel":"local","commit":"unknown","sourceEpoch":0,"version":"0.0.0-local"}` + "\n"
	if string(r.stdout) != want {
		t.Fatalf("stdout %q, want %q", r.stdout, want)
	}
}

func TestVersionText(t *testing.T) {
	r := run(t, nil, "version")
	if r.code != 0 || string(r.stdout) != "ricevanta-server 0.0.0-local (commit unknown, channel local)\n" {
		t.Fatalf("exit %d stdout %q", r.code, r.stdout)
	}
}
