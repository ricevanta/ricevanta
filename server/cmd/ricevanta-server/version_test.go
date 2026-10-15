package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// serverBin is the binary built once for every black-box test in the package;
// testDir holds it and every other build output, and is removed after the run.
var serverBin, testDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ricevanta-server-test-")
	if err != nil {
		panic(err)
	}
	testDir = dir
	serverBin = filepath.Join(dir, "ricevanta-server")
	if runtime.GOOS == "windows" {
		serverBin += ".exe"
	}
	build := exec.Command("go", "build", "-o", serverBin, ".")
	build.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
	if out, err := build.CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	stdout, stderr []byte
	code           int
}

func run(t *testing.T, env []string, args ...string) result {
	t.Helper()
	cmd := exec.Command(serverBin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exit.ExitCode()
	}
	return result{stdout.Bytes(), stderr.Bytes(), code}
}

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

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"frobnicate"},
		{"--frobnicate"},
		{"version", "--yaml"},
		{"version", "extra"},
		{"migrate"},
		{"serve", "--config"},
		{"serve", "--config", "/x", "extra"},
		{"check-config", "--bogus"},
		{"console-manifest", "extra"},
		{"--version", "extra"},
	} {
		r := run(t, nil, args...)
		if r.code != 2 {
			t.Errorf("%v: exit %d, want 2", args, r.code)
		}
		if len(r.stdout) != 0 {
			t.Errorf("%v: stdout %q, want empty", args, r.stdout)
		}
		if !bytes.Contains(r.stderr, []byte("usage")) && !bytes.Contains(r.stderr, []byte("blocked")) {
			t.Errorf("%v: stderr %q lacks usage", args, r.stderr)
		}
	}
}

func TestMigrateNamesItsGate(t *testing.T) {
	r := run(t, nil, "migrate")
	if r.code != 2 || !bytes.Contains(r.stderr, []byte("blocked")) {
		t.Fatalf("exit %d stderr %q", r.code, r.stderr)
	}
}
