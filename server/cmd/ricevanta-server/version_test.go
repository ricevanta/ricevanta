package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// serverBin is the binary every black-box test runs; testDir holds build
// outputs and is removed after the run.
//
// RICEVANTA_TEST_SERVER_BINARY names a prebuilt binary to test instead, such
// as a release build. The name avoids the RICEVANTA_SERVER_ prefix, which the
// server rejects for unknown variables, because the tests pass their
// environment on to the binary. Without it the suite builds the command with
// the same build tags this test binary was compiled with.
var serverBin, testDir string

func buildTags() []string {
	var tags []string
	if consoleTag {
		tags = append(tags, "ricevanta_console")
	}
	if releaseTag {
		tags = append(tags, "ricevanta_release")
	}
	return tags
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ricevanta-server-test-")
	if err != nil {
		panic(err)
	}
	testDir = dir
	if prebuilt := os.Getenv("RICEVANTA_TEST_SERVER_BINARY"); prebuilt != "" {
		if !filepath.IsAbs(prebuilt) {
			os.RemoveAll(dir)
			panic("RICEVANTA_TEST_SERVER_BINARY must be an absolute path")
		}
		serverBin = prebuilt
	} else {
		serverBin = filepath.Join(dir, "ricevanta-server")
		if runtime.GOOS == "windows" {
			serverBin += ".exe"
		}
		args := []string{"build", "-o", serverBin}
		if tags := buildTags(); len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		build := exec.Command("go", append(args, ".")...)
		build.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
		if out, err := build.CombinedOutput(); err != nil {
			os.Stderr.Write(out)
			os.RemoveAll(dir)
			panic(err)
		}
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
