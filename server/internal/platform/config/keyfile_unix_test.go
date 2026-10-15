//go:build unix

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestKeyOwnershipRule(t *testing.T) {
	const euid, egid, other = 1000, 1000, 4242
	id := procIdentity{euid: euid, egid: egid, groups: []uint32{egid, 2000}}
	cases := []struct {
		name string
		st   keyStat
		ok   bool
	}{
		{"0400 owner", keyStat{uid: euid, gid: other, perm: 0o400}, true},
		{"0600 owner", keyStat{uid: euid, gid: other, perm: 0o600}, true},
		{"0600 root", keyStat{uid: 0, gid: other, perm: 0o600}, true},
		{"0440 root supplementary group", keyStat{uid: 0, gid: 2000, perm: 0o440}, true},
		{"0440 root effective group", keyStat{uid: 0, gid: egid, perm: 0o440}, true},
		{"0640 owner effective group", keyStat{uid: euid, gid: egid, perm: 0o640}, true},
		{"0640 foreign group", keyStat{uid: euid, gid: other, perm: 0o640}, false},
		{"0440 foreign group", keyStat{uid: 0, gid: other, perm: 0o440}, false},
		{"0644 world readable", keyStat{uid: euid, gid: egid, perm: 0o644}, false},
		{"0444 compose environment secret", keyStat{uid: 0, gid: 0, perm: 0o444}, false},
		{"0660 group write", keyStat{uid: euid, gid: egid, perm: 0o660}, false},
		{"0700 owner execute", keyStat{uid: euid, gid: egid, perm: 0o700}, false},
		{"0200 unreadable", keyStat{uid: euid, gid: egid, perm: 0o200}, false},
		{"0604 other read", keyStat{uid: euid, gid: egid, perm: 0o604}, false},
		{"0600 foreign owner", keyStat{uid: other, gid: egid, perm: 0o600}, false},
		{"0600 setuid", keyStat{uid: euid, gid: egid, perm: 0o600, special: true}, false},
		{"not regular", keyStat{uid: euid, gid: egid, perm: 0o600, notRegular: true}, false},
	}
	for _, c := range cases {
		err := checkKeyStat(c.st, id)
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.name, c.ok, err)
		}
	}
}

func writeKey(t *testing.T, path string, perm fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("key material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func TestReadKeyFileModes(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.key")
	writeKey(t, good, 0o600)
	if data, err := ReadKeyFile(good); err != nil || string(data) != "key material" {
		t.Fatalf("0600: %q %v", data, err)
	}
	world := filepath.Join(dir, "world.key")
	writeKey(t, world, 0o644)
	_, err := ReadKeyFile(world)
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != CodeKeyFileRejected {
		t.Fatalf("0644: %v", err)
	}
	if _, err := ReadKeyFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := ReadKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing accepted")
	}
}

func TestReadKeyFileGroupRules(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing a file's group to a foreign group needs root; TestKeyOwnershipRule covers the rule")
	}
	dir := t.TempDir()
	foreign := filepath.Join(dir, "foreign.key")
	writeKey(t, foreign, 0o640)
	if err := os.Chown(foreign, 0, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(foreign); err == nil {
		t.Fatal("0640 with a foreign group accepted")
	}
	own := filepath.Join(dir, "own.key")
	writeKey(t, own, 0o440)
	if err := os.Chown(own, 0, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(own); err != nil {
		t.Fatalf("0440 root with the effective group: %v", err)
	}
}

// TestReadKeyFileKubernetesSymlinkChain builds the layout the kubelet's atomic
// writer projects: key -> ..data/key and ..data -> ..<timestamp>.
func TestReadKeyFileKubernetesSymlinkChain(t *testing.T) {
	dir := t.TempDir()
	stamp := "..2026_10_15_12_00_00.123456789"
	if err := os.Mkdir(filepath.Join(dir, stamp), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, stamp, "key")
	writeKey(t, target, 0o440)
	if err := os.Chown(target, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(stamp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key")
	if err := os.Symlink(filepath.Join("..data", "key"), link); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadKeyFile(link); err != nil || string(data) != "key material" {
		t.Fatalf("chain to 0440: %q %v", data, err)
	}
	// The link itself has mode 0777; only the target's mode counts, so a
	// world-readable target through the same chain is refused.
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(link); err == nil {
		t.Fatal("chain to 0644 accepted")
	}
}

func TestReadKeyFileFIFODoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadKeyFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadKeyFile blocked on a FIFO")
	}
}

func TestLoadConfigFIFODoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "server.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Load(fifo, func(string) (string, bool) { return "", false }); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}

func TestReadKeyFileSizeBound(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.key")
	if err := os.WriteFile(p, make([]byte, maxPEMBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(p); err == nil {
		t.Fatal("oversized key accepted")
	}
}
