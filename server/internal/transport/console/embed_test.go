//go:build !ricevanta_console

package console_test

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

func TestNothingEmbeddedWithoutTag(t *testing.T) {
	dist, manifest, ok := console.Embedded()
	if ok || dist != nil || manifest != nil {
		t.Fatalf("untagged build embeds a console: ok=%v", ok)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			t.Fatalf("unexpected non-regular file %s", p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestTaggedBuildEmbedsFixture copies the console and buildinfo packages
// into a temporary module, places the fixture tree where the release recipe
// puts the real one, and runs the tagged tests there, so the tracked tree
// never holds dist/ or manifest.json.
func TestTaggedBuildEmbedsFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a temporary module")
	}
	root := t.TempDir()
	for _, f := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join("../../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyTree(t, "../../buildinfo", filepath.Join(root, "internal/buildinfo"))
	pkg := filepath.Join(root, "internal/transport/console")
	copyTree(t, ".", pkg)
	copyTree(t, "testdata/dist", filepath.Join(pkg, "dist"))
	data, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	// The copied tests read console/security/csp.txt four levels up.
	csp, err := os.ReadFile("../../../../console/security/csp.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "../console/security"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "../console/security/csp.txt"), csp, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"vet", "-tags", "ricevanta_console", "./internal/transport/console"},
		{"test", "-count=1", "-short", "-tags", "ricevanta_console", "./internal/transport/console"},
	} {
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, out)
		}
	}
}
