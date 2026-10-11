package loader

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
)

func TestTokenVectors(t *testing.T) {
	b, err := os.ReadFile("../../../../schemas/extension/v1alpha1/loader-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct{ Name, YAML, Result string }
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			err := yamltokens.Check([]byte(c.YAML))
			if c.Result == "accept" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, yamltokens.ErrTag) {
				t.Fatalf("got %v, want tag", err)
			}
		})
	}
}

func TestYAMLFraming(t *testing.T) {
	for _, s := range []string{"a: b\n", "---\na: b\n...\n# tail\n", "a: |\n  ---\n  ...\n  ! & * #\n", "{a: ['!', '&', '*', '---', '...']}\r\n", "? a\n: b\n", "a: 'can''t !'\n", "a: \"escaped \\\" !\"\n"} {
		if err := yamltokens.Check([]byte(s)); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "# comment\n", "---\n...\n", "a: b\n---\n", "a: b\n...\n---\n", "a: b\n...\n...\n", "a: b\n...\nx: y\n", "a: b\n[\n", "a: &x b\n", "a: *x\n", "%YAML 1.1\n---\na: b\n", "%TAG !e! tag:example.com,2026:\n---\na: b\n", "\xef\xbb\xbfa: b\n", "a: \xff\n"} {
		if err := yamltokens.Check([]byte(s)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, tag := range []string{"!", "!!str", "!e!str", "!<tag:yaml.org,2002:str>"} {
		for _, s := range []string{tag + " a\n", "a: " + tag + " b\n", "[" + tag + " b]\n", "? " + tag + " a\n: b\n"} {
			if err := yamltokens.Check([]byte(s)); !errors.Is(err, yamltokens.ErrTag) {
				t.Fatalf("%q: %v", s, err)
			}
		}
	}
}

func TestTokenLimits(t *testing.T) {
	for _, n := range []int{(1 << 20) - 1, 1 << 20} {
		if err := yamltokens.Check([]byte("#" + strings.Repeat("x", n-1))); err == nil {
			t.Fatal("empty document accepted")
		}
	}
	if err := yamltokens.Check([]byte(strings.Repeat("x", (1<<20)+1))); !errors.Is(err, yamltokens.ErrLimit) {
		t.Fatalf("payload cap: %v", err)
	}
}

func TestPreflightNodeBounds(t *testing.T) {
	for _, depth := range []int{15, 16, 17} {
		s := strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
		err := yamltokens.Check([]byte(s))
		if depth <= 16 && err != nil || depth > 16 && !errors.Is(err, yamltokens.ErrLimit) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
	for _, nodes := range []int{65535, 65536, 65537} {
		s := "[" + strings.Repeat("0,", nodes-2) + "0]"
		err := yamltokens.Check([]byte(s))
		if nodes <= 65536 && err != nil || nodes > 65536 && !errors.Is(err, yamltokens.ErrLimit) {
			t.Fatalf("nodes %d: %v", nodes, err)
		}
	}
	s := strings.Repeat("a:\n", 32768)
	if err := yamltokens.Check([]byte(s)); !errors.Is(err, yamltokens.ErrLimit) {
		t.Fatalf("empty scalar count: %v", err)
	}
}
