package loader

import (
	"fmt"
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/qualificationfixture"
	"go.yaml.in/yaml/v3"
	"os"
	"strconv"
	"strings"
)

type parserInput struct {
	Name string
	Size int
}

func parserPayload(c parserInput) []byte {
	n := c.Size
	if strings.HasPrefix(c.Name, "maximum-branch") {
		index, err := strconv.Atoi(strings.TrimPrefix(c.Name, "maximum-branch"))
		if err != nil {
			panic(err)
		}
		schema, err := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
		if err != nil {
			panic(err)
		}
		return qualificationfixture.MaximumBranch(index, schema)
	}
	if c.Name == "implicit-binary" {
		return []byte("[" + strings.Repeat("0b2,", n-2) + "0b2]")
	}
	if c.Name == "implicit-octal" {
		return []byte("[" + strings.Repeat("0o9,", n-2) + "0o9]")
	}
	if c.Name == "implicit-float" {
		return []byte("[" + strings.Repeat("1e999,", n-2) + "1e999]")
	}
	if strings.HasPrefix(c.Name, "maximum-") {
		return qualificationfixture.MaximumPayload(c.Name)
	}
	switch c.Name {
	case "comment-collections":
		return []byte(strings.Repeat("- {} #c\n", n/8))
	case "plain":
		return []byte(strings.Repeat("x", n))
	case "comment-keys":
		return []byte(strings.Repeat("a: b #c\n", n/8))
	case "comments":
		return []byte("a: b\n#" + strings.Repeat("c", max(0, n-6)))
	case "tiny-comments":
		return []byte("a: b\n" + strings.Repeat("#\n", max(0, (n-5)/2)))
	case "escaped":
		return []byte("\"" + strings.Repeat("\\L", max(0, (n-2)/2)) + "\"")
	case "block":
		return []byte("a: |-\n  " + strings.Repeat("x", max(0, n-8)))
	case "empty-flow":
		return []byte("[" + strings.Repeat("{},", max(0, (n-3)/3)) + "{}]")
	case "tiny-keys":
		return []byte(strings.Repeat("a: b\n", n/5))
	case "indent":
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat(" ", i) + "a:\n")
		}
		b.WriteString(strings.Repeat(" ", n) + "b\n")
		return []byte(b.String())
	case "flow":
		return []byte(strings.Repeat("[", n) + "0" + strings.Repeat("]", n))
	case "explicit-key":
		return []byte(strings.Repeat("? a\n: b\n", n/8))
	case "tags":
		return []byte(strings.Repeat("! a\n", n/4))
	case "anchors":
		return []byte(strings.Repeat("&a b\n", n/5))
	case "missing-end":
		return []byte("[" + strings.Repeat(" ", max(0, n-1)))
	case "malformed-suffix":
		return []byte("a: b\n...\n" + strings.Repeat("[", max(0, n-9)))
	case "nodes":
		return []byte("[" + strings.Repeat("0,", n-2) + "0]")
	default:
		panic("unknown qualification recipe")
	}
}

func parserCorpus(extended bool) []parserInput {
	var out []parserInput
	names := []string{"comment-collections", "plain", "comment-keys", "comments", "tiny-comments", "escaped", "block", "empty-flow", "tiny-keys", "explicit-key", "tags", "anchors", "missing-end", "malformed-suffix"}
	sizes := []int{1 << 20}
	if extended {
		sizes = nil
		for n := 64; n < 1<<20; n *= 2 {
			sizes = append(sizes, n)
		}
		sizes = append(sizes, (1<<20)-1, 1<<20, (1<<20)+1)
	}
	for _, name := range names {
		for _, n := range sizes {
			out = append(out, parserInput{name, n})
		}
	}
	for _, name := range []string{"flow", "indent"} {
		for _, n := range []int{15, 16, 17, 63, 64, 65} {
			out = append(out, parserInput{name, n})
		}
	}
	for _, n := range []int{65535, 65536, 65537} {
		out = append(out, parserInput{"nodes", n})
	}
	out = append(out, parserInput{"tiny-keys", 32767 * 5}, parserInput{"explicit-key", 32767 * 8}, parserInput{"comment-keys", 32767 * 8}, parserInput{"empty-flow", 196608}, parserInput{"comment-collections", 65535 * 8})
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		out = append(out, parserInput{name, 0})
	}
	for i := 0; i < 7; i++ {
		out = append(out, parserInput{fmt.Sprintf("maximum-branch%d", i), 0})
	}
	for _, name := range []string{"implicit-binary", "implicit-octal", "implicit-float"} {
		out = append(out, parserInput{name, 65536})
	}
	return out
}

// nodeCounts walks only the Node tree, independently of scanner/event accounting.
func nodeCounts(root *yaml.Node) (nodes, depth int) {
	type item struct {
		N     *yaml.Node
		Depth int
	}
	todo := []item{{root, 0}}
	for len(todo) > 0 {
		it := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if it.N.Kind == yaml.DocumentNode {
			for _, c := range it.N.Content {
				todo = append(todo, item{c, it.Depth})
			}
			continue
		}
		nodes++
		d := it.Depth
		if it.N.Kind == yaml.MappingNode || it.N.Kind == yaml.SequenceNode {
			d++
			depth = max(depth, d)
		}
		for _, c := range it.N.Content {
			todo = append(todo, item{c, d})
		}
	}
	return
}
