package loader

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/qualificationfixture"
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"go.yaml.in/yaml/v3"
)

func TestTreeBudgets(t *testing.T) {
	for _, depth := range []int{15, 16, 17} {
		source := "a: " + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1)
		_, err := decodeVerifiedYAML([]byte(source))
		if depth <= 16 && err != nil || depth > 16 && !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("depth %d: %v", depth, err)
		}
	}
	for _, nodes := range []int{65535, 65536, 65537} {
		source := "a: [" + strings.Repeat("0,", nodes-4) + "0]"
		_, err := decodeVerifiedYAML([]byte(source))
		if nodes <= 65536 && err != nil || nodes > 65536 && !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("nodes %d: %v", nodes, err)
		}
	}
	// Source punctuation prevents cap-sized decoded text in a cap-sized payload.
	for _, size := range []int{(1 << 20) - 1, 1 << 20, (1 << 20) + 1} {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "a"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: strings.Repeat("x", size-1)}}}
		err := inspectYAML(root, new(yamltokens.Budget))
		if size <= 1<<20 && err != nil || size > 1<<20 && !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("text %d: %v", size, err)
		}
	}
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		if _, err := decodeVerifiedYAML(qualificationfixture.MaximumPayload(name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	b := new(yamltokens.Budget)
	if err := b.Reserve(64<<20, 0); err != nil {
		t.Fatal(err)
	}
	if err := inspectYAML(&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, b); !errors.Is(err, ErrYAMLLimit) {
		t.Fatalf("allocation exhaustion: %v", err)
	}
}

func mappingSource(count int) string {
	var out strings.Builder
	out.WriteByte('{')
	for i := 0; i < count; i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		fmt.Fprintf(&out, "k%d: true", i)
	}
	out.WriteByte('}')
	return out.String()
}
func TestOutputMapBounds(t *testing.T) {
	// Test every admitted arity, which also covers every table-capacity step.
	for count := 0; count <= 896; count++ {
		capacity := 8
		if count > 8 {
			for capacity < (count*8)/7 {
				capacity *= 2
			}
			if capacity > 1024 || count > 7*capacity/8 {
				t.Fatalf("unsafe arity %d capacity %d", count, capacity)
			}
		}
		got, err := decodeVerifiedYAML([]byte(mappingSource(count)))
		if err != nil || len(got) != count {
			t.Fatalf("arity %d: len %d, %v", count, len(got), err)
		}
	}
	large := mappingSource(897)
	for _, source := range []string{large, "a: " + large, "a: [" + large + "]"} {
		assertYAMLError(t, source, ErrYAMLLimit)
	}
	for _, prefix := range []bool{false, true} {
		for _, defect := range []struct {
			source string
			err    error
		}{{"b: {kind: a, \"k\\u0069nd\": b}\n", ErrDuplicateKey}, {"b: null\n", ErrYAML}, {"b: ! x\n", ErrExplicitTag}, {"b: [\n", ErrYAML}} {
			source := "a: " + large + "\n" + defect.source
			if prefix {
				source = defect.source + "a: " + large + "\n"
			}
			assertYAMLError(t, source, defect.err)
		}
	}
	t.Run("map storage reservations", func(t *testing.T) {
		for count := 0; count <= 896; count++ {
			// Independent expected runtime layouts, not calls to the production formula.
			bytes, objects := uint64(128), uint64(1)
			if count > 0 && count <= 8 {
				bytes += 560
				objects++
			}
			if count > 8 {
				capacity := 16
				for 7*capacity/8 < count {
					capacity *= 2
				}
				group := uint64(264 * capacity / 8)
				if group < 32768 {
					group = 2*group + 32
				} else {
					group += 8192
				}
				bytes += 48 + 96 + group
				objects += 3
			}
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: make([]*yaml.Node, 2*count)}
			assertYAMLReservation(t, n, bytes, objects)
		}
	})
}
func assertYAMLReservation(t *testing.T, n *yaml.Node, bytes, objects uint64) {
	t.Helper()
	for _, deficit := range []string{"none", "bytes", "objects"} {
		b := new(yamltokens.Budget)
		availableBytes, availableObjects := bytes, objects
		if deficit == "bytes" {
			availableBytes--
		}
		if deficit == "objects" {
			availableObjects--
		}
		if err := b.Reserve((64<<20)-availableBytes, 1000000-availableObjects); err != nil {
			t.Fatal(err)
		}
		got, err := yamlValue(n, b)
		if deficit == "none" {
			if err != nil || got == nil {
				t.Fatalf("kind %d len %d exact reservation: %v", n.Kind, len(n.Content), err)
			}
			if b.Reserve(1, 0) == nil || b.Reserve(0, 1) == nil {
				t.Fatal("reservation was not fully charged")
			}
		} else if got != nil || !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("%s exhaustion: %T, %v", deficit, got, err)
		}
	}
}
func TestTreeBudgetsAllocationFamilies(t *testing.T) {
	for _, n := range []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "a"}, {Kind: yaml.ScalarNode, Tag: "!!int", Value: "18446744073709551615"}, {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}} {
		assertYAMLReservation(t, n, 64, 1)
	}
	for _, count := range []int{0, 1, 2047, 2048, 65533} {
		backing := uint64(count) * 16
		if backing < 32768 {
			backing = 2*backing + 32
		} else {
			backing += 8192
		}
		assertYAMLReservation(t, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: make([]*yaml.Node, count)}, backing+80, 2)
	}
	for _, objects := range []bool{false, true} {
		b := new(yamltokens.Budget)
		if objects {
			if err := b.Reserve(0, 1000000); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := b.Reserve(64<<20, 0); err != nil {
				t.Fatal(err)
			}
		}
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if err := duplicateYAMLKeys(root, b); !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("scratch exhaustion: %v", err)
		}
		if got, err := convertYAML(root, b); got != nil || !errors.Is(err, ErrYAMLLimit) {
			t.Fatalf("conversion exhaustion: %#v, %v", got, err)
		}
	}
}
func TestDecodeVerifiedYAMLSchemaCapacity(t *testing.T) {
	data, err := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	objects, largest := 0, 0
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if x["type"] == "object" {
				objects++
				if x["additionalProperties"] != false {
					t.Fatal("schema object is open")
				}
				if _, ok := x["patternProperties"]; ok {
					t.Fatal("schema uses patternProperties")
				}
				props, _ := x["properties"].(map[string]any)
				largest = max(largest, len(props))
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(schema)
	if objects != 27 || largest != 13 {
		t.Fatalf("schema objects %d largest %d", objects, largest)
	}
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		got, err := decodeVerifiedYAML(qualificationfixture.MaximumPayload(name))
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.Validate(got, manifest.Options{}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	branches := schema.(map[string]any)["$defs"].(map[string]any)["component"].(map[string]any)["oneOf"].([]any)
	for index := 0; index < len(branches)-1; index++ {
		source := qualificationfixture.MaximumBranch(index, data)
		got, err := decodeVerifiedYAML(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.Validate(got, manifest.Options{}); err != nil {
			t.Fatalf("branch %d: %v", index, err)
		}
	}
	// Independent JSON decoding also checks full tree equality and number spelling.
	source := qualificationfixture.MaximumManifest()
	var want map[string]any
	d := json.NewDecoder(strings.NewReader(string(source)))
	d.UseNumber()
	if err := d.Decode(&want); err != nil {
		t.Fatal(err)
	}
	got, err := decodeVerifiedYAML(source)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("maximum witness tree mismatch", err)
	}
}

func TestTreeBudgetsFixedLayouts(t *testing.T) {
	if unsafe.Sizeof(yamlPosition{}) != 24 || unsafe.Sizeof(yamlWalk{}) != 416 || unsafe.Sizeof(yamlConversion{}) != 32 || unsafe.Sizeof([16]yamlConversion{}) != 512 {
		t.Fatal("converter fixed-layout reservation needs a new source audit")
	}
}
func TestScalarProfileNodeDefense(t *testing.T) {
	for _, child := range []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x", Anchor: "a"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x", Style: yaml.TaggedStyle},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x", Alias: &yaml.Node{}},
		{Kind: yaml.AliasNode, Tag: "!!str"},
		{Kind: yaml.ScalarNode, Tag: "!!binary", Value: "YQ=="},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "\xff"},
		{Kind: yaml.SequenceNode, Tag: "!!map"},
		{Kind: yaml.MappingNode, Tag: "!!seq"},
	} {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "a"}, child}}
		if err := inspectYAML(root, new(yamltokens.Budget)); !errors.Is(err, ErrYAML) {
			t.Fatalf("kind %d tag %s: %v", child.Kind, child.Tag, err)
		}
	}
}
