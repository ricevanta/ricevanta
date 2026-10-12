package loader

import (
	"encoding/json"
	"slices"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"go.yaml.in/yaml/v3"
)

// yamlWalk retains only the current source path, including one scalar/key slot.
// Inspection proves the depth and content bounds before later walks use it.
type yamlWalk struct {
	path  [manifest.MaxTreeDepth + 1]yamlPosition
	depth int
}
type yamlPosition struct {
	node *yaml.Node
	next int
	key  bool
}

func (w *yamlWalk) next() (*yaml.Node, int, bool) {
	for w.depth > 0 {
		p := &w.path[w.depth-1]
		if p.next == -1 {
			p.next = 0
			return p.node, w.depth - 1, p.key
		}
		if p.next < len(p.node.Content) {
			child := p.node.Content[p.next]
			key := p.node.Kind == yaml.MappingNode && p.next%2 == 0
			p.next++
			w.path[w.depth] = yamlPosition{node: child, next: -1, key: key}
			w.depth++
		} else {
			w.depth--
		}
	}
	return nil, 0, false
}
func walkYAML(root *yaml.Node) yamlWalk {
	w := yamlWalk{depth: 1}
	w.path[0] = yamlPosition{node: root, next: -1}
	return w
}

func inspectYAML(root *yaml.Node, b *yamltokens.Budget) error {
	// Reserve the fixed walk and returned walk copy separately, even on stack.
	if b.Reserve(2*yamlAllocation(416), 2) != nil {
		return ErrYAMLLimit
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return ErrYAML
	}
	nodes, text := 0, 0
	w := walkYAML(root)
	for w.depth > 0 {
		n, depth, key := w.next()
		if n == nil {
			if w.depth > 0 {
				return ErrYAML
			}
			break
		}
		if nodes == manifest.MaxTreeNodes {
			return ErrYAMLLimit
		}
		nodes++
		if n.Anchor != "" || n.Alias != nil || n.Style&yaml.TaggedStyle != 0 {
			return ErrYAML
		}
		if key && (n.Kind != yaml.ScalarNode || n.Tag != "!!str" || n.Value == "<<") {
			return ErrYAML
		}
		switch n.Kind {
		case yaml.MappingNode, yaml.SequenceNode:
			if depth == manifest.MaxTreeDepth || len(n.Content) > manifest.MaxTreeNodes-nodes {
				return ErrYAMLLimit
			}
			if n.Kind == yaml.MappingNode && (n.Tag != "!!map" || len(n.Content)%2 != 0) || n.Kind == yaml.SequenceNode && n.Tag != "!!seq" {
				return ErrYAML
			}
		case yaml.ScalarNode:
			if len(n.Content) != 0 {
				return ErrYAML
			}
			switch n.Tag {
			case "!!str":
				if !utf8.ValidString(n.Value) {
					return ErrYAML
				}
			case "!!bool":
				if n.Value != "true" && n.Value != "false" {
					return ErrYAML
				}
				continue
			case "!!int":
				if !unsignedYAML(n.Value) {
					return ErrYAML
				}
			default:
				return ErrYAML
			}
			if len(n.Value) > manifest.MaxManifestBytes-text {
				return ErrYAMLLimit
			}
			text += len(n.Value)
		default:
			return ErrYAML
		}
	}
	return nil
}

// unsignedYAML validates without strconv's allocated errors on rejected numbers.
func unsignedYAML(s string) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d := uint64(s[i] - '0')
		if n > (^uint64(0)-d)/10 {
			return false
		}
		n = n*10 + d
	}
	return true
}

func duplicateYAMLKeys(root *yaml.Node, b *yamltokens.Budget) error {
	// Fixed walk storage, two returned copies, and the scratch slice header.
	if b.Reserve(3*yamlAllocation(416)+yamlAllocation(24), 4) != nil {
		return ErrYAMLLimit
	}
	largest := 0
	w := walkYAML(root)
	for w.depth > 0 {
		n, _, _ := w.next()
		if n != nil && n.Kind == yaml.MappingNode {
			largest = max(largest, len(n.Content)/2)
		}
	}
	// One exact reusable string-header array. Go 1.27.1 runtime/slice.go:101-119
	// allocates the requested backing once. slices/sort.go:16-19 and
	// slices/zsortordered.go:63-132 sort in place, without heap allocation.
	// Only the smaller partition recurses, at most 15 frames for 32,767 keys.
	if b.Reserve(yamlAllocation(uint64(largest)*16), 1) != nil {
		return ErrYAMLLimit
	}
	keys := make([]string, largest)
	w = walkYAML(root)
	for w.depth > 0 {
		n, _, _ := w.next()
		if n == nil || n.Kind != yaml.MappingNode {
			continue
		}
		count := len(n.Content) / 2
		for i := 0; i < count; i++ {
			keys[i] = n.Content[2*i].Value
		}
		slices.Sort(keys[:count])
		for i := 1; i < count; i++ {
			if keys[i-1] == keys[i] {
				return ErrDuplicateKey
			}
		}
	}
	return nil
}

type yamlConversion struct {
	node  *yaml.Node
	value any
	next  int
}

func convertYAML(root *yaml.Node, b *yamltokens.Budget) (map[string]any, error) {
	// Sixteen 32-byte conversion frames, with no recursive conversion.
	if b.Reserve(yamlAllocation(512), 1) != nil {
		return nil, ErrYAMLLimit
	}
	value, err := yamlValue(root, b)
	if err != nil {
		return nil, err
	}
	result := value.(map[string]any)
	var path [manifest.MaxTreeDepth]yamlConversion
	path[0] = yamlConversion{node: root, value: value}
	depth := 1
	for depth > 0 {
		p := &path[depth-1]
		if p.next == len(p.node.Content) {
			depth--
			continue
		}
		index := p.next
		child := p.node.Content[index]
		key := ""
		if p.node.Kind == yaml.MappingNode {
			key = child.Value
			child = p.node.Content[index+1]
			p.next += 2
		} else {
			p.next++
		}
		value, err := yamlValue(child, b)
		if err != nil {
			return nil, err
		}
		if m, ok := p.value.(map[string]any); ok {
			m[key] = value
		} else {
			p.value.([]any)[index] = value
		}
		if child.Kind != yaml.ScalarNode {
			path[depth] = yamlConversion{node: child, value: value}
			depth++
		}
	}
	return result, nil
}
func yamlValue(n *yaml.Node, b *yamltokens.Budget) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		count := uint64(len(n.Content) / 2)
		bytes, objects, ok := yamlMapStorage(count)
		if !ok || b.Reserve(bytes, objects) != nil {
			return nil, ErrYAMLLimit
		}
		return make(map[string]any, int(count)), nil
	case yaml.SequenceNode:
		// Go 1.27.1 runtime/slice.go:101-119 makes one exact 16*n backing;
		// runtime/iface.go:456-466 boxes one 24-byte slice header.
		if b.Reserve(yamlAllocation(uint64(len(n.Content))*16)+yamlAllocation(24), 2) != nil {
			return nil, ErrYAMLLimit
		}
		return make([]any, len(n.Content)), nil
	default:
		// Go 1.27.1 runtime/iface.go:437-445 boxes one 16-byte string
		// header, without copying bytes, also for json.Number. Booleans use
		// static storage (cmd/compile/internal/walk/convert.go:162-175);
		// charging one rounded string header for every scalar is conservative.
		if b.Reserve(64, 1) != nil {
			return nil, ErrYAMLLimit
		}
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!bool":
			return n.Value == "true", nil
		default:
			return json.Number(n.Value), nil
		}
	}
}

// yamlAllocation bounds each allocator-rounded object separately. All callers
// derive sizes from the inspected 65,536-node tree or fixed 64-bit layouts.
// Go 1.27.1 runtime/msize.go:16-40, runtime/malloc.go:1119-1155 and
// internal/runtime/gc/sizeclasses.go bound each small object by 2*s+32,
// and each large object by s+8192, including headers/page rounding.
//
// Fixed reservations cover each yamlWalk (416 bytes), returned walk copy,
// scratch slice header (24 bytes) and conversion path (16*32 bytes), even
// when the compiler keeps them on the stack. Layout tests pin these sizes.
// utf8.ValidString, unsignedYAML, static-sentinel comparison and concrete
// map/slice assertions allocate nothing. No closure, defer, formatting,
// reflection, append growth or allocating error helper runs here. Sorting
// and explicit traversal stacks are separately subject to Gate B's 8 MiB
// stack qualification; a heap reservation does not qualify stack growth.
func yamlAllocation(size uint64) uint64 {
	if size >= 32768 {
		return size + 8192
	}
	return 2*size + 32
}

// yamlMapStorage applies the pinned Go 1.27.1 single-table proof from spec 4.3.
// Exactly n distinct inserts cannot exhaust capacity, regardless of hash seed.
// Sources: internal/runtime/maps/map.go:283-345; table.go:75-133 and
// :1208-1248; runtime_faststr.go:286-299,375-395. With n<=896, the hint
// creates one table with capacity c>=floor(8*n/7) and growthLeft>=n.
// Small maps fit eight entries; empty maps need no group. Keys and values
// are inline 16-byte headers, below internal/abi/map.go's 128-byte limits.
// cmd/compile/internal/reflectdata/map.go:21-108,168-216 and
// internal/runtime/maps/group.go:327-335 supply the 264-byte group,
// 48-byte map, 8-byte directory and 32-byte table layouts. Charge every
// possible map-owned allocation separately before make, including the
// deferred first group allocation of small maps. No deletes, extra inserts
// or mutation occur during construction. Runtime map seeds (runtime/rand.go:
// 163-188, internal/chacha8rand/chacha8.go:54-106) and string hashing
// (internal/runtime/maps/runtime_hash64.go:21-79, memhash_amd64.s and
// memhash_arm64.s) use existing state and fixed locals, without allocation.
// A pin/layout/operation change
// requires a fresh audit and Gate B native measurements.
func yamlMapStorage(n uint64) (bytes, objects uint64, ok bool) {
	if n > 896 {
		return 0, 0, false
	}
	bytes, objects = yamlAllocation(48), 1
	if n == 0 {
		return bytes, objects, true
	}
	if n <= 8 {
		return bytes + yamlAllocation(264), objects + 1, true
	}
	target := 8 * n / 7
	capacity := uint64(16)
	for capacity < target {
		capacity *= 2
	}
	return bytes + yamlAllocation(8) + yamlAllocation(32) + yamlAllocation(264*capacity/8), objects + 3, true
}

// boundYAMLMaps runs only after every profile and duplicate check. It checks
// the complete tree before conversion can allocate its first output container.
func boundYAMLMaps(root *yaml.Node, b *yamltokens.Budget) error {
	if b.Reserve(2*yamlAllocation(416), 2) != nil {
		return ErrYAMLLimit
	}
	w := walkYAML(root)
	for w.depth > 0 {
		n, _, _ := w.next()
		if n != nil && n.Kind == yaml.MappingNode && len(n.Content)/2 > 896 {
			return ErrYAMLLimit
		}
	}
	return nil
}
