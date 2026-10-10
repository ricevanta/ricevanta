package manifest

import (
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

type treeBudget struct{ nodes, bytes int }

func (b *treeBudget) text(s string) bool {
	if len(s) > MaxManifestBytes-b.bytes || !utf8.ValidString(s) {
		return false
	}
	b.bytes += len(s)
	return true
}
func number(s string) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, e := strconv.ParseUint(s, 10, 64)
	return e == nil
}
func (b *treeBudget) visit(v any, depth int) bool {
	if b.nodes == MaxTreeNodes {
		return false
	}
	b.nodes++
	switch x := v.(type) {
	case map[string]any:
		if x == nil || depth == MaxTreeDepth || len(x) > (MaxTreeNodes-b.nodes)/2 {
			return false
		}
		for k, v := range x {
			if b.nodes == MaxTreeNodes {
				return false
			}
			b.nodes++
			if !b.text(k) || !b.visit(v, depth+1) {
				return false
			}
		}
	case []any:
		if x == nil || depth == MaxTreeDepth || len(x) > MaxTreeNodes-b.nodes {
			return false
		}
		for _, v := range x {
			if !b.visit(v, depth+1) {
				return false
			}
		}
	case string:
		return b.text(x)
	case bool:
		return true
	case json.Number:
		return number(string(x)) && b.text(string(x))
	default:
		return false
	}
	return true
}

// encoding/json orders map keys and preserves canonical number lexemes.
func encoding(v any) string { b, _ := json.Marshal(v); return string(b) }
func unsigned(v any) uint64 { n, _ := strconv.ParseUint(string(v.(json.Number)), 10, 64); return n }
