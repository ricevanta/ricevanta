// Package exportdest validates decoded ExportDestination authoring resources.
// Shape validation grants no authority and performs no secret or network access.
package exportdest

import (
	"errors"
	"math"
	"sort"
	"unicode/utf8"
)

var (
	ErrInput       = errors.New("export destination decoded input")
	ErrLimits      = errors.New("export destination input limits")
	ErrResource    = errors.New("export destination resource envelope")
	ErrAdapter     = errors.New("export destination adapter selection")
	ErrCommon      = errors.New("export destination common fields")
	ErrParameters  = errors.New("export destination adapter parameters")
	ErrCombination = errors.New("export destination field combination")
)

// Validate checks an ordinary decoded JSON tree without changing or retaining it.
// Callers must own the tree for the duration of the call.
func Validate(resource any) error {
	p := preflight{bytes: 262144}
	if err := p.visit(resource, 0); err != nil {
		return err
	}
	r, ok := resource.(map[string]any)
	if !ok || !closed(r, "apiVersion", "kind", "metadata", "spec") || !required(r, "apiVersion", "kind", "metadata", "spec") || r["apiVersion"] != "ricevanta.io/v1alpha1" || r["kind"] != "ExportDestination" || !metadata(r["metadata"]) {
		return ErrResource
	}
	s, ok := r["spec"].(map[string]any)
	if !ok {
		return ErrResource
	}
	a, ok := s["type"].(string)
	if !ok || !adapterName(a) || !closed(s, "type", "enabled", "endpoint", "credentialRef", "tls", "filter", "projection", "repeats", "audit", "archive", "batch", "inflight", "elasticsearch", "opensearch", "splunk_hec", "syslog", "otlp", "loki", "sentinel", "kafka", "s3", "connector") || !required(s, a) {
		return ErrAdapter
	}
	for k := range s {
		if adapterName(k) && k != a {
			return ErrAdapter
		}
	}
	if !common(s) {
		return ErrCommon
	}
	if !parameters(a, s[a]) {
		return ErrParameters
	}
	if !combination(a, s) {
		return ErrCombination
	}
	return nil
}

type preflight struct{ nodes, bytes int }

func (p *preflight) charge(n int) bool {
	if n > p.bytes {
		return false
	}
	p.bytes -= n
	return true
}
func (p *preflight) visit(v any, depth int) error {
	p.nodes++
	if depth > 12 || p.nodes > 8192 {
		return ErrLimits
	}
	switch x := v.(type) {
	case nil, bool:
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return ErrInput
		}
	case string:
		if !p.charge(len(x)) {
			return ErrLimits
		}
		if !utf8.ValidString(x) {
			return ErrInput
		}
	case []any:
		if len(x) > 8192 {
			return ErrLimits
		}
		if x == nil {
			return ErrInput
		}
		for _, child := range x {
			if err := p.visit(child, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(x) > 8192 {
			return ErrLimits
		}
		if x == nil {
			return ErrInput
		}
		// Budget every key before UTF-8 scanning, allocating keys or sorting.
		for key := range x {
			if !p.charge(len(key)) {
				return ErrLimits
			}
		}
		for key := range x {
			if !utf8.ValidString(key) {
				return ErrInput
			}
		}
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := p.visit(x[key], depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInput
	}
	return nil
}

func adapterName(a string) bool {
	return oneOf(a, "elasticsearch", "opensearch", "splunk_hec", "syslog", "otlp", "loki", "sentinel", "kafka", "s3", "connector")
}
