package loader

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// schemaReference evaluates the manifest schema's used keywords directly. It
// does not import manifest's field inventory or any candidate parser checks.
type schemaReference struct {
	Root     map[string]any
	Patterns map[string]*regexp.Regexp
}

func (v *schemaReference) valid(value any, r map[string]any) bool {
	if ref, ok := r["$ref"].(string); ok {
		var target any = v.Root
		for _, key := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			target = target.(map[string]any)[key]
		}
		return v.valid(value, target.(map[string]any))
	}
	if branches, ok := r["oneOf"].([]any); ok {
		matches := 0
		for _, b := range branches {
			if v.valid(value, b.(map[string]any)) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	if c, ok := r["const"]; ok && !reflect.DeepEqual(value, c) {
		return false
	}
	if enum, ok := r["enum"].([]any); ok {
		match := false
		for _, c := range enum {
			match = match || reflect.DeepEqual(value, c)
		}
		if !match {
			return false
		}
	}
	switch r["type"] {
	case "object":
		m, ok := value.(map[string]any)
		if !ok {
			return false
		}
		if !schemaRange(len(m), r, "minProperties", "maxProperties") {
			return false
		}
		required, _ := r["required"].([]any)
		for _, key := range required {
			if _, ok := m[key.(string)]; !ok {
				return false
			}
		}
		props, _ := r["properties"].(map[string]any)
		for key, c := range m {
			rule, ok := props[key]
			if !ok {
				if r["additionalProperties"] == false {
					return false
				}
				continue
			}
			if !v.valid(c, rule.(map[string]any)) {
				return false
			}
		}
	case "array":
		a, ok := value.([]any)
		if !ok || !schemaRange(len(a), r, "minItems", "maxItems") {
			return false
		}
		seen := make(map[string]bool)
		for _, c := range a {
			if r["uniqueItems"] == true {
				b, err := json.Marshal(c)
				if err != nil {
					return false
				}
				key := string(b)
				if seen[key] {
					return false
				}
				seen[key] = true
			}
			if item, ok := r["items"].(map[string]any); ok && !v.valid(c, item) {
				return false
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok || !schemaRange(utf8.RuneCountInString(s), r, "minLength", "maxLength") {
			return false
		}
		if pattern, ok := r["pattern"].(string); ok {
			re := v.Patterns[pattern]
			if re == nil {
				// The schema's final negative lookahead makes ECMAScript '$' strict.
				// Go's '$' already requires the absolute end of the input.
				goPattern := strings.TrimSuffix(pattern, `(?![\s\S])`)
				unicodeEscape := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
				goPattern = unicodeEscape.ReplaceAllString(goPattern, `\x{$1}`)
				var err error
				re, err = regexp.Compile(goPattern)
				if err != nil {
					panic(fmt.Sprintf("unhandled schema pattern: %v", err))
				}
				v.Patterns[pattern] = re
			}
			if !re.MatchString(s) {
				return false
			}
		}
	case "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		i, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil {
			return false
		}
		if min, ok := r["minimum"].(float64); ok && float64(i) < min {
			return false
		}
		if max, ok := r["maximum"].(float64); ok && float64(i) > max {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	case nil:
	default:
		panic("unhandled schema type")
	}
	return true
}
func schemaRange(n int, r map[string]any, minKey, maxKey string) bool {
	if min, ok := r[minKey].(float64); ok && n < int(min) {
		return false
	}
	if max, ok := r[maxKey].(float64); ok && n > int(max) {
		return false
	}
	return true
}
