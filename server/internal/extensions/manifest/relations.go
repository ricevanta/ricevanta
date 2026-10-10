package manifest

import "strings"

func relations(document map[string]any, options Options) error {
	metadata := document["metadata"].(map[string]any)
	id := metadata["id"].(string)
	if !options.AllowReservedID && (id == "io.ricevanta" || strings.HasPrefix(id, "io.ricevanta.")) {
		return ErrReserved
	}
	spec := document["spec"].(map[string]any)
	components := spec["components"].([]any)
	files := document["files"].([]any)
	names := make(map[string]bool, len(components))
	listing := make(map[string]bool, len(files))
	for _, v := range components {
		name := v.(map[string]any)["name"].(string)
		if names[name] {
			return ErrDuplicate
		}
		names[name] = true
	}
	for _, v := range files {
		path := v.(map[string]any)["path"].(string)
		if listing[path] {
			return ErrDuplicate
		}
		listing[path] = true
	}
	for path := range listing {
		if !portable(path) || path == "extension.yaml" || strings.HasPrefix(path, "extension.yaml/") || path == "envelope.json" || strings.HasPrefix(path, "envelope.json/") {
			return ErrPath
		}
		for i := 0; i < len(path); i++ {
			if path[i] == '/' && listing[path[:i]] {
				return ErrPath
			}
		}
	}
	for _, v := range components {
		c := v.(map[string]any)
		for _, p := range c["files"].([]any) {
			if !portable(p.(string)) {
				return ErrPath
			}
		}
		for _, key := range []string{"file", "entry", "row_schema"} {
			if p, ok := c[key].(string); ok && !portable(p) {
				return ErrPath
			}
		}
	}
	ceiling := options.MaxTotalFileBytes
	if ceiling == 0 {
		ceiling = DefaultMaxTotalFileBytes
	}
	var total uint64
	for _, v := range files {
		size := unsigned(v.(map[string]any)["size"])
		if size > ceiling-total {
			return ErrLimit
		}
		total += size
	}
	used := make(map[string]map[string]bool)
	for _, v := range components {
		c := v.(map[string]any)
		kind := c["kind"].(string)
		if used[kind] == nil {
			used[kind] = make(map[string]bool)
		}
		used[kind][c["interface"].(string)] = true
	}
	requires := spec["requires"].(map[string]any)
	if len(used) != len(requires) {
		return ErrRequires
	}
	for kind, interfaces := range used {
		v, ok := requires[kind]
		if !ok {
			return ErrRequires
		}
		a := v.([]any)
		if len(a) != len(interfaces) {
			return ErrRequires
		}
		for _, v := range a {
			if !interfaces[v.(string)] {
				return ErrRequires
			}
		}
	}
	owners := make(map[string]bool, len(files))
	for _, v := range components {
		c := v.(map[string]any)
		own := make(map[string]bool)
		for _, v := range c["files"].([]any) {
			p := v.(string)
			if !listing[p] || owners[p] || strings.HasPrefix(p, "attestations/") {
				return ErrReference
			}
			own[p] = true
			owners[p] = true
		}
		for _, key := range []string{"file", "entry", "row_schema"} {
			if p, ok := c[key].(string); ok && !own[p] {
				return ErrReference
			}
		}
	}
	for p := range listing {
		if !owners[p] && !strings.HasPrefix(p, "attestations/") {
			return ErrReference
		}
	}
	for _, v := range components {
		c := v.(map[string]any)
		if c["interface"] == "ricevanta:agent/collector@1.0.0" {
			caps := c["capabilities"].(map[string]any)
			if unsigned(caps["max_bytes_per_file"]) > unsigned(caps["max_input_bytes"]) || unsigned(caps["max_open_handles"]) > unsigned(caps["max_read_requests"]) {
				return ErrCapability
			}
		}
	}
	return nil
}
func portable(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if len(segment) > 63 || strings.HasSuffix(segment, ".") {
			return false
		}
		stem, _, _ := strings.Cut(segment, ".")
		switch stem {
		case "con", "prn", "aux", "nul":
			return false
		}
		if len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9' {
			return false
		}
	}
	return true
}
