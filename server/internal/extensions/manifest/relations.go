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
	names := make([]string, len(components))
	listing := make([]string, len(files))
	for i, v := range components {
		names[i] = v.(map[string]any)["name"].(string)
	}
	sortStrings(names)
	for i := 1; i < len(names); i++ {
		if names[i-1] == names[i] {
			return ErrDuplicate
		}
	}
	for i, v := range files {
		listing[i] = v.(map[string]any)["path"].(string)
	}
	sortStrings(listing)
	for i := 1; i < len(listing); i++ {
		if listing[i-1] == listing[i] {
			return ErrDuplicate
		}
	}
	for _, path := range listing {
		if !portable(path) || path == "extension.yaml" || strings.HasPrefix(path, "extension.yaml/") || path == "envelope.json" || strings.HasPrefix(path, "envelope.json/") {
			return ErrPath
		}
		for i := 0; i < len(path); i++ {
			if path[i] == '/' {
				if _, found := findString(listing, path[:i]); found {
					return ErrPath
				}
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
	owners := make([]byte, len(listing))
	for componentIndex, v := range components {
		c := v.(map[string]any)
		owner := byte(componentIndex + 1)
		for _, v := range c["files"].([]any) {
			p := v.(string)
			index, found := findString(listing, p)
			if !found || owners[index] != 0 || strings.HasPrefix(p, "attestations/") {
				return ErrReference
			}
			owners[index] = owner
		}
		for _, key := range []string{"file", "entry", "row_schema"} {
			if p, ok := c[key].(string); ok {
				index, found := findString(listing, p)
				if !found || owners[index] != owner {
					return ErrReference
				}
			}
		}
	}
	for i, p := range listing {
		if owners[i] == 0 && !strings.HasPrefix(p, "attestations/") {
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
