package manifest

import (
	"encoding/json"
	"regexp"
	"unicode/utf8"
)

// Rules encode the reviewed field inventory without a runtime schema interpreter.
type rule struct {
	typ      string
	props    map[string]*rule
	required []string
	item     *rule
	min, max uint64
	pattern  *regexp.Regexp
	values   []string
	branches []*rule
}

func str(min, max uint64, p string) *rule {
	r := &rule{typ: "string", min: min, max: max}
	if p != "" {
		r.pattern = regexp.MustCompile("^(?:" + p + ")$")
	}
	return r
}
func choices(v ...string) *rule { return &rule{typ: "string", values: v} }
func num(max uint64) *rule      { return &rule{typ: "number", min: 1, max: max} }
func array(min, max uint64, item *rule) *rule {
	return &rule{typ: "array", min: min, max: max, item: item}
}
func object(p map[string]*rule, required ...string) *rule {
	return &rule{typ: "object", props: p, required: required}
}

var (
	idRule        = str(3, 253, `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,15}`)
	pathRule      = str(1, 240, `[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*`)
	nameRule      = str(1, 63, `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`)
	digestRule    = str(64, 64, `[0-9a-f]{64}`)
	urlRule       = str(9, 2048, `https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?`)
	componentRule = &rule{typ: "branch"}
	rootRule      = inventory()
)

func inventory() *rule {
	osEntry := object(map[string]*rule{"policy_names": array(0, 64, str(1, 64, `[A-Za-z][A-Za-z0-9]{0,63}`)), "native_host": {typ: "bool"}}, "policy_names", "native_host")
	os := object(map[string]*rule{"macos": osEntry, "windows": osEntry, "linux": osEntry})
	os.min = 1
	agents := []string{"ricevanta:agent/classifier@1.0.0", "ricevanta:agent/parser@1.0.0", "ricevanta:agent/collector@1.0.0", "ricevanta:agent/responder@1.0.0"}
	connectors := []string{"ext.ricevanta.io/export-destination/v1", "ext.ricevanta.io/ca-connector/v1", "ext.ricevanta.io/notifier/v1", "ext.ricevanta.io/enricher/v1"}
	add := func(kind string, iface *rule, extra map[string]*rule, caps *rule) {
		p := map[string]*rule{"name": nameRule, "kind": choices(kind), "interface": iface, "files": array(1, 4096, pathRule), "capabilities": caps}
		req := []string{"name", "kind", "interface", "files", "capabilities"}
		for k, v := range extra {
			p[k] = v
			req = append(req, k)
		}
		componentRule.branches = append(componentRule.branches, object(p, req...))
	}
	add("content", choices("ext.ricevanta.io/content/v1"), map[string]*rule{"file": pathRule, "format": choices("sigma", "yara", "pii", "secrets", "dictionary", "fingerprint", "osquery", "falco", "classification", "baseline", "mdm-template", "report")}, object(map[string]*rule{}))
	add("browser-adapter", choices("ext.ricevanta.io/browser-adapter/v1"), map[string]*rule{"file": pathRule}, object(map[string]*rule{"registration": idRule, "os": os}, "registration", "os"))
	for i, iface := range agents {
		p := map[string]*rule{"memory_pages": num(4096), "fuel_per_call": num(1000000000), "deadline_ms": num(60000)}
		extra := map[string]*rule{"file": pathRule}
		switch i {
		case 1:
			p["mime_types"] = array(1, 32, str(3, 127, `[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*`))
		case 2:
			extra["row_schema"] = pathRule
			for k, v := range map[string]uint64{"max_roots": 16, "max_path_depth": 32, "max_directory_entries": 10000, "max_open_handles": 64, "max_list_requests": 1024, "max_read_requests": 4096, "max_bytes_per_file": 16777216, "max_input_bytes": 67108864, "max_rows": 10000, "max_output_bytes": 16777216} {
				p[k] = num(v)
			}
		case 3:
			p["actions"] = array(1, 9, choices("edr.kill_process", "edr.quarantine_file", "edr.restore_file", "edr.isolate_host", "edr.unisolate_host", "edr.kill_and_ban", "edr.unban", "edr.collect", "edr.scan"))
			for k, v := range map[string]uint64{"max_entities": 256, "max_parameters_bytes": 65536, "max_plan_steps": 256, "max_plan_bytes": 1048576} {
				p[k] = num(v)
			}
		}
		req := []string{}
		for k := range p {
			req = append(req, k)
		}
		add("agent-module", choices(iface), extra, object(p, req...))
	}
	add("console-module", choices("ext.ricevanta.io/console-module/v1"), map[string]*rule{"entry": pathRule, "bridge": choices("ext.ricevanta.io/console-bridge/v1"), "slots": array(1, 6, choices("navigation", "device-tab", "alert-panel", "finding-panel", "dashboard-panel", "settings"))}, object(map[string]*rule{"operations": array(0, 23, choices("listDevices", "getDevice", "getDeviceInventory", "listDeviceSoftware", "getDeviceCapabilities", "getDevicePolicyState", "getDeviceFootprint", "listComplianceResults", "listAlerts", "getAlert", "listInvestigations", "listResponseActions", "listDlpFindings", "getDlpFinding", "listClassifications", "listExceptions", "queryLineage", "getLineageEdge", "updateAlert", "createInvestigation", "updateInvestigation", "updateDlpFinding", "createResponseAction"))}, "operations"))
	host := str(3, 253, `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+`)
	add("service-connector", choices(connectors...), map[string]*rule{"file": pathRule}, object(map[string]*rule{"outbound": array(0, 64, object(map[string]*rule{"host": host, "port": num(65535), "transport": choices("tcp", "udp")}, "host", "port", "transport"))}, "outbound"))
	requires := object(map[string]*rule{"content": array(1, 1, choices("ext.ricevanta.io/content/v1")), "browser-adapter": array(1, 1, choices("ext.ricevanta.io/browser-adapter/v1")), "agent-module": array(1, 4, choices(agents...)), "console-module": array(1, 1, choices("ext.ricevanta.io/console-module/v1")), "service-connector": array(1, 4, choices(connectors...))})
	requires.min = 1
	metadata := object(map[string]*rule{"id": idRule, "version": str(5, 128, `(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[a-z-][0-9a-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-z-][0-9a-z-]*))*)?`), "publisher": object(map[string]*rule{"name": str(1, 128, `[^\x{0000}-\x{001f}\x{007f}-\x{009f}]+`), "key": str(71, 71, `sha256:[0-9a-f]{64}`)}, "name", "key"), "license": str(1, 256, `[A-Za-z0-9.():+ -]+`), "source": urlRule, "homepage": urlRule}, "id", "version", "publisher", "license", "source")
	return object(map[string]*rule{"apiVersion": choices("ricevanta.io/v1alpha1"), "kind": choices("Extension"), "metadata": metadata, "spec": object(map[string]*rule{"requires": requires, "components": array(1, 64, componentRule)}, "requires", "components"), "files": array(1, 4096, object(map[string]*rule{"path": pathRule, "sha256": digestRule, "size": {typ: "number", max: HardMaxTotalFileBytes}}, "path", "sha256", "size"))}, "apiVersion", "kind", "metadata", "spec", "files")
}
func branch(v any, r *rule) *rule {
	if r.typ != "branch" {
		return r
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	kind, ok := m["kind"].(string)
	if !ok {
		return nil
	}
	iface, ok := m["interface"].(string)
	if !ok {
		return nil
	}
	for _, b := range r.branches {
		if kind == b.props["kind"].values[0] && (kind != "agent-module" || iface == b.props["interface"].values[0]) {
			return b
		}
	}
	return nil
}
func shape(v any, r *rule) bool {
	r = branch(v, r)
	if r == nil {
		return false
	}
	switch r.typ {
	case "object":
		x, ok := v.(map[string]any)
		if !ok {
			return false
		}
		for _, k := range r.required {
			if _, ok := x[k]; !ok {
				return false
			}
		}
		for k, v := range x {
			p := r.props[k]
			if p == nil || !shape(v, p) {
				return false
			}
		}
	case "array":
		x, ok := v.([]any)
		if !ok {
			return false
		}
		for _, v := range x {
			if !shape(v, r.item) {
				return false
			}
		}
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "bool":
		_, ok := v.(bool)
		return ok
	}
	return true
}
func fields(v any, r *rule) bool {
	r = branch(v, r)
	switch r.typ {
	case "object":
		x := v.(map[string]any)
		if uint64(len(x)) < r.min {
			return false
		}
		for k, v := range x {
			if !fields(v, r.props[k]) {
				return false
			}
		}
	case "array":
		x := v.([]any)
		if uint64(len(x)) < r.min || uint64(len(x)) > r.max {
			return false
		}
		seen := make(map[string]bool, len(x))
		for _, v := range x {
			s := encoding(v)
			if seen[s] || !fields(v, r.item) {
				return false
			}
			seen[s] = true
		}
	case "number":
		n := unsigned(v)
		return n >= r.min && n <= r.max
	case "string":
		s := v.(string)
		if len(r.values) > 0 {
			for _, value := range r.values {
				if s == value {
					return true
				}
			}
			return false
		}
		n := uint64(utf8.RuneCountInString(s))
		return n >= r.min && n <= r.max && (r.pattern == nil || r.pattern.MatchString(s))
	}
	return true
}
