package admission

import (
	"encoding/json"
	"sort"
	"strconv"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

// FromPackage projects a loader result into typed evidence. It validates the
// decoded document with reserved ids allowed (namespace authority is the
// namespace stage's), binds the loader's fingerprint to the document and
// requires nonzero digests. It never reads the archive, file bytes or envelope.
func FromPackage(p loader.Package, options manifest.Options) (Evidence, error) {
	options.AllowReservedID = true
	if p.Document == nil || manifest.Validate(p.Document, options) != nil {
		return Evidence{}, ErrEvidence
	}
	var zero [32]byte
	if p.PackageSHA256 == zero || p.ManifestSHA256 == zero || p.EnvelopeSHA256 == zero {
		return Evidence{}, ErrEvidence
	}
	metadata := p.Document["metadata"].(map[string]any)
	if p.PublisherFingerprint != metadata["publisher"].(map[string]any)["key"].(string) {
		return Evidence{}, ErrEvidence
	}
	spec := p.Document["spec"].(map[string]any)
	e := Evidence{
		ID:                   metadata["id"].(string),
		Version:              metadata["version"].(string),
		PublisherFingerprint: p.PublisherFingerprint,
		PackageSHA256:        p.PackageSHA256,
		ManifestSHA256:       p.ManifestSHA256,
		EnvelopeSHA256:       p.EnvelopeSHA256,
		Requires:             map[string][]string{},
	}
	for kind, v := range spec["requires"].(map[string]any) {
		e.Requires[kind] = documentStrings(v)
	}
	for _, v := range spec["components"].([]any) {
		e.Components = append(e.Components, projectComponent(v.(map[string]any)))
	}
	sort.Slice(e.Components, func(i, j int) bool { return e.Components[i].Name < e.Components[j].Name })
	if !checkEvidence(&e) {
		return Evidence{}, ErrEvidence
	}
	return e, nil
}

func documentStrings(v any) []string {
	items := v.([]any)
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.(string)
	}
	return out
}

func documentNumber(v any) uint64 {
	n, _ := strconv.ParseUint(string(v.(json.Number)), 10, 64)
	return n
}

// projectComponent copies a validated manifest component into grant-value
// shape. Manifest validation fixed every type asserted here.
func projectComponent(m map[string]any) Component {
	c := Component{Name: m["name"].(string), Kind: m["kind"].(string), Interface: m["interface"].(string)}
	if f, ok := m["format"].(string); ok {
		c.Format = f
	}
	caps := m["capabilities"].(map[string]any)
	switch c.Kind {
	case kindContent:
		c.Requested.Content = &struct{}{}
	case kindBrowserAdapter:
		b := &BrowserAdapterValues{Registration: caps["registration"].(string)}
		for name, v := range caps["os"].(map[string]any) {
			entry := v.(map[string]any)
			policy := &OSPolicy{PolicyNames: documentStrings(entry["policy_names"]), NativeHost: entry["native_host"].(bool)}
			switch name {
			case "macos":
				b.OS.MacOS = policy
			case "windows":
				b.OS.Windows = policy
			case "linux":
				b.OS.Linux = policy
			}
		}
		c.Requested.BrowserAdapter = b
	case kindAgentModule:
		a := &AgentModuleValues{}
		for _, f := range numericFields(c.Interface) {
			*f.get(a) = documentNumber(caps[f.name])
		}
		switch c.Interface {
		case ifaceParser:
			a.MIMETypes = documentStrings(caps["mime_types"])
		case ifaceResponder:
			a.Actions = documentStrings(caps["actions"])
		}
		c.Requested.AgentModule = a
	case kindConsoleModule:
		c.Slots = documentStrings(m["slots"])
		operations := documentStrings(caps["operations"])
		slots := make(map[string][]string, len(c.Slots))
		for _, s := range c.Slots {
			slots[s] = append([]string{}, operations...)
		}
		c.Requested.ConsoleModule = &ConsoleModuleValues{Slots: slots}
	case kindServiceConnector:
		var out []Outbound
		for _, v := range caps["outbound"].([]any) {
			o := v.(map[string]any)
			out = append(out, Outbound{Host: o["host"].(string), Port: documentNumber(o["port"]), Transport: o["transport"].(string)})
		}
		c.Requested.ServiceConnector = &ServiceConnectorValues{Outbound: out}
	}
	return c
}

// checkEvidence repeats FromPackage's cheap checks on typed evidence, so a
// hand-built value cannot skip them (input.evidence).
func checkEvidence(e *Evidence) bool {
	var zero [32]byte
	if e.PackageSHA256 == zero || e.ManifestSHA256 == zero || e.EnvelopeSHA256 == zero {
		return false
	}
	if !validID(e.ID) || !validVersion(e.Version) || !validFingerprint(e.PublisherFingerprint) {
		return false
	}
	if len(e.Components) < 1 || len(e.Components) > 64 {
		return false
	}
	used := map[string]map[string]bool{}
	for i := range e.Components {
		c := &e.Components[i]
		if !validName(c.Name) || i > 0 && e.Components[i-1].Name >= c.Name {
			return false
		}
		if !definedPair(c.Kind, c.Interface) || !valuesAgree(c.Kind, c.Interface, &c.Requested) {
			return false
		}
		if used[c.Kind] == nil {
			used[c.Kind] = map[string]bool{}
		}
		used[c.Kind][c.Interface] = true
	}
	if len(used) != len(e.Requires) {
		return false
	}
	for kind, interfaces := range e.Requires {
		want := used[kind]
		if want == nil || len(interfaces) != len(want) || !uniqueStrings(interfaces) {
			return false
		}
		for _, iface := range interfaces {
			if !want[iface] {
				return false
			}
		}
	}
	return true
}
