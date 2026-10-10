package resourcevalidate

import (
	"regexp"
	"strings"
)

var (
	teamPattern         = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	guidPattern         = regexp.MustCompile(`^\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}$`)
	uninstallKeyPattern = regexp.MustCompile(`^[\x20-\x2e\x30-\x5b\x5d-\x7e]+$`)
)

func (c checker) source(v any) {
	m := c.tag(v, "type", "blob repository")
	if m == nil {
		return
	}
	if m["type"] == "blob" {
		c.obj(v, "type blobKey sha256 size", "")
		c.field(m, "blobKey", func(q checker, x any) { q.pattern(x, 1, 1024, blobPattern) })
		c.field(m, "sha256", func(q checker, x any) { q.hash(x) })
		c.field(m, "size", func(q checker, x any) { q.integer(x, 1, 9007199254740991) })
	} else {
		c.obj(v, "type manager ref package", "")
		c.field(m, "manager", func(q checker, x any) { q.enum(x, "apt dnf zypper flatpak homebrew winget") })
		c.field(m, "ref", func(q checker, x any) { q.name(x) })
		c.field(m, "package", func(q checker, x any) { q.packageName(x, 256) })
	}
}
func (c checker) signature(v any) {
	m := c.tag(v, "type", "developer-id authenticode msix openpgp checksum none")
	if m == nil {
		return
	}
	switch m["type"] {
	case "developer-id":
		c.obj(v, "type teamId", "")
		c.field(m, "teamId", func(q checker, x any) { q.pattern(x, 1, 10, teamPattern) })
	case "authenticode":
		c.obj(v, "type subject", "")
		c.field(m, "subject", func(q checker, x any) { q.text(x, 1, 1024, false) })
	case "msix":
		c.obj(v, "type publisher", "")
		c.field(m, "publisher", func(q checker, x any) { q.text(x, 1, 1024, false) })
	case "openpgp":
		c.obj(v, "type fingerprints", "")
		c.field(m, "fingerprints", func(q checker, x any) { q.array(x, 1, 16, true, func(r checker, x any) { r.fingerprint(x) }) })
	case "checksum":
		c.obj(v, "type sha256", "")
		c.field(m, "sha256", func(q checker, x any) { q.hash(x) })
	case "none":
		c.obj(v, "type reason allowUnsigned", "")
		c.field(m, "reason", func(q checker, x any) { q.text(x, 1, 1024, false) })
		c.field(m, "allowUnsigned", func(q checker, x any) { q.one(x, true) })
	}
}
func (c checker) detection(v any) {
	m := c.tag(v, "type", "bundle msi msix uninstall package")
	if m == nil {
		return
	}
	switch m["type"] {
	case "bundle":
		c.obj(v, "type identifier version", "")
		c.field(m, "identifier", func(q checker, x any) { q.identifier(x) })
	case "msi":
		c.obj(v, "type productCode", "")
		c.field(m, "productCode", func(q checker, x any) { q.pattern(x, 1, 38, guidPattern) })
	case "msix":
		c.obj(v, "type family version", "")
		c.field(m, "family", func(q checker, x any) { q.packageName(x, 255) })
	case "uninstall":
		c.obj(v, "type hive view key version", "")
		c.field(m, "hive", func(q checker, x any) { q.one(x, "HKLM") })
		c.field(m, "view", func(q checker, x any) { q.one(x, float64(32), float64(64)) })
		c.field(m, "key", func(q checker, x any) { q.pattern(x, 1, 256, uninstallKeyPattern) })
	case "package":
		c.obj(v, "type name version", "")
		c.field(m, "name", func(q checker, x any) { q.packageName(x, 256) })
	}
	if m["type"] != "msi" {
		c.field(m, "version", func(q checker, x any) { q.version(x) })
	}
}
func (c checker) software(v any) {
	m := c.obj(v, "os format name version source signature detection allowedGroups installArgs uninstallArgs reboot interaction", "retrySafe")
	if m == nil {
		return
	}
	c.field(m, "os", func(q checker, x any) { q.enum(x, "macos windows linux") })
	c.field(m, "format", func(q checker, x any) {
		q.enum(x, "pkg homebrew-formula homebrew-cask msi msix exe winget deb rpm flatpak")
	})
	c.field(m, "name", func(q checker, x any) { q.text(x, 1, 256, false) })
	c.field(m, "version", func(q checker, x any) {
		q.version(x)
		if x == "latest" {
			q.bad(6)
		}
	})
	c.field(m, "source", func(q checker, x any) { q.source(x) })
	c.field(m, "signature", func(q checker, x any) { q.signature(x) })
	c.field(m, "detection", func(q checker, x any) { q.detection(x) })
	c.field(m, "allowedGroups", func(q checker, x any) { q.groups(x) })
	for _, k := range []string{"installArgs", "uninstallArgs"} {
		c.field(m, k, func(q checker, x any) { q.array(x, 0, 64, false, func(r checker, x any) { r.text(x, 0, 4096, false) }) })
	}
	c.field(m, "retrySafe", func(q checker, x any) { q.boolean(x) })
	c.field(m, "reboot", func(q checker, x any) {
		a := q.tag(x, "mode", "none required exit-code")
		if a == nil {
			return
		}
		if a["mode"] != "exit-code" {
			q.obj(x, "mode", "")
			return
		}
		q.obj(x, "mode codes", "")
		q.field(a, "codes", func(r checker, x any) {
			r.array(x, 1, 32, false, func(r checker, x any) {
				b := r.obj(x, "code reboot", "")
				if b == nil {
					return
				}
				r.field(b, "code", func(t checker, x any) { t.integer(x, 0, 4294967295) })
				r.field(b, "reboot", func(t checker, x any) { t.boolean(x) })
			})
		})
	})
	c.field(m, "interaction", func(q checker, x any) {
		a := q.tag(x, "mode", "silent defer-while-running")
		if a == nil {
			return
		}
		if a["mode"] == "silent" {
			q.obj(x, "mode", "")
			return
		}
		q.obj(x, "mode processes", "")
		q.field(a, "processes", func(r checker, x any) { r.array(x, 1, 64, true, func(t checker, x any) { t.basename(x, 256) }) })
	})
	c.packageMatrix(m)
}

type packageRow struct{ os, format, source, manager, signatures, detection string }

var packageRows = []packageRow{
	{"macos", "pkg", "blob", "", "developer-id none", "bundle"},
	{"macos", "homebrew-formula", "repository", "homebrew", "checksum none", "package"},
	{"macos", "homebrew-cask", "repository", "homebrew", "checksum none", "bundle"},
	{"windows", "msi", "blob", "", "authenticode none", "msi"},
	{"windows", "msix", "blob", "", "msix none", "msix"},
	{"windows", "exe", "blob", "", "authenticode none", "uninstall"},
	{"windows", "winget", "repository", "winget", "authenticode none", "uninstall"},
	{"windows", "winget", "repository", "winget", "msix none", "msix"},
	{"linux", "deb", "blob", "", "none", "package"},
	{"linux", "deb", "repository", "apt", "openpgp none", "package"},
	{"linux", "rpm", "blob", "", "openpgp none", "package"},
	{"linux", "rpm", "repository", "dnf", "openpgp none", "package"},
	{"linux", "rpm", "repository", "zypper", "openpgp none", "package"},
	{"linux", "flatpak", "repository", "flatpak", "openpgp none", "package"},
}

func includes(list string, v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range strings.Fields(list) {
		if s == x {
			return true
		}
	}
	return false
}
func (c checker) packageMatrix(m map[string]any) {
	rows := packageRows
	// Discriminators narrow the allowed matrix before child checks. Nested tags
	// narrow only when at least one candidate matches, as in the published union.
	for _, tag := range []string{"os", "format"} {
		next := []packageRow{}
		for _, r := range rows {
			x := r.os
			if tag == "format" {
				x = r.format
			}
			if m[tag] == x {
				next = append(next, r)
			}
		}
		if len(next) == 0 {
			if _, ok := m[tag]; !ok {
				c.at(tag).bad(0)
			} else {
				c.at(tag).bad(3)
			}
			return
		}
		rows = next
	}
	for _, field := range []string{"source", "signature", "detection"} {
		a, ok := m[field].(map[string]any)
		if !ok {
			continue
		}
		tags := []string{"type"}
		if field == "source" {
			tags = append(tags, "manager")
		}
		for _, tag := range tags {
			next := []packageRow{}
			for _, r := range rows {
				match := false
				switch field {
				case "source":
					if tag == "type" {
						match = a[tag] == r.source
					} else {
						match = r.manager == "" || a[tag] == r.manager
					}
				case "signature":
					match = includes(r.signatures, a[tag])
				case "detection":
					match = a[tag] == r.detection
				}
				if match {
					next = append(next, r)
				}
			}
			if len(next) > 0 {
				rows = next
			}
		}
	}
	for _, r := range rows {
		for _, field := range []string{"source", "signature", "detection"} {
			a, ok := m[field].(map[string]any)
			if !ok {
				continue
			}
			if x, ok := a["type"]; ok {
				switch field {
				case "source":
					c.at(field).at("type").one(x, r.source)
				case "signature":
					c.at(field).at("type").enum(x, r.signatures)
				case "detection":
					c.at(field).at("type").one(x, r.detection)
				}
			}
			if field == "source" && r.manager != "" {
				if x, ok := a["manager"]; ok {
					c.at(field).at("manager").one(x, r.manager)
				}
			}
		}
		if r.format != "exe" {
			if _, ok := m["retrySafe"]; ok {
				c.at("retrySafe").bad(1)
			}
		}
	}
}
