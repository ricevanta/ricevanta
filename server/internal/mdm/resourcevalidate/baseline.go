package resourcevalidate

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// kindClass is closed: the OS prefix is empty for all-platform kinds.
func kindClass(kind string) (os string, apply bool) {
	switch kind {
	case "apple.declaration", "apple.profile":
		return "macos", true
	case "windows.csp", "windows.registry", "windows.service":
		return "windows", true
	case "linux.dconf", "linux.polkit", "linux.sysctl", "linux.systemd", "linux.pam", "linux.file", "linux.repository":
		return "linux", true
	case "software", "os_update", "encryption":
		return "", true
	case "check.query", "check.collector":
		return "", false
	}
	return "", false
}
func knownKind(kind string) bool {
	switch kind {
	case "apple.declaration", "apple.profile", "windows.csp", "windows.registry", "windows.service", "linux.dconf", "linux.polkit", "linux.sysctl", "linux.systemd", "linux.pam", "linux.file", "linux.repository", "software", "check.query", "check.collector", "os_update", "encryption":
		return true
	}
	return false
}
func (c checker) baseline(v any) {
	s := c.obj(v, "os items", "allowedGroups minOsVersion")
	if s == nil {
		return
	}
	c.field(s, "os", func(q checker, x any) { q.enum(x, "macos windows linux") })
	os, _ := s["os"].(string)
	c.field(s, "allowedGroups", func(q checker, x any) { q.groups(x) })
	c.field(s, "minOsVersion", func(q checker, x any) { q.version(x) })
	c.field(s, "items", func(q checker, x any) {
		q.array(x, 1, 2000, false, func(q checker, x any) {
			m := q.obj(x, "id kind settings required severity", "grace authority references")
			if m == nil {
				return
			}
			kind, _ := m["kind"].(string)
			q.field(m, "id", func(r checker, x any) { r.name(x) })
			q.field(m, "kind", func(r checker, x any) {
				k, ok := x.(string)
				if !ok || !knownKind(k) {
					r.bad(3)
					return
				}
				nativeOS, _ := kindClass(k)
				if nativeOS != "" && includes("macos windows linux", os) && nativeOS != os {
					r.bad(3)
				}
			})
			q.field(m, "required", func(r checker, x any) { r.boolean(x) })
			q.field(m, "severity", func(r checker, x any) { r.enum(x, "informational low medium high critical") })
			q.field(m, "grace", func(r checker, x any) { r.duration(x) })
			q.field(m, "authority", func(r checker, x any) {
				r.enum(x, "native agent")
				switch {
				case kind == "apple.declaration" || kind == "apple.profile":
					r.one(x, "native")
				case kind == "windows.csp":
				case kind == "os_update" || kind == "encryption":
					if os == "macos" {
						r.one(x, "native")
					} else if os == "linux" || os == "windows" {
						r.one(x, "agent")
					}
				case knownKind(kind):
					r.one(x, "agent")
				}
			})
			q.field(m, "references", func(r checker, x any) {
				r.array(x, 0, 16, false, func(r checker, x any) {
					a := r.obj(x, "framework id", "document version")
					if a == nil {
						return
					}
					for _, k := range []string{"framework", "id", "document", "version"} {
						r.field(a, k, func(t checker, x any) {
							n := 128
							if k == "framework" || k == "version" {
								n = 64
							}
							t.text(x, 1, n, false)
						})
					}
				})
			})
			if knownKind(kind) {
				q.field(m, "settings", func(r checker, x any) { r.settings(kind, x) })
			}
		})
	})
	_, has := s["allowedGroups"]
	// JSON Schema's contains applies only to arrays. A missing or nonarray
	// items value satisfies the conditional, while an empty check array
	// satisfies the else branch. Preserve those diagnostics before rejection.
	apply, checksOnly := false, false
	items, array := s["items"].([]any)
	if !array {
		apply = true
	} else {
		checksOnly = true
		for _, value := range items {
			m, object := value.(map[string]any)
			if !object {
				apply = true
				checksOnly = false
				continue
			}
			kind, _ := m["kind"].(string)
			_, capable := kindClass(kind)
			apply = apply || capable
			checksOnly = checksOnly && (kind == "check.query" || kind == "check.collector")
		}
	}
	if apply && !has {
		c.at("allowedGroups").bad(0)
	}
	if !apply && checksOnly && has {
		c.at("allowedGroups").bad(1)
	}
}

var (
	cspPattern       = regexp.MustCompile(`^\./(?:Device|User)/Vendor/MSFT/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)
	registryPattern  = regexp.MustCompile(`^[\x20-\x2e\x30-\x5b\x5d-\x7e]+(?:\\[\x20-\x2e\x30-\x5b\x5d-\x7e]+)*$`)
	accountPattern   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	sysctlPattern    = regexp.MustCompile(`^[a-z0-9_]+(?:\.[a-z0-9_-]+)+$`)
	unitPattern      = regexp.MustCompile(`^[A-Za-z0-9_:@.-]+\.(?:service|socket|timer|target|path|mount|automount|swap|slice)$`)
	directivePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	collectorPattern = regexp.MustCompile(`^ext/[a-z0-9][a-z0-9.-]*/[a-z0-9][a-z0-9_-]*$`)
	qwordPattern     = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,19})$`)
	timezonePattern  = regexp.MustCompile(`^(?:device|UTC|[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+)$`)
	clockPattern     = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
)

func (c checker) tag(v any, tag, choices string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		c.bad(2)
		return nil
	}
	x, ok := m[tag]
	if !ok {
		c.at(tag).bad(0)
		return nil
	}
	if !c.at(tag).enum(x, choices) {
		return nil
	}
	return m
}
func (c checker) settings(kind string, v any) {
	switch kind {
	case "apple.declaration":
		m := c.obj(v, "identifier type payload", "")
		if m == nil {
			return
		}
		c.field(m, "identifier", func(q checker, x any) { q.identifier(x) })
		c.field(m, "type", func(q checker, x any) { q.pattern(x, 1, 255, appleTypePattern) })
		c.field(m, "payload", func(q checker, x any) { q.nativeObject(x) })
	case "apple.profile":
		m := c.obj(v, "identifier payloads", "")
		if m == nil {
			return
		}
		c.field(m, "identifier", func(q checker, x any) { q.identifier(x) })
		c.field(m, "payloads", func(q checker, x any) {
			q.array(x, 1, 64, false, func(q checker, x any) {
				q.nativeObject(x)
				a, ok := x.(map[string]any)
				if !ok {
					return
				}
				for _, k := range []string{"PayloadIdentifier", "PayloadType"} {
					if _, ok := a[k]; !ok {
						q.at(k).bad(0)
					}
				}
				q.field(a, "PayloadIdentifier", func(r checker, x any) { r.identifier(x) })
				q.field(a, "PayloadType", func(r checker, x any) {
					r.pattern(x, 1, 255, appleTypePattern)
					if x == "com.apple.mdm" || x == "com.apple.security.scep" || x == "com.apple.security.pkcs12" {
						r.bad(6)
					}
				})
			})
		})
	case "windows.csp":
		m := c.tag(v, "format", "int bool chr xml b64")
		if m == nil {
			return
		}
		c.obj(v, "locUri format value", "")
		c.field(m, "locUri", func(q checker, x any) { q.pattern(x, 1, 2048, cspPattern) })
		c.field(m, "value", func(q checker, x any) {
			switch m["format"] {
			case "int":
				q.integer(x, -2147483648, 2147483647)
			case "bool":
				q.boolean(x)
			case "chr":
				q.text(x, 0, 16384, false)
			case "xml":
				q.text(x, 1, 16384, true)
			case "b64":
				q.pattern(x, 4, 16384, base64Pattern)
			}
		})
	case "windows.registry":
		m := c.tag(v, "type", "string expand-string multi-string dword qword binary")
		if m == nil {
			return
		}
		c.obj(v, "hive view key name type value", "")
		c.field(m, "hive", func(q checker, x any) { q.one(x, "HKLM") })
		c.field(m, "view", func(q checker, x any) { q.one(x, float64(32), float64(64)) })
		c.field(m, "key", func(q checker, x any) { q.pattern(x, 1, 1024, registryPattern) })
		c.field(m, "name", func(q checker, x any) { q.text(x, 0, 256, false) })
		c.field(m, "value", func(q checker, x any) {
			switch m["type"] {
			case "string", "expand-string":
				q.text(x, 0, 16384, false)
			case "multi-string":
				q.array(x, 0, 256, false, func(r checker, x any) { r.text(x, 0, 1024, false) })
			case "dword":
				q.integer(x, 0, 4294967295)
			case "qword":
				q.pattern(x, 1, 20, qwordPattern)
			case "binary":
				q.pattern(x, 0, 16384, base64Pattern)
			}
		})
	case "windows.service":
		m := c.obj(v, "name startType state", "")
		if m == nil {
			return
		}
		c.field(m, "name", func(q checker, x any) { q.basename(x, 256) })
		c.field(m, "startType", func(q checker, x any) { q.enum(x, "automatic automatic-delayed manual disabled") })
		c.field(m, "state", func(q checker, x any) { q.enum(x, "running stopped") })
	case "linux.dconf":
		m := c.obj(v, "key value locked", "")
		if m == nil {
			return
		}
		c.field(m, "key", func(q checker, x any) { q.pattern(x, 2, 4096, posixPattern) })
		c.field(m, "value", func(q checker, x any) { q.text(x, 0, 16384, false) })
		c.field(m, "locked", func(q checker, x any) { q.boolean(x) })
	case "linux.polkit":
		m := c.obj(v, "rules", "")
		if m == nil {
			return
		}
		c.field(m, "rules", func(q checker, x any) { q.text(x, 1, 16384, true) })
	case "linux.sysctl":
		m := c.obj(v, "key value", "")
		if m == nil {
			return
		}
		c.field(m, "key", func(q checker, x any) { q.pattern(x, 1, 255, sysctlPattern) })
		c.field(m, "value", func(q checker, x any) { q.text(x, 1, 1024, false) })
	case "linux.systemd":
		c.systemd(v)
	case "linux.pam":
		c.pam(v)
	case "linux.file":
		m := c.obj(v, "path content mode owner group", "")
		if m == nil {
			return
		}
		c.field(m, "path", func(q checker, x any) { q.pattern(x, 2, 4096, posixPattern) })
		c.field(m, "content", func(q checker, x any) { q.text(x, 0, 16384, true) })
		c.field(m, "mode", func(q checker, x any) { q.enum(x, "0400 0440 0444 0600 0640 0644") })
		for _, k := range []string{"owner", "group"} {
			c.field(m, k, func(q checker, x any) { q.pattern(x, 1, 32, accountPattern) })
		}
	case "linux.repository":
		c.repository(v)
	case "software":
		m := c.obj(v, "package ensure", "removeOnUnassign")
		if m == nil {
			return
		}
		c.field(m, "package", func(q checker, x any) { q.name(x) })
		c.field(m, "ensure", func(q checker, x any) { q.enum(x, "present absent latest") })
		c.field(m, "removeOnUnassign", func(q checker, x any) { q.boolean(x) })
	case "check.query":
		m := c.obj(v, "query expect", "")
		if m == nil {
			return
		}
		for _, k := range []string{"query", "expect"} {
			c.field(m, k, func(q checker, x any) { q.text(x, 1, 4096, true) })
		}
	case "check.collector":
		m := c.obj(v, "ref expect", "input")
		if m == nil {
			return
		}
		c.field(m, "ref", func(q checker, x any) { q.pattern(x, 1, 256, collectorPattern) })
		c.field(m, "expect", func(q checker, x any) { q.text(x, 1, 4096, true) })
		c.field(m, "input", func(q checker, x any) { q.nativeObject(x) })
	case "os_update":
		c.update(v)
	case "encryption":
		m := c.tag(v, "platform", "macos windows linux")
		if m == nil {
			return
		}
		required := "platform enabled escrow"
		if m["platform"] == "linux" {
			required += " existingLuks2Root tpm2"
		}
		c.obj(v, required, "")
		for _, k := range strings.Fields(required) {
			if k != "platform" {
				c.field(m, k, func(q checker, x any) { q.one(x, true) })
			}
		}
	}
}
func (c checker) systemd(v any) {
	m := c.obj(v, "unit", "state dropIn")
	if m == nil {
		return
	}
	c.field(m, "unit", func(q checker, x any) {
		s := q.text(x, 1, 255, false)
		if !unitPattern.MatchString(s) || strings.HasPrefix(s, ".") || strings.Contains(s, "..") || strings.Count(s, "@") > 1 || strings.Contains(s, "@.") {
			q.bad(5)
		}
	})
	c.field(m, "state", func(q checker, x any) { q.enum(x, "enabled disabled masked") })
	if _, a := m["state"]; !a {
		if _, b := m["dropIn"]; !b {
			c.at("dropIn").bad(0)
			c.at("state").bad(0)
		}
	}
	c.field(m, "dropIn", func(q checker, x any) {
		a := q.obj(x, "name sections", "")
		if a == nil {
			return
		}
		q.field(a, "name", func(r checker, x any) { r.name(x) })
		q.field(a, "sections", func(r checker, x any) {
			r.array(x, 1, 8, false, func(r checker, x any) {
				b := r.obj(x, "name directives", "")
				if b == nil {
					return
				}
				r.field(b, "name", func(t checker, x any) { t.enum(x, "Unit Service Socket Timer Path Mount Automount Swap Slice Install") })
				r.field(b, "directives", func(t checker, x any) {
					t.array(x, 1, 128, false, func(t checker, x any) {
						d := t.obj(x, "name value", "")
						if d == nil {
							return
						}
						t.field(d, "name", func(u checker, x any) { u.pattern(x, 1, 64, directivePattern) })
						t.field(d, "value", func(u checker, x any) {
							s := u.text(x, 0, 4096, false)
							if strings.HasSuffix(s, "\\") {
								u.bad(5)
							}
						})
					})
				})
			})
		})
	})
}
func (c checker) pam(v any) {
	m := c.obj(v, "", "pwquality faillock")
	if m == nil {
		return
	}
	c.nonempty(m)
	c.field(m, "pwquality", func(q checker, x any) {
		a := q.obj(x, "", "minlen minclass maxrepeat enforceForRoot")
		if a == nil {
			return
		}
		q.nonempty(a)
		q.field(a, "minlen", func(r checker, x any) { r.integer(x, 6, 128) })
		q.field(a, "minclass", func(r checker, x any) { r.integer(x, 0, 4) })
		q.field(a, "maxrepeat", func(r checker, x any) { r.integer(x, 0, 128) })
		q.field(a, "enforceForRoot", func(r checker, x any) { r.boolean(x) })
	})
	c.field(m, "faillock", func(q checker, x any) {
		a := q.obj(x, "", "deny failIntervalSeconds unlockTimeSeconds evenDenyRoot rootUnlockTimeSeconds")
		if a == nil {
			return
		}
		q.nonempty(a)
		q.field(a, "deny", func(r checker, x any) { r.integer(x, 1, 100) })
		q.field(a, "failIntervalSeconds", func(r checker, x any) { r.integer(x, 1, 86400) })
		q.field(a, "unlockTimeSeconds", func(r checker, x any) { r.integer(x, 0, 604800) })
		q.field(a, "evenDenyRoot", func(r checker, x any) { r.boolean(x) })
		q.field(a, "rootUnlockTimeSeconds", func(r checker, x any) { r.integer(x, 1, 604800) })
		if a["evenDenyRoot"] == true {
			if _, ok := a["rootUnlockTimeSeconds"]; !ok {
				q.at("rootUnlockTimeSeconds").bad(0)
			}
		}
	})
}
func (c checker) repository(v any) {
	m := c.obj(v, "manager name url key", "suite components")
	if m == nil {
		return
	}
	c.field(m, "manager", func(q checker, x any) { q.enum(x, "apt dnf zypper flatpak") })
	c.field(m, "name", func(q checker, x any) { q.name(x) })
	c.field(m, "url", func(q checker, x any) {
		s := q.text(x, 1, 2048, false)
		if !strings.HasPrefix(s, "https://") || len(s) <= 8 || strings.ContainsAny(s, "\\#") || strings.ContainsFunc(s, unicode.IsSpace) {
			q.bad(5)
		}
	})
	c.field(m, "key", func(q checker, x any) {
		a := q.obj(x, "sha256 fingerprint", "")
		if a == nil {
			return
		}
		q.field(a, "sha256", func(r checker, x any) { r.hash(x) })
		q.field(a, "fingerprint", func(r checker, x any) { r.fingerprint(x) })
	})
	c.field(m, "suite", func(q checker, x any) { q.text(x, 1, 128, false) })
	c.field(m, "components", func(q checker, x any) { q.array(x, 1, 32, true, func(r checker, x any) { r.text(x, 1, 64, false) }) })
	for _, k := range []string{"suite", "components"} {
		_, has := m[k]
		switch m["manager"] {
		case "apt":
			if !has {
				c.at(k).bad(0)
			}
		case "dnf", "zypper", "flatpak":
			if has {
				c.at(k).bad(1)
			}
		}
	}
}
func (c checker) update(v any) {
	m := c.tag(v, "platform", "macos windows linux")
	if m == nil {
		return
	}
	required := "platform maintenance reboot"
	optional := ""
	switch m["platform"] {
	case "macos":
		required += " targetVersion deferrals automaticDownload automaticInstall notifications"
		optional = "targetBuild"
	case "windows":
		required += " productVersion targetRelease qualityDeferralDays featureDeferralDays qualityDeadlineDays featureDeadlineDays graceDays activeHours"
	case "linux":
		required += " class includeFlatpak"
	}
	c.obj(v, required, optional)
	c.field(m, "maintenance", func(q checker, x any) {
		a := q.obj(x, "timezone slots", "")
		if a == nil {
			return
		}
		q.field(a, "timezone", func(r checker, x any) { r.pattern(x, 1, 128, timezonePattern) })
		q.field(a, "slots", func(r checker, x any) {
			r.array(x, 1, 14, false, func(r checker, x any) {
				b := r.obj(x, "days start durationMinutes", "")
				if b == nil {
					return
				}
				r.field(b, "days", func(t checker, x any) {
					t.array(x, 1, 7, true, func(u checker, x any) { u.enum(x, "mon tue wed thu fri sat sun") })
				})
				r.field(b, "start", func(t checker, x any) { t.pattern(x, 1, 5, clockPattern) })
				r.field(b, "durationMinutes", func(t checker, x any) { t.integer(x, 1, 1440) })
			})
		})
	})
	c.field(m, "reboot", func(q checker, x any) {
		a := q.obj(x, "notify maxDeferrals deadline", "")
		if a == nil {
			return
		}
		for _, k := range []string{"notify", "deadline"} {
			q.field(a, k, func(r checker, x any) { r.duration(x) })
		}
		q.field(a, "maxDeferrals", func(r checker, x any) { r.integer(x, 0, 100) })
	})
	switch m["platform"] {
	case "macos":
		for _, k := range []string{"targetVersion", "targetBuild"} {
			c.field(m, k, func(q checker, x any) { q.version(x) })
		}
		for _, k := range []string{"automaticDownload", "automaticInstall", "notifications"} {
			c.field(m, k, func(q checker, x any) { q.boolean(x) })
		}
		c.field(m, "deferrals", func(q checker, x any) {
			a := q.obj(x, "majorDays minorDays systemDays", "")
			if a == nil {
				return
			}
			for _, k := range []string{"majorDays", "minorDays", "systemDays"} {
				q.field(a, k, func(r checker, x any) { r.integer(x, 0, 90) })
			}
		})
	case "windows":
		for _, k := range []string{"productVersion", "targetRelease"} {
			c.field(m, k, func(q checker, x any) { q.version(x) })
		}
		for _, k := range []string{"qualityDeferralDays", "featureDeferralDays", "qualityDeadlineDays", "featureDeadlineDays", "graceDays"} {
			c.field(m, k, func(q checker, x any) {
				hi := float64(30)
				if k == "featureDeferralDays" {
					hi = 365
				}
				if k == "graceDays" {
					hi = 7
				}
				q.integer(x, 0, hi)
			})
		}
		c.field(m, "activeHours", func(q checker, x any) {
			a := q.obj(x, "start end", "")
			if a == nil {
				return
			}
			for _, k := range []string{"start", "end"} {
				q.field(a, k, func(r checker, x any) { r.integer(x, 0, 23) })
			}
		})
	case "linux":
		c.field(m, "class", func(q checker, x any) { q.enum(x, "security all") })
		c.field(m, "includeFlatpak", func(q checker, x any) { q.boolean(x) })
	}
}

// Semantic checks collect the first location in each fixed rule group. Every
// assertion below follows successful structural validation, never untrusted shape.
func semantic(resource map[string]any) *Error {
	defects := map[string]*defect{}
	add := func(rule string, p location) {
		d := defects[rule]
		if d == nil || before(p, d.path) {
			defects[rule] = &defect{path: p}
		}
	}
	unique := func(a []any, key string, p location) {
		seen := map[string]bool{}
		for i, x := range a {
			m := x.(map[string]any)
			v := comparisonKey(m[key])
			if seen[v] {
				add("unique", p.child(i).child(key))
			}
			seen[v] = true
		}
	}
	duration := func(v any, p location) int64 {
		if _, ok := v.(float64); ok {
			return 0
		}
		s := v.(string)
		n, _ := strconv.ParseInt(s[:len(s)-1], 10, 64)
		switch s[len(s)-1] {
		case 'm':
			n *= 60
		case 'h':
			n *= 3600
		case 'd':
			n *= 86400
		}
		if n > 2592000 {
			add("duration", p)
		}
		return n
	}
	encoding := func(v string, p location, qword bool) {
		if qword {
			if _, err := strconv.ParseUint(v, 10, 64); err != nil {
				add("encoding", p)
			}
			return
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || base64.StdEncoding.EncodeToString(b) != v {
			add("encoding", p)
		}
	}
	spec := resource["spec"].(map[string]any)
	root := location{"spec"}
	switch resource["kind"] {
	case "Baseline":
		items := spec["items"].([]any)
		unique(items, "id", root.child("items"))
		for i, x := range items {
			item := x.(map[string]any)
			settings := item["settings"].(map[string]any)
			p := root.child("items").child(i)
			sp := p.child("settings")
			kind := item["kind"].(string)
			if grace, ok := item["grace"]; ok {
				n := duration(grace, p.child("grace"))
				if item["severity"] == "critical" && n != 0 {
					add("duration", p.child("grace"))
				}
			}
			switch kind {
			case "apple.profile":
				unique(settings["payloads"].([]any), "PayloadIdentifier", sp.child("payloads"))
			case "linux.systemd":
				if d, ok := settings["dropIn"].(map[string]any); ok {
					unique(d["sections"].([]any), "name", sp.child("dropIn").child("sections"))
				}
			case "windows.registry":
				segments := strings.Split(settings["key"].(string), "\\")
				for j, s := range segments {
					if s == "." || s == ".." || strings.TrimSpace(s) != s || strings.EqualFold(s, "wow6432node") {
						add("target", sp.child("key"))
					}
					if j == 0 && strings.EqualFold(s, "software") && len(segments) > 1 && strings.EqualFold(segments[1], "policies") {
						add("target", sp.child("key"))
					}
				}
				if settings["type"] == "binary" || settings["type"] == "qword" {
					encoding(settings["value"].(string), sp.child("value"), settings["type"] == "qword")
				}
			case "windows.csp":
				if dotSegments(strings.Join(strings.Split(settings["locUri"].(string), "/")[4:], "/")) {
					add("target", sp.child("locUri"))
				}
				if settings["format"] == "b64" {
					encoding(settings["value"].(string), sp.child("value"), false)
				}
			case "linux.file", "linux.dconf":
				key := "key"
				if kind == "linux.file" {
					key = "path"
				}
				s := settings[key].(string)
				bad := dotSegments(s)
				if kind == "linux.file" {
					bad = bad || !strings.HasPrefix(s, "/etc/")
					for _, prefix := range []string{"/etc/pam.d", "/etc/ricevanta"} {
						bad = bad || s == prefix || strings.HasPrefix(s, prefix+"/")
					}
				}
				if bad {
					add("target", sp.child(key))
				}
			case "linux.repository":
				if !validHTTPS(settings["url"].(string)) {
					add("target", sp.child("url"))
				}
			case "windows.service":
				if settings["startType"] == "disabled" && settings["state"] == "running" {
					add("relation", sp.child("state"))
				}
			}
			if kind == "encryption" || kind == "os_update" {
				if settings["platform"] != spec["os"] {
					add("relation", sp.child("platform"))
				}
			}
			if kind == "os_update" {
				reboot := settings["reboot"].(map[string]any)
				rp := sp.child("reboot")
				notify := duration(reboot["notify"], rp.child("notify"))
				deadline := duration(reboot["deadline"], rp.child("deadline"))
				if deadline == 0 {
					add("duration", rp.child("deadline"))
				}
				if notify > deadline {
					add("duration", rp.child("notify"))
				}
				if settings["platform"] == "macos" && settings["targetVersion"] == "latest" {
					if _, ok := settings["targetBuild"]; ok {
						add("relation", sp.child("targetBuild"))
					}
				}
				if settings["platform"] == "windows" {
					h := settings["activeHours"].(map[string]any)
					if h["start"] == h["end"] {
						add("relation", sp.child("activeHours").child("end"))
					}
				}
			}
		}
	case "SoftwarePackage":
		source := spec["source"].(map[string]any)
		detection := spec["detection"].(map[string]any)
		if source["type"] == "blob" && dotSegments(source["blobKey"].(string)) {
			add("target", root.child("source").child("blobKey"))
		}
		reboot := spec["reboot"].(map[string]any)
		if reboot["mode"] == "exit-code" {
			unique(reboot["codes"].([]any), "code", root.child("reboot").child("codes"))
		}
		if v, ok := detection["version"]; ok && v != spec["version"] {
			add("relation", root.child("detection").child("version"))
		}
		if detection["type"] == "package" {
			name := spec["name"]
			if source["type"] == "repository" {
				name = source["package"]
			}
			if detection["name"] != name {
				add("relation", root.child("detection").child("name"))
			}
		}
	}
	for _, rule := range []string{"unique", "duration", "target", "encoding", "relation"} {
		if d := defects[rule]; d != nil {
			return failure(ErrSemantic, d.path, rule)
		}
	}
	return nil
}
func dotSegments(s string) bool {
	for _, x := range strings.Split(s, "/") {
		if x == "." || x == ".." {
			return true
		}
	}
	return false
}
func validHTTPS(s string) bool {
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, "\\#") || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r < 32 || r == 127 }) {
		return false
	}
	rest := s[8:]
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	if authority == "" || strings.ContainsAny(authority, "%@") || strings.Count(authority, ":") > 1 {
		return false
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort {
		if len(port) == 0 || len(port) > 5 || port[0] == '0' {
			return false
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return false
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	numeric := true
	for _, r := range host {
		if r != '.' && (r < '0' || r > '9') {
			numeric = false
		}
	}
	if numeric {
		parts := strings.Split(host, ".")
		if len(parts) != 4 {
			return false
		}
		for _, x := range parts {
			if len(x) < 1 || len(x) > 3 || len(x) > 1 && x[0] == '0' {
				return false
			}
			n, err := strconv.Atoi(x)
			if err != nil || n < 0 || n > 255 {
				return false
			}
		}
	} else {
		if len(host) > 253 {
			return false
		}
		for _, x := range strings.Split(host, ".") {
			if !namePattern.MatchString(x) {
				return false
			}
		}
	}
	suffix := rest[end:]
	path, _, _ := strings.Cut(suffix, "?")
	for i := 0; i < len(suffix); i++ {
		if suffix[i] == '%' {
			if i+2 >= len(suffix) {
				return false
			}
			n, err := strconv.ParseUint(suffix[i+1:i+3], 16, 8)
			if err != nil {
				return false
			}
			if i < len(path) && (n == 47 || n == 92 || n == 37 || n == 127 || n < 32) {
				return false
			}
			i += 2
		}
	}
	decoded, err := url.PathUnescape(path)
	return err == nil && !dotSegments(decoded)
}
