package exportdest

import (
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	namePattern       = regexp.MustCompile(`\A[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?\z`)
	dnsPattern        = regexp.MustCompile(`\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z`)
	pathPattern       = regexp.MustCompile(`\A[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}\z`)
	metaKeyPattern    = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._/-]*\z`)
	projectionPattern = regexp.MustCompile(`\A[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,15}\z`)
	durationPattern   = regexp.MustCompile(`\A(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)s\z`)
	pinPattern        = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
	ipv6Pattern       = regexp.MustCompile(`\A[0-9a-f:]+\z`)
)

type predicate func(any) bool

func oneOf(v any, values ...string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, x := range values {
		if s == x {
			return true
		}
	}
	return false
}
func required(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func closed(m map[string]any, keys ...string) bool {
	for k := range m {
		found := false
		for _, allowed := range keys {
			if k == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func object(v any, fields map[string]predicate, needs ...string) bool {
	m, ok := v.(map[string]any)
	if !ok || !required(m, needs...) {
		return false
	}
	for k, v := range m {
		check, ok := fields[k]
		if !ok || !check(v) {
			return false
		}
	}
	return true
}
func text(v any, min, max int, pattern *regexp.Regexp) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max && (pattern == nil || pattern.MatchString(s))
}
func name(v any) bool    { return text(v, 1, 63, namePattern) }
func boolean(v any) bool { _, ok := v.(bool); return ok }
func integer(min, max float64) predicate {
	return func(v any) bool { n, ok := v.(float64); return ok && n >= min && n <= max && math.Trunc(n) == n }
}
func enumeration(values ...string) predicate { return func(v any) bool { return oneOf(v, values...) } }
func stringField(min, max int, pattern *regexp.Regexp) predicate {
	return func(v any) bool { return text(v, min, max, pattern) }
}
func array(min, max int, item predicate) predicate {
	return func(v any) bool {
		a, ok := v.([]any)
		if !ok || len(a) < min || len(a) > max {
			return false
		}
		seen := make(map[string]bool, len(a))
		for _, v := range a {
			if !item(v) {
				return false
			}
			s, ok := v.(string)
			if !ok || seen[s] {
				return false
			}
			seen[s] = true
		}
		return true
	}
}
func boundedMap(v any, min, max int, key, value predicate) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) < min || len(m) > max {
		return false
	}
	for k, v := range m {
		if !key(k) || !value(v) {
			return false
		}
	}
	return true
}
func metadata(v any) bool {
	return object(v, map[string]predicate{
		"name": name, "description": stringField(0, 1024, nil),
		"labels": func(v any) bool {
			return boundedMap(v, 0, 32, stringField(1, 128, metaKeyPattern), stringField(0, 63, nil))
		},
		"annotations": func(v any) bool {
			return boundedMap(v, 0, 32, stringField(1, 128, metaKeyPattern), stringField(0, 4096, nil))
		},
	}, "name")
}
func tls(v any) bool {
	if !object(v, map[string]predicate{"caRef": name, "pinSha256": stringField(1, 64, pinPattern), "clientCertificateRef": name, "serverName": stringField(1, 253, dnsPattern)}) {
		return false
	}
	return !required(v.(map[string]any), "caRef", "pinSha256")
}
func class(v any) bool {
	return oneOf(v,
		"api_activity", "application_lifecycle", "authentication", "authorize_session", "base_event", "clipboard_activity", "compliance_finding", "data_security_finding", "detection_finding", "device_config_state_change", "dns_activity", "entity_management", "event_log_actvity", "evidence_info", "file_activity", "file_remediation_activity", "http_activity", "inventory_info", "kernel_extension_activity", "memory_activity", "module_activity", "network_activity", "network_remediation_activity", "peripheral_activity", "process_activity", "process_remediation_activity", "remediation_activity", "ricevanta/agent_health_activity", "ricevanta/certificate_lifecycle_activity", "ricevanta/device_management_activity", "ricevanta/lineage_activity", "ricevanta/pipeline_activity", "ricevanta/policy_activity", "role_management", "scheduled_job_activity", "script_activity", "software_info", "user_management", "vulnerability_finding", "win/registry_key_activity", "win/registry_value_activity", "win/windows_service_activity")
}
func filter(v any) bool {
	return object(v, map[string]predicate{
		"classes": array(0, 42, class), "deviceGroups": array(0, 64, name), "origins": array(1, 3, enumeration("agent", "server", "extension")),
		"minSeverity": enumeration("unknown", "informational", "low", "medium", "high", "critical", "fatal", "other"), "condition": stringField(0, 4096, nil),
	})
}
func drop(v any) bool {
	if !text(v, 1, 256, projectionPattern) {
		return false
	}
	s := v.(string)
	if s == "metadata" {
		return false
	}
	for _, p := range []string{"metadata.uid", "metadata.version", "class_uid", "time"} {
		if s == p || strings.HasPrefix(s, p+".") {
			return false
		}
	}
	return true
}
func projection(v any) bool { return object(v, map[string]predicate{"drop": array(0, 64, drop)}) }
func duration(v any) bool   { return text(v, 1, 4, durationPattern) }
func batch(v any) bool {
	return object(v, map[string]predicate{"maxEvents": integer(1, 10000), "maxBytes": integer(1024, 67108864), "maxDelay": duration})
}
func common(s map[string]any) bool {
	checks := map[string]predicate{"enabled": boolean, "endpoint": endpoint, "credentialRef": name, "tls": tls, "filter": filter, "projection": projection, "repeats": enumeration("first_and_summary", "all"), "audit": boolean, "archive": boolean, "batch": batch, "inflight": integer(1, 16)}
	for k, check := range checks {
		if v, ok := s[k]; ok && !check(v) {
			return false
		}
	}
	return true
}

func hostPort(s string, portRequired bool) bool {
	var host, port string
	hasPort := false
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return false
		}
		host = s[1:end]
		rest := s[end+1:]
		if !ipv6Pattern.MatchString(host) {
			return false
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return false
		}
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return false
			}
			port = rest[1:]
			hasPort = true
		}
	} else {
		host = s
		if i := strings.IndexByte(s, ':'); i >= 0 {
			host = s[:i]
			port = s[i+1:]
			hasPort = true
		}
		if !dnsPattern.MatchString(host) {
			return false
		}
	}
	if !hasPort {
		return !portRequired
	}
	if len(port) < 1 || len(port) > 5 || port[0] == '0' {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}
func endpoint(v any) bool {
	if !text(v, 1, 2048, nil) {
		return false
	}
	s := v.(string)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return false
	}
	switch scheme {
	case "https":
		host, path, hasPath := strings.Cut(rest, "/")
		if !hostPort(host, false) {
			return false
		}
		if !hasPath || path == "" {
			return true
		}
		path = strings.TrimSuffix(path, "/")
		for _, segment := range strings.Split(path, "/") {
			if !pathPattern.MatchString(segment) {
				return false
			}
		}
		return true
	case "tls", "udp":
		return hostPort(rest, true)
	default:
		return false
	}
}
func broker(v any) bool { return text(v, 1, 320, nil) && hostPort(v.(string), true) }
