package exportdest

import (
	"regexp"
	"strings"
)

var (
	tokenPattern    = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._:-]*\z`)
	regionPattern   = regexp.MustCompile(`\A[a-z0-9]+(?:-[a-z0-9]+)*\z`)
	headerPattern   = regexp.MustCompile(`\A[a-z][a-z0-9-]*\z`)
	tenantPattern   = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._-]*\z`)
	uuidPattern     = regexp.MustCompile(`\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z`)
	dcrPattern      = regexp.MustCompile(`\Adcr-[0-9a-f]{32}\z`)
	topicPattern    = regexp.MustCompile(`\A[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\.(?:\{category\}|\{class\}))?\z`)
	bucketPattern   = regexp.MustCompile(`\A[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\z`)
	ipBucketPattern = regexp.MustCompile(`\A[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\z`)
	prefixPattern   = regexp.MustCompile(`\A[A-Za-z0-9_-][A-Za-z0-9._-]{0,62}(?:/[A-Za-z0-9_-][A-Za-z0-9._-]{0,62})*\z`)
	kmsPattern      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9:/_-]*\z`)
)

func region(v any) bool { return text(v, 1, 63, regionPattern) }
func header(v any) bool {
	if !text(v, 1, 64, headerPattern) {
		return false
	}
	s := v.(string)
	return !strings.HasPrefix(s, "grpc-") && !oneOf(s, "host", "connection", "content-length", "content-type", "transfer-encoding", "te", "trailer", "upgrade", "keep-alive", "proxy-authorization", "proxy-authenticate", "content-encoding", "accept-encoding", "grpc-encoding", "grpc-accept-encoding", "user-agent")
}
func bucket(v any) bool {
	return text(v, 1, 63, bucketPattern) && !strings.Contains(v.(string), "..") && !ipBucketPattern.MatchString(v.(string))
}
func prefix(v any) bool { return v == "" || text(v, 0, 256, prefixPattern) }
func encryption(v any) bool {
	if !object(v, map[string]predicate{"mode": enumeration("none", "sse_s3", "sse_kms"), "kmsKeyId": stringField(1, 2048, kmsPattern)}, "mode") {
		return false
	}
	m := v.(map[string]any)
	return (m["mode"] == "sse_kms") == required(m, "kmsKeyId")
}
func parameters(a string, v any) bool {
	var fields map[string]predicate
	var needs []string
	switch a {
	case "elasticsearch":
		fields = map[string]predicate{"auth": enumeration("api_key", "basic", "mtls"), "namespace": name}
		needs = []string{"auth"}
	case "opensearch":
		fields = map[string]predicate{"auth": enumeration("basic", "mtls", "sigv4"), "namespace": name, "region": region, "service": enumeration("es", "aoss"), "credentialSource": enumeration("secret", "workload")}
		needs = []string{"auth"}
	case "splunk_hec":
		fields = map[string]predicate{"mode": enumeration("event", "raw"), "sourcetype": stringField(1, 128, tokenPattern), "index": stringField(1, 128, tokenPattern), "requireAck": boolean}
	case "syslog":
		fields = map[string]predicate{"transport": enumeration("tls", "udp"), "facility": integer(0, 23), "maxMessageBytes": integer(480, 1048576)}
		needs = []string{"transport"}
	case "otlp":
		fields = map[string]predicate{"transport": enumeration("grpc", "http"), "body": enumeration("map", "json_string"), "auth": enumeration("mtls", "bearer", "headers"), "headers": func(v any) bool { return boundedMap(v, 1, 16, header, name) }}
		needs = []string{"auth"}
	case "loki":
		fields = map[string]predicate{"auth": enumeration("basic", "bearer"), "tenant": stringField(1, 128, tenantPattern), "timestamp": enumeration("metadata.logged_time", "time"), "labels": array(0, 2, enumeration("ocsf_category", "os")), "maxLineBytes": integer(1024, 1048576)}
		needs = []string{"auth"}
	case "sentinel":
		fields = map[string]predicate{"cloud": enumeration("public", "usgovernment", "china"), "tenantId": stringField(1, 36, uuidPattern), "clientId": stringField(1, 36, uuidPattern), "dcrImmutableId": stringField(1, 36, dcrPattern), "auth": enumeration("certificate", "client_secret")}
		needs = []string{"cloud", "tenantId", "clientId", "dcrImmutableId", "auth"}
	case "kafka":
		fields = map[string]predicate{"brokers": array(1, 16, broker), "auth": enumeration("mtls", "scram_sha_256", "scram_sha_512", "plain", "oauthbearer"), "topic": stringField(1, 249, topicPattern), "key": enumeration("device.uid", "metadata.uid"), "compression": enumeration("zstd", "lz4", "snappy", "gzip")}
		needs = []string{"brokers", "auth"}
	case "s3":
		fields = map[string]predicate{"bucket": bucket, "prefix": prefix, "region": region, "auth": enumeration("access_key", "workload"), "forcePathStyle": boolean, "encryption": encryption}
		needs = []string{"bucket", "region", "auth"}
	case "connector":
		fields = map[string]predicate{"registrationRef": name, "timeout": duration}
		needs = []string{"registrationRef"}
	default:
		return false
	}
	if !object(v, fields, needs...) {
		return false
	}
	m := v.(map[string]any)
	switch a {
	case "opensearch":
		if m["auth"] == "sigv4" {
			return required(m, "region", "service", "credentialSource")
		}
		for _, k := range []string{"region", "service", "credentialSource"} {
			if required(m, k) {
				return false
			}
		}
	case "syslog":
		if m["transport"] == "udp" {
			if n, ok := m["maxMessageBytes"]; ok {
				return n.(float64) <= 1180
			}
		}
	case "otlp":
		return (m["auth"] == "headers") == required(m, "headers")
	}
	return true
}
func combination(a string, s map[string]any) bool {
	b := s[a].(map[string]any)
	if a != "s3" && s["archive"] == true {
		return false
	}
	switch a {
	case "connector":
		return !required(s, "endpoint") && !required(s, "tls") && !required(s, "credentialRef")
	case "kafka":
		if required(s, "endpoint") {
			return false
		}
	case "syslog":
		ep, ok := s["endpoint"].(string)
		if !ok || !strings.HasPrefix(ep, b["transport"].(string)+"://") || required(s, "credentialRef") {
			return false
		}
		return b["transport"] != "udp" || !required(s, "tls")
	default:
		ep, ok := s["endpoint"].(string)
		if !ok || !strings.HasPrefix(ep, "https://") {
			return false
		}
	}
	if a == "sentinel" {
		if batch, ok := s["batch"].(map[string]any); ok {
			if n, ok := batch["maxBytes"].(float64); ok && n > 1000000 {
				return false
			}
		}
	}
	auth := b["auth"]
	if auth == "mtls" {
		t, ok := s["tls"].(map[string]any)
		return ok && required(t, "clientCertificateRef") && !required(s, "credentialRef")
	}
	forbid := auth == "workload" || (a == "opensearch" && b["credentialSource"] == "workload") || (a == "otlp" && auth == "headers")
	return required(s, "credentialRef") != forbid
}
