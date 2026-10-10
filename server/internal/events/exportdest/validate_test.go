package exportdest

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func expect(t testing.TB, value any, want error) {
	t.Helper()
	if got := Validate(value); !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func nested(depth int, leaf any) any {
	for range depth {
		leaf = []any{leaf}
	}
	return leaf
}

func TestPreflight(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	shared := []any{nil}
	tests := []struct {
		name  string
		value any
		want  error
	}{
		{"nil", nil, ErrResource}, {"typed-map", map[string]any(nil), ErrInput}, {"typed-array", []any(nil), ErrInput},
		{"int", 1, ErrInput}, {"number", json.Number("1"), ErrInput}, {"struct", struct{}{}, ErrInput},
		{"nan", math.NaN(), ErrInput}, {"positive-infinity", math.Inf(1), ErrInput}, {"negative-infinity", math.Inf(-1), ErrInput},
		{"invalid-string", string([]byte{255}), ErrInput}, {"invalid-key", map[string]any{string([]byte{255}): nil}, ErrInput},
		{"depth12", nested(12, nil), ErrResource}, {"depth13", nested(13, nil), ErrLimits}, {"depth-before-type", nested(13, struct{}{}), ErrLimits},
		{"nodes8192", make([]any, 8191), ErrResource}, {"nodes8193", make([]any, 8192), ErrLimits},
		{"container8193", make([]any, 8193), ErrLimits}, {"bytes262144", strings.Repeat("a", 262144), ErrResource},
		{"bytes262145", strings.Repeat("a", 262145), ErrLimits}, {"bytes-before-utf8", strings.Repeat("a", 262144) + string([]byte{255}), ErrLimits},
		{"cycle", cycle, ErrLimits}, {"shared", []any{shared, shared}, ErrResource},
		{"bounded-invalid-key-before-child", map[string]any{string([]byte{255}): struct{}{}}, ErrInput},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) { expect(t, c.value, c.want) })
	}
	for _, n := range []int{262144, 262145} {
		want := ErrResource
		if n > 262144 {
			want = ErrLimits
		}
		expect(t, map[string]any{strings.Repeat("a", n): nil}, want)
	}
	long := make(map[string]any, 8192)
	for i := range 8192 {
		long[strings.Repeat("a", 128)+strconv.Itoa(i)] = nil
	}
	expect(t, long, ErrLimits)
	long[string([]byte{255})] = struct{}{}
	expect(t, long, ErrLimits)
	oversized := map[string]any{strings.Repeat("a", 262144) + string([]byte{255}): struct{}{}}
	expect(t, oversized, ErrLimits)
	// Shared children count on each occurrence, even when they share storage.
	repeated := make([]any, 4096)
	for i := range repeated {
		repeated[i] = shared
	}
	expect(t, repeated, ErrLimits)
	// Key accounting precedes child accounting and uses the same byte budget.
	expect(t, map[string]any{"a": strings.Repeat("b", 262143)}, ErrResource)
	expect(t, map[string]any{"a": strings.Repeat("b", 262144)}, ErrLimits)
}

func TestPrecedence(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[string]any)
		want   error
	}{
		{"depth-kind", func(r map[string]any) { r["kind"] = "bad"; r["z"] = nested(13, nil) }, ErrLimits},
		{"input-kind", func(r map[string]any) { r["kind"] = "bad"; r["z"] = struct{}{} }, ErrInput},
		{"resource-adapter", func(r map[string]any) { r["kind"] = "bad"; spec(r)["type"] = "bad" }, ErrResource},
		{"adapter-common", func(r map[string]any) { spec(r)["type"] = "bad"; spec(r)["enabled"] = nil }, ErrAdapter},
		{"common-parameters", func(r map[string]any) { spec(r)["enabled"] = nil; spec(r)["splunk_hec"] = nil }, ErrCommon},
		{"parameters-combination", func(r map[string]any) { spec(r)["splunk_hec"] = nil; delete(spec(r), "credentialRef") }, ErrParameters},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) { r := base("splunk_hec"); c.change(r); expect(t, r, c.want) })
	}
}

func TestNoMutation(t *testing.T) {
	for _, c := range readFixtures(t) {
		before := clone(c.Resource)
		Validate(c.Resource)
		if !reflect.DeepEqual(before, c.Resource) {
			t.Fatalf("mutation: %s", c.ID)
		}
	}
}

func TestNoInputInErrors(t *testing.T) {
	const canary = "synthetic-private-canary"
	var taint func(any) any
	taint = func(v any) any {
		switch x := v.(type) {
		case string:
			return canary
		case []any:
			a := make([]any, len(x))
			for i, v := range x {
				a[i] = taint(v)
			}
			return a
		case map[string]any:
			m := map[string]any{}
			for k, v := range x {
				m[k] = taint(v)
			}
			return m
		default:
			return v
		}
	}
	for _, c := range readFixtures(t) {
		for _, value := range []any{taint(c.Resource), map[string]any{canary: c.Resource}} {
			err := Validate(value)
			if err == nil || strings.Contains(err.Error(), canary) {
				t.Fatal("unsafe error")
			}
		}
	}
	// Place a canary at each scalar and key while preserving the envelope elsewhere.
	for _, f := range fields() {
		r := base(f.adapter)
		put(r, strings.Split(f.path, "."), canary)
		if err := Validate(r); err != nil && strings.Contains(err.Error(), canary) {
			t.Fatal("unsafe field error")
		}
	}
}

func TestNumericSemantics(t *testing.T) {
	for _, c := range []struct {
		v    any
		want error
	}{{math.Copysign(0, -1), nil}, {float64(1), nil}, {float64(1.5), ErrParameters}, {math.MaxFloat64, ErrParameters}, {true, ErrParameters}, {1, ErrInput}, {math.NaN(), ErrInput}, {math.Inf(1), ErrInput}} {
		r := base("syslog")
		spec(r)["syslog"].(map[string]any)["facility"] = c.v
		expect(t, r, c.want)
	}
	for _, text := range []string{"1.0", "1e0", "-0"} {
		var value any
		if err := json.Unmarshal([]byte(text), &value); err != nil {
			t.Fatal(err)
		}
		r := base("syslog")
		spec(r)["syslog"].(map[string]any)["facility"] = value
		expect(t, r, nil)
	}
}

type field struct {
	adapter, path string
	value         any
	stage         error
	required      bool
}

func fields() []field {
	// Values and required flags follow the approved schema, independently of Validate.
	f := []field{
		{"splunk_hec", "metadata.name", "soc", ErrResource, true}, {"splunk_hec", "metadata.labels", map[string]any{"team": "soc"}, ErrResource, false},
		{"splunk_hec", "metadata.annotations", map[string]any{"note": "x"}, ErrResource, false}, {"splunk_hec", "metadata.description", "x", ErrResource, false},
	}
	common := map[string]any{"enabled": false, "endpoint": "https://a.example", "credentialRef": "credential", "tls": map[string]any{}, "filter": map[string]any{}, "projection": map[string]any{}, "repeats": "all", "audit": true, "archive": false, "batch": map[string]any{}, "inflight": float64(2), "tls.caRef": "ca", "tls.pinSha256": strings.Repeat("a", 64), "tls.clientCertificateRef": "cert", "tls.serverName": "a.example", "filter.classes": []any{"authentication"}, "filter.deviceGroups": []any{"soc"}, "filter.origins": []any{"agent"}, "filter.minSeverity": "low", "filter.condition": "true", "projection.drop": []any{"unmapped"}, "batch.maxEvents": float64(1), "batch.maxBytes": float64(1024), "batch.maxDelay": "1s"}
	for p, v := range common {
		f = append(f, field{"splunk_hec", "spec." + p, v, ErrCommon, false})
	}
	blocks := map[string]map[string]any{
		"elasticsearch": {"auth": "basic", "namespace": "soc"},
		"opensearch":    {"auth": "basic", "namespace": "soc"},
		"splunk_hec":    {"mode": "event", "sourcetype": "ricevanta:ocsf", "index": "security", "requireAck": true},
		"syslog":        {"transport": "tls", "facility": float64(0), "maxMessageBytes": float64(480)},
		"otlp":          {"auth": "bearer", "transport": "grpc", "body": "map"},
		"loki":          {"auth": "basic", "tenant": "soc", "timestamp": "time", "labels": []any{"os"}, "maxLineBytes": float64(1024)},
		"sentinel":      {"cloud": "public", "tenantId": "11111111-1111-4111-8111-111111111111", "clientId": "22222222-2222-4222-8222-222222222222", "dcrImmutableId": "dcr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "auth": "certificate"},
		"kafka":         {"brokers": []any{"a.example:1"}, "auth": "plain", "topic": "topic", "key": "device.uid", "compression": "zstd"},
		"s3":            {"bucket": "events", "region": "us-east-1", "auth": "access_key", "prefix": "", "forcePathStyle": false, "encryption": map[string]any{"mode": "none"}, "encryption.mode": "none"},
		"connector":     {"registrationRef": "connector", "timeout": "1s"},
	}
	required := map[string]string{"elasticsearch": "auth", "opensearch": "auth", "syslog": "transport", "otlp": "auth", "loki": "auth", "sentinel": "cloud tenantId clientId dcrImmutableId auth", "kafka": "brokers auth", "s3": "bucket region auth encryption.mode", "connector": "registrationRef"}
	for a, values := range blocks {
		for p, v := range values {
			req := false
			for _, k := range strings.Fields(required[a]) {
				if k == p {
					req = true
				}
			}
			f = append(f, field{a, "spec." + a + "." + p, v, ErrParameters, req})
		}
	}
	return f
}

func TestDefaultsAndNull(t *testing.T) {
	for _, f := range fields() {
		t.Run(f.adapter+"/"+f.path, func(t *testing.T) {
			r := base(f.adapter)
			p := strings.Split(f.path, ".")
			put(r, p, f.value)
			expect(t, r, nil)
			put(r, p, nil)
			expect(t, r, f.stage)
			r = base(f.adapter)
			put(r, p, f.value)
			m := r
			for _, k := range p[:len(p)-1] {
				m = m[k].(map[string]any)
			}
			delete(m, p[len(p)-1])
			want := error(nil)
			if f.required {
				want = f.stage
			}
			if f.path == "spec.endpoint" || f.path == "spec.credentialRef" {
				want = ErrCombination
			}
			expect(t, r, want)
		})
	}
	for _, p := range []string{"apiVersion", "kind", "metadata", "spec"} {
		r := base("splunk_hec")
		delete(r, p)
		expect(t, r, ErrResource)
		r = base("splunk_hec")
		r[p] = nil
		expect(t, r, ErrResource)
	}
	for _, a := range []string{"elasticsearch", "opensearch", "splunk_hec", "syslog", "otlp", "loki", "sentinel", "kafka", "s3", "connector"} {
		r := base(a)
		delete(spec(r), a)
		expect(t, r, ErrAdapter)
		r = base(a)
		spec(r)[a] = nil
		expect(t, r, ErrParameters)
		delete(spec(r), "type")
		expect(t, r, ErrAdapter)
	}
}

func TestClosedObjects(t *testing.T) {
	paths := []struct {
		adapter, path string
		stage         error
	}{{"splunk_hec", "", ErrResource}, {"splunk_hec", "metadata", ErrResource}, {"splunk_hec", "spec", ErrAdapter}, {"splunk_hec", "spec.tls", ErrCommon}, {"splunk_hec", "spec.filter", ErrCommon}, {"splunk_hec", "spec.projection", ErrCommon}, {"splunk_hec", "spec.batch", ErrCommon}, {"s3", "spec.s3.encryption", ErrParameters}}
	for _, a := range []string{"elasticsearch", "opensearch", "splunk_hec", "syslog", "otlp", "loki", "sentinel", "kafka", "s3", "connector"} {
		paths = append(paths, struct {
			adapter, path string
			stage         error
		}{a, "spec." + a, ErrParameters})
	}
	for _, p := range paths {
		r := base(p.adapter)
		m := r
		if p.path != "" {
			for _, k := range strings.Split(p.path, ".") {
				if m[k] == nil {
					m[k] = map[string]any{}
				}
				m = m[k].(map[string]any)
			}
		}
		if p.path == "spec.s3.encryption" {
			m["mode"] = "none"
		}
		m["unexpected"] = true
		spec(r)["enabled"] = false
		expect(t, r, p.stage)
	}
	for _, a := range []string{"elasticsearch", "opensearch", "syslog", "otlp", "loki", "sentinel", "kafka", "s3", "connector"} {
		r := base("splunk_hec")
		spec(r)[a] = map[string]any{}
		expect(t, r, ErrAdapter)
	}
}

func TestProjectionProtection(t *testing.T) {
	for _, p := range []string{"metadata", "metadata.uid", "metadata.version", "class_uid", "time", "metadata.uid.value", "metadata.version.value", "class_uid.value", "time.value", "metadata.uid.value.deep"} {
		r := base("splunk_hec")
		spec(r)["projection"] = map[string]any{"drop": []any{p}}
		expect(t, r, ErrCommon)
	}
	for _, p := range []string{"metadata.other", "metadata.uids", "time_zone", "class_uids", "unmapped", "a.b"} {
		r := base("splunk_hec")
		spec(r)["projection"] = map[string]any{"drop": []any{p}}
		expect(t, r, nil)
	}
	for _, p := range []string{"A", "a.*", "a[0]", "a..b", "a\\.b", strings.TrimSuffix(strings.Repeat("a.", 17), ".")} {
		r := base("splunk_hec")
		spec(r)["projection"] = map[string]any{"drop": []any{p}}
		expect(t, r, ErrCommon)
	}
}

type enumField struct {
	adapter, path string
	values        []string
	stage         error
}

func enumFields() []enumField {
	return []enumField{
		{"splunk_hec", "spec.repeats", []string{"all", "first_and_summary"}, ErrCommon},
		{"splunk_hec", "spec.filter.minSeverity", []string{"unknown", "informational", "low", "medium", "high", "critical", "fatal", "other"}, ErrCommon},
		{"splunk_hec", "spec.filter.origins", []string{"agent", "server", "extension"}, ErrCommon},
		{"elasticsearch", "spec.elasticsearch.auth", []string{"api_key", "basic", "mtls"}, ErrParameters},
		{"opensearch", "spec.opensearch.auth", []string{"basic", "mtls", "sigv4"}, ErrParameters},
		{"splunk_hec", "spec.splunk_hec.mode", []string{"event", "raw"}, ErrParameters},
		{"syslog", "spec.syslog.transport", []string{"tls", "udp"}, ErrParameters},
		{"otlp", "spec.otlp.auth", []string{"bearer", "mtls", "headers"}, ErrParameters},
		{"otlp", "spec.otlp.transport", []string{"grpc", "http"}, ErrParameters},
		{"otlp", "spec.otlp.body", []string{"map", "json_string"}, ErrParameters},
		{"loki", "spec.loki.auth", []string{"basic", "bearer"}, ErrParameters},
		{"loki", "spec.loki.timestamp", []string{"metadata.logged_time", "time"}, ErrParameters},
		{"loki", "spec.loki.labels", []string{"ocsf_category", "os"}, ErrParameters},
		{"sentinel", "spec.sentinel.cloud", []string{"public", "usgovernment", "china"}, ErrParameters},
		{"sentinel", "spec.sentinel.auth", []string{"certificate", "client_secret"}, ErrParameters},
		{"kafka", "spec.kafka.auth", []string{"mtls", "scram_sha_256", "scram_sha_512", "plain", "oauthbearer"}, ErrParameters},
		{"kafka", "spec.kafka.compression", []string{"zstd", "lz4", "snappy", "gzip"}, ErrParameters},
		{"kafka", "spec.kafka.key", []string{"device.uid", "metadata.uid"}, ErrParameters},
		{"s3", "spec.s3.auth", []string{"access_key", "workload"}, ErrParameters},
		{"s3", "spec.s3.encryption.mode", []string{"none", "sse_s3", "sse_kms"}, ErrParameters},
	}
}

func modeResource(a, path, value string) map[string]any {
	r := base(a)
	p := strings.Split(path, ".")
	var v any = value
	if strings.HasSuffix(path, ".origins") || strings.HasSuffix(path, ".labels") {
		v = []any{value}
	}
	put(r, p, v)
	s := spec(r)
	b := s[a].(map[string]any)
	if strings.HasSuffix(path, ".auth") {
		if value == "mtls" {
			delete(s, "credentialRef")
			s["tls"] = map[string]any{"clientCertificateRef": "cert"}
		}
		if value == "sigv4" {
			b["region"] = "us-east-1"
			b["service"] = "es"
			b["credentialSource"] = "secret"
		}
		if value == "headers" {
			delete(s, "credentialRef")
			b["headers"] = map[string]any{"authorization": "token"}
		}
		if value == "workload" {
			delete(s, "credentialRef")
		}
	}
	if a == "syslog" && value == "udp" {
		s["endpoint"] = "udp://a.example:1"
	}
	if path == "spec.s3.encryption.mode" && value == "sse_kms" {
		b["encryption"].(map[string]any)["kmsKeyId"] = "alias/events"
	}
	return r
}

func TestAuthCombinations(t *testing.T) {
	for _, f := range enumFields() {
		for _, v := range append(append([]string{}, f.values...), "unknown-value") {
			t.Run(f.path+"/"+v, func(t *testing.T) {
				r := modeResource(f.adapter, f.path, v)
				want := error(nil)
				if v == "unknown-value" {
					want = f.stage
				}
				expect(t, r, want)
				if v != "unknown-value" && strings.HasSuffix(f.path, ".auth") {
					s := spec(r)
					_, has := s["credentialRef"]
					if has {
						delete(s, "credentialRef")
					} else {
						s["credentialRef"] = "credential"
					}
					expect(t, r, ErrCombination)
					if v == "mtls" {
						delete(s, "credentialRef")
						delete(s, "tls")
						expect(t, r, ErrCombination)
						s["tls"] = map[string]any{}
						expect(t, r, ErrCombination)
					}
				}
			})
		}
	}
	for _, source := range []string{"secret", "workload"} {
		for _, service := range []string{"es", "aoss"} {
			r := modeResource("opensearch", "spec.opensearch.auth", "sigv4")
			b := spec(r)["opensearch"].(map[string]any)
			b["credentialSource"] = source
			b["service"] = service
			if source == "workload" {
				delete(spec(r), "credentialRef")
			}
			expect(t, r, nil)
			for _, k := range []string{"region", "service", "credentialSource"} {
				c := clone(r).(map[string]any)
				delete(spec(c)["opensearch"].(map[string]any), k)
				expect(t, c, ErrParameters)
			}
			c := clone(r).(map[string]any)
			if source == "workload" {
				spec(c)["credentialRef"] = "credential"
			} else {
				delete(spec(c), "credentialRef")
			}
			expect(t, c, ErrCombination)
		}
	}
	for _, k := range []string{"region", "service", "credentialSource"} {
		r := base("opensearch")
		spec(r)["opensearch"].(map[string]any)[k] = "secret"
		expect(t, r, ErrParameters)
	}
	for _, mode := range []string{"none", "sse_s3", "sse_kms"} {
		r := modeResource("s3", "spec.s3.encryption.mode", mode)
		e := spec(r)["s3"].(map[string]any)["encryption"].(map[string]any)
		if mode == "sse_kms" {
			delete(e, "kmsKeyId")
		} else {
			e["kmsKeyId"] = "alias/events"
		}
		expect(t, r, ErrParameters)
	}
	for _, auth := range []string{"bearer", "mtls", "headers"} {
		r := modeResource("otlp", "spec.otlp.auth", auth)
		b := spec(r)["otlp"].(map[string]any)
		if auth == "headers" {
			delete(b, "headers")
		} else {
			b["headers"] = map[string]any{"authorization": "token"}
		}
		expect(t, r, ErrParameters)
	}
	for _, a := range []string{"syslog", "connector"} {
		r := base(a)
		spec(r)["credentialRef"] = "credential"
		expect(t, r, ErrCombination)
	}
	for _, a := range []string{"kafka", "connector"} {
		r := base(a)
		spec(r)["endpoint"] = "https://a.example"
		expect(t, r, ErrCombination)
	}
	r := base("connector")
	spec(r)["tls"] = map[string]any{}
	expect(t, r, ErrCombination)
	r = modeResource("syslog", "spec.syslog.transport", "udp")
	spec(r)["tls"] = map[string]any{}
	expect(t, r, ErrCombination)
	r = base("syslog")
	spec(r)["endpoint"] = "udp://a.example:1"
	expect(t, r, ErrCombination)
	for _, a := range []string{"elasticsearch", "opensearch", "splunk_hec", "syslog", "otlp", "loki", "sentinel", "kafka", "connector"} {
		r := base(a)
		spec(r)["archive"] = true
		expect(t, r, ErrCombination)
	}
	r = base("s3")
	spec(r)["archive"] = true
	expect(t, r, nil)
}

type numberField struct {
	adapter, path string
	min, max      float64
	stage         error
}

func numberFields() []numberField {
	return []numberField{
		{"splunk_hec", "spec.batch.maxEvents", 1, 10000, ErrCommon}, {"splunk_hec", "spec.batch.maxBytes", 1024, 67108864, ErrCommon}, {"splunk_hec", "spec.inflight", 1, 16, ErrCommon},
		{"syslog", "spec.syslog.facility", 0, 23, ErrParameters}, {"syslog", "spec.syslog.maxMessageBytes", 480, 1048576, ErrParameters}, {"loki", "spec.loki.maxLineBytes", 1024, 1048576, ErrParameters},
	}
}
func TestParameterBoundaries(t *testing.T) {
	for _, f := range numberFields() {
		for i, v := range []float64{f.min - 1, f.min, f.max, f.max + 1, 1.5} {
			r := base(f.adapter)
			put(r, strings.Split(f.path, "."), v)
			want := error(nil)
			if i == 0 || i >= 3 {
				want = f.stage
			}
			expect(t, r, want)
		}
	}
	for _, v := range []float64{479, 480, 1180, 1181, 65536, 1048577} {
		r := modeResource("syslog", "spec.syslog.transport", "udp")
		spec(r)["syslog"].(map[string]any)["maxMessageBytes"] = v
		want := error(nil)
		if v < 480 || v > 1180 {
			want = ErrParameters
		}
		expect(t, r, want)
	}
	for _, v := range []float64{999999, 1000000, 1000001} {
		r := base("sentinel")
		spec(r)["batch"] = map[string]any{"maxBytes": v}
		want := error(nil)
		if v > 1000000 {
			want = ErrCombination
		}
		expect(t, r, want)
	}
	for _, f := range []struct{ a, path string }{{"splunk_hec", "spec.batch.maxDelay"}, {"connector", "spec.connector.timeout"}} {
		for _, v := range []string{"0s", "1s", "300s", "301s", "01s", "1ms", "1.0s"} {
			r := base(f.a)
			put(r, strings.Split(f.path, "."), v)
			want := error(nil)
			if v != "1s" && v != "300s" {
				want = ErrCommon
				if f.a == "connector" {
					want = ErrParameters
				}
			}
			expect(t, r, want)
		}
	}
	for _, prefix := range []string{"", "events", "soc/evidence", ".hidden", "/events", "events/", "events//soc", "events/.hidden"} {
		r := base("s3")
		spec(r)["s3"].(map[string]any)["prefix"] = prefix
		want := error(nil)
		if prefix != "" && prefix != "events" && prefix != "soc/evidence" {
			want = ErrParameters
		}
		expect(t, r, want)
	}
	for _, topic := range []string{"topic", "topic.{category}", "topic.{class}", "{class}", "topic.{other}", "topic.{class}.{category}"} {
		r := base("kafka")
		spec(r)["kafka"].(map[string]any)["topic"] = topic
		want := error(nil)
		if topic != "topic" && topic != "topic.{category}" && topic != "topic.{class}" {
			want = ErrParameters
		}
		expect(t, r, want)
	}
	for _, name := range []string{"authorization", "x-api-key", "Host", "host", "connection", "content-length", "content-type", "transfer-encoding", "te", "trailer", "upgrade", "keep-alive", "proxy-authorization", "proxy-authenticate", "content-encoding", "accept-encoding", "grpc-encoding", "grpc-accept-encoding", "user-agent", "grpc-anything", "x_key"} {
		r := modeResource("otlp", "spec.otlp.auth", "headers")
		spec(r)["otlp"].(map[string]any)["headers"] = map[string]any{name: "token"}
		want := error(nil)
		if name != "authorization" && name != "x-api-key" {
			want = ErrParameters
		}
		expect(t, r, want)
	}
}

func TestWholeStringPatterns(t *testing.T) {
	for _, f := range fields() {
		if s, ok := f.value.(string); ok {
			r := base(f.adapter)
			put(r, strings.Split(f.path, "."), s+"\n")
			if f.path == "metadata.description" || f.path == "spec.filter.condition" {
				expect(t, r, nil)
			} else {
				expect(t, r, f.stage)
			}
		}
	}
	for _, v := range []string{"https://a", "https://[::1]", "https://[2001:db8::1]:65535/a-b_/", "https://[1:2:3:4:5:6:7:8]", "https://a:1"} {
		r := base("splunk_hec")
		spec(r)["endpoint"] = v
		expect(t, r, nil)
	}
	for _, v := range []string{"https://a:0", "https://a:01", "https://a:65536", "https://A", "https://a?x", "https://user@a", "https://a/#x", "https://a/%20", "https://a/..", "https://a/.a", "https://a//b", "https://[::ffff:192.0.2.1]", "https://[fe80::1%eth0]", "https://[1:2:3]", "https://[:::]", "https://a\\b", "//a", "http://a", "https://a\n"} {
		r := base("splunk_hec")
		spec(r)["endpoint"] = v
		expect(t, r, ErrCommon)
	}
}

func TestSegmentBoundaries(t *testing.T) {
	// Keep whole-field lengths below their caps to isolate each segment limit.
	tests := []struct {
		name, adapter, path, value string
		want                       error
	}{
		{"https-128", "splunk_hec", "spec.endpoint", "https://a/" + strings.Repeat("a", 128), nil},
		{"https-129", "splunk_hec", "spec.endpoint", "https://a/" + strings.Repeat("a", 129), ErrCommon},
		{"https-later-128", "splunk_hec", "spec.endpoint", "https://a/base/" + strings.Repeat("a", 128), nil},
		{"https-later-129", "splunk_hec", "spec.endpoint", "https://a/base/" + strings.Repeat("a", 129), ErrCommon},
		{"s3-63", "s3", "spec.s3.prefix", strings.Repeat("a", 63), nil},
		{"s3-64", "s3", "spec.s3.prefix", strings.Repeat("a", 64), ErrParameters},
		{"s3-later-63", "s3", "spec.s3.prefix", "base/" + strings.Repeat("a", 63), nil},
		{"s3-later-64", "s3", "spec.s3.prefix", "base/" + strings.Repeat("a", 64), ErrParameters},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			r := base(c.adapter)
			put(r, strings.Split(c.path, "."), c.value)
			expect(t, r, c.want)
		})
	}
}

func TestHTTPSIPv6Case(t *testing.T) {
	tests := []struct {
		name, endpoint string
		want           error
	}{
		{"lowercase", "https://[2001:db8::1]", nil},
		{"uppercase", "https://[2001:DB8::1]", ErrCommon},
		{"mixed-case", "https://[2001:dB8::1]", ErrCommon},
		{"uppercase-port-path", "https://[2001:DB8::1]:443/base", ErrCommon},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			r := base("splunk_hec")
			spec(r)["endpoint"] = c.endpoint
			expect(t, r, c.want)
		})
	}
}

func TestUnicodeLengths(t *testing.T) {
	for _, f := range []struct {
		path  string
		max   int
		stage error
	}{{"metadata.description", 1024, ErrResource}, {"spec.filter.condition", 4096, ErrCommon}} {
		for _, n := range []int{0, 1, f.max, f.max + 1} {
			r := base("splunk_hec")
			put(r, strings.Split(f.path, "."), strings.Repeat("界", n))
			want := error(nil)
			if n > f.max {
				want = f.stage
			}
			expect(t, r, want)
		}
	}
	for _, n := range []int{0, 1, 63, 64} {
		r := base("splunk_hec")
		spec(r)["credentialRef"] = strings.Repeat("a", n)
		want := error(nil)
		if n == 0 || n == 64 {
			want = ErrCommon
		}
		expect(t, r, want)
	}
	r := base("splunk_hec")
	spec(r)["credentialRef"] = strings.Repeat("a", 63) + "\n"
	expect(t, r, ErrCommon)
}

// exactDNS and exactEndpoint construct spellings whose lengths hit schema bounds.
func exactDNS(n int) string {
	if n < 1 {
		return ""
	}
	var parts []string
	for n > 63 {
		take := 63
		if n-take-1 == 0 {
			take--
		}
		parts = append(parts, strings.Repeat("a", take))
		n -= take + 1
	}
	parts = append(parts, strings.Repeat("a", n))
	return strings.Join(parts, ".")
}
func exactEndpoint(n int) string {
	const origin = "https://a"
	if n < len(origin) {
		return strings.Repeat("a", n)
	}
	result := origin
	left := n - len(origin)
	for left > 0 {
		if left == 1 {
			return result + "/"
		}
		take := left - 1
		if take > 128 {
			take = 128
		}
		result += "/" + strings.Repeat("a", take)
		left -= take + 1
	}
	return result
}
func exactPrefix(n int) string {
	var parts []string
	for n > 63 {
		take := 63
		if n-take-1 == 0 {
			take--
		}
		parts = append(parts, strings.Repeat("a", take))
		n -= take + 1
	}
	parts = append(parts, strings.Repeat("a", n))
	return strings.Join(parts, "/")
}

func TestStringBoundaries(t *testing.T) {
	type bound struct {
		a, path   string
		min, max  int
		build     func(int) string
		acceptMin bool
		stage     error
	}
	repeat := func(n int) string { return strings.Repeat("a", n) }
	bounds := []bound{
		{"splunk_hec", "metadata.name", 1, 63, repeat, true, ErrResource},
		{"splunk_hec", "metadata.description", 0, 1024, repeat, true, ErrResource},
		{"splunk_hec", "metadata.labels.key", 1, 128, repeat, true, ErrResource},
		{"splunk_hec", "metadata.labels.value", 0, 63, repeat, true, ErrResource},
		{"splunk_hec", "metadata.annotations.key", 1, 128, repeat, true, ErrResource},
		{"splunk_hec", "metadata.annotations.value", 0, 4096, repeat, true, ErrResource},
		{"splunk_hec", "spec.credentialRef", 1, 63, repeat, true, ErrCommon},
		{"splunk_hec", "spec.tls.caRef", 1, 63, repeat, true, ErrCommon},
		{"splunk_hec", "spec.tls.clientCertificateRef", 1, 63, repeat, true, ErrCommon},
		{"splunk_hec", "spec.tls.serverName", 1, 253, exactDNS, true, ErrCommon},
		{"splunk_hec", "spec.tls.pinSha256", 1, 64, repeat, false, ErrCommon},
		{"splunk_hec", "spec.endpoint", 1, 2048, exactEndpoint, false, ErrCommon},
		{"splunk_hec", "spec.filter.condition", 0, 4096, repeat, true, ErrCommon},
		{"splunk_hec", "spec.filter.deviceGroups.item", 1, 63, repeat, true, ErrCommon},
		{"splunk_hec", "spec.projection.drop.item", 1, 256, repeat, true, ErrCommon},
		{"elasticsearch", "spec.elasticsearch.namespace", 1, 63, repeat, true, ErrParameters},
		{"opensearch", "spec.opensearch.namespace", 1, 63, repeat, true, ErrParameters},
		{"opensearch", "spec.opensearch.region", 1, 63, repeat, true, ErrParameters},
		{"splunk_hec", "spec.splunk_hec.index", 1, 128, repeat, true, ErrParameters},
		{"splunk_hec", "spec.splunk_hec.sourcetype", 1, 128, repeat, true, ErrParameters},
		{"otlp", "spec.otlp.headers.key", 1, 64, repeat, true, ErrParameters},
		{"otlp", "spec.otlp.headers.value", 1, 63, repeat, true, ErrParameters},
		{"loki", "spec.loki.tenant", 1, 128, repeat, true, ErrParameters},
		{"sentinel", "spec.sentinel.tenantId", 1, 36, func(n int) string {
			if n == 36 {
				return "11111111-1111-4111-8111-111111111111"
			}
			return repeat(n)
		}, false, ErrParameters},
		{"sentinel", "spec.sentinel.clientId", 1, 36, func(n int) string {
			if n == 36 {
				return "11111111-1111-4111-8111-111111111111"
			}
			return repeat(n)
		}, false, ErrParameters},
		{"sentinel", "spec.sentinel.dcrImmutableId", 1, 36, func(n int) string {
			if n >= 4 {
				return "dcr-" + repeat(n-4)
			}
			return repeat(n)
		}, false, ErrParameters},
		{"kafka", "spec.kafka.brokers.item", 1, 320, func(n int) string {
			if n < 3 {
				return repeat(n)
			}
			return exactDNS(n-2) + ":1"
		}, false, ErrParameters},
		{"kafka", "spec.kafka.topic", 1, 249, repeat, true, ErrParameters},
		{"s3", "spec.s3.bucket", 1, 63, repeat, false, ErrParameters},
		{"s3", "spec.s3.region", 1, 63, repeat, true, ErrParameters},
		{"s3", "spec.s3.prefix", 0, 256, exactPrefix, true, ErrParameters},
		{"s3", "spec.s3.encryption.kmsKeyId", 1, 2048, repeat, true, ErrParameters},
		{"connector", "spec.connector.registrationRef", 1, 63, repeat, true, ErrParameters},
	}
	for _, b := range bounds {
		for _, n := range []int{b.min - 1, b.min, b.max, b.max + 1} {
			if n < 0 {
				continue
			}
			t.Run(b.path+"/"+strconv.Itoa(n), func(t *testing.T) {
				r := base(b.a)
				if b.path == "spec.opensearch.region" {
					r = modeResource(b.a, "spec.opensearch.auth", "sigv4")
				}
				if strings.Contains(b.path, ".headers.") {
					r = modeResource(b.a, "spec.otlp.auth", "headers")
				}
				if b.path == "spec.s3.encryption.kmsKeyId" {
					r = modeResource(b.a, "spec.s3.encryption.mode", "sse_kms")
				}
				value := b.build(n)
				path := strings.Split(b.path, ".")
				switch path[len(path)-1] {
				case "item":
					put(r, path[:len(path)-1], []any{value})
				case "key":
					put(r, path[:len(path)-1], map[string]any{value: "a"})
				case "value":
					put(r, path[:len(path)-1], map[string]any{"a": value})
				default:
					put(r, path, value)
				}
				want := error(nil)
				if n < b.min || n > b.max || (n == b.min && !b.acceptMin) {
					want = b.stage
				}
				expect(t, r, want)
			})
		}
	}
	// Bucket grammar makes three characters the actual lower bound.
	for _, n := range []int{2, 3} {
		r := base("s3")
		spec(r)["s3"].(map[string]any)["bucket"] = strings.Repeat("a", n)
		want := error(nil)
		if n == 2 {
			want = ErrParameters
		}
		expect(t, r, want)
	}
	for _, value := range []string{"a..b", "1.2.3.4", "a-b", "a.b"} {
		r := base("s3")
		spec(r)["s3"].(map[string]any)["bucket"] = value
		want := error(nil)
		if value == "a..b" || value == "1.2.3.4" {
			want = ErrParameters
		}
		expect(t, r, want)
	}
}

func TestContainerBoundaries(t *testing.T) {
	var classes []any
	for _, c := range readFixtures(t) {
		if c.ID == "valid-selection" {
			classes = spec(c.Resource.(map[string]any))["filter"].(map[string]any)["classes"].([]any)
		}
	}
	if len(classes) != 42 {
		t.Fatal("class fixture size differs")
	}
	for _, c := range classes {
		r := base("splunk_hec")
		spec(r)["filter"] = map[string]any{"classes": []any{c}}
		expect(t, r, nil)
	}
	type bound struct {
		a, path  string
		min, max int
		items    func(int) []any
		stage    error
	}
	names := func(n int) []any {
		a := make([]any, n)
		for i := range a {
			a[i] = "field" + strconv.Itoa(i)
		}
		return a
	}
	bounds := []bound{
		{"splunk_hec", "spec.filter.classes", 0, 42, func(n int) []any {
			a := make([]any, n)
			for i := range a {
				if i < len(classes) {
					a[i] = classes[i]
				} else {
					a[i] = "unknown"
				}
			}
			return a
		}, ErrCommon},
		{"splunk_hec", "spec.filter.deviceGroups", 0, 64, names, ErrCommon},
		{"splunk_hec", "spec.filter.origins", 1, 3, func(n int) []any { values := []any{"agent", "server", "extension", "unknown"}; return values[:n] }, ErrCommon},
		{"splunk_hec", "spec.projection.drop", 0, 64, names, ErrCommon},
		{"loki", "spec.loki.labels", 0, 2, func(n int) []any { values := []any{"os", "ocsf_category", "unknown"}; return values[:n] }, ErrParameters},
		{"kafka", "spec.kafka.brokers", 1, 16, func(n int) []any {
			a := make([]any, n)
			for i := range a {
				a[i] = "broker" + strconv.Itoa(i) + ":1"
			}
			return a
		}, ErrParameters},
	}
	for _, b := range bounds {
		for _, n := range []int{b.min - 1, b.min, b.max, b.max + 1} {
			if n < 0 {
				continue
			}
			r := base(b.a)
			put(r, strings.Split(b.path, "."), b.items(n))
			want := error(nil)
			if n < b.min || n > b.max {
				want = b.stage
			}
			expect(t, r, want)
		}
		r := base(b.a)
		items := b.items(1)
		put(r, strings.Split(b.path, "."), []any{items[0], items[0]})
		expect(t, r, b.stage)
		r = base(b.a)
		put(r, strings.Split(b.path, "."), []any{nil})
		expect(t, r, b.stage)
	}
	for _, b := range []struct {
		a, path  string
		min, max int
		stage    error
	}{{"splunk_hec", "metadata.labels", 0, 32, ErrResource}, {"splunk_hec", "metadata.annotations", 0, 32, ErrResource}, {"otlp", "spec.otlp.headers", 1, 16, ErrParameters}} {
		for _, n := range []int{b.min - 1, b.min, b.max, b.max + 1} {
			if n < 0 {
				continue
			}
			r := base(b.a)
			if b.a == "otlp" {
				r = modeResource(b.a, "spec.otlp.auth", "headers")
			}
			m := map[string]any{}
			for i := range n {
				m["x"+strconv.Itoa(i)] = "reference"
			}
			put(r, strings.Split(b.path, "."), m)
			want := error(nil)
			if n < b.min || n > b.max {
				want = b.stage
			}
			expect(t, r, want)
		}
		r := base(b.a)
		if b.a == "otlp" {
			r = modeResource(b.a, "spec.otlp.auth", "headers")
		}
		put(r, strings.Split(b.path, "."), map[string]any{"x": nil})
		expect(t, r, b.stage)
	}
	// These valid schema strings exceed only the decoded aggregate byte bound.
	r := base("splunk_hec")
	m := map[string]any{}
	for i := range 32 {
		m["x"+strconv.Itoa(i)] = strings.Repeat("界", 4096)
	}
	r["metadata"].(map[string]any)["annotations"] = m
	expect(t, r, ErrLimits)
}

func TestConditionalFields(t *testing.T) {
	for _, key := range []string{"region", "service", "credentialSource"} {
		r := modeResource("opensearch", "spec.opensearch.auth", "sigv4")
		b := spec(r)["opensearch"].(map[string]any)
		b[key] = nil
		expect(t, r, ErrParameters)
		b[key] = "unknown-value"
		if key != "region" {
			expect(t, r, ErrParameters)
		}
	}
	for _, auth := range []string{"bearer", "mtls", "headers"} {
		r := modeResource("otlp", "spec.otlp.auth", auth)
		spec(r)["otlp"].(map[string]any)["headers"] = nil
		expect(t, r, ErrParameters)
	}
	r := modeResource("s3", "spec.s3.encryption.mode", "sse_kms")
	spec(r)["s3"].(map[string]any)["encryption"].(map[string]any)["kmsKeyId"] = nil
	expect(t, r, ErrParameters)
	for _, v := range []any{nil, true, float64(1), "unknown-value"} {
		r := base("splunk_hec")
		spec(r)["type"] = v
		expect(t, r, ErrAdapter)
	}
	for _, key := range []string{"caRef", "pinSha256"} {
		r := base("splunk_hec")
		spec(r)["tls"] = map[string]any{"caRef": "ca", "pinSha256": strings.Repeat("a", 64)}
		expect(t, r, ErrCommon)
		delete(spec(r)["tls"].(map[string]any), key)
		expect(t, r, nil)
	}
}
