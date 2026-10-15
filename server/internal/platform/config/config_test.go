package config_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

const schemaDir = "../../../../schemas/server/config/v1/"

func noEnv(string) (string, bool) { return "", false }

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// toYAML converts a decoded JSON value into block-style YAML, keeping JSON
// integers as YAML integers.
func toYAML(t testing.TB, raw []byte) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(convertNumbers(v))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func convertNumbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = convertNumbers(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = convertNumbers(e)
		}
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	}
	return v
}

func writeFile(t testing.TB, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type schemaCases struct {
	Cases []struct {
		ID       string          `json:"id"`
		Valid    bool            `json:"valid"`
		Instance json.RawMessage `json:"instance"`
	} `json:"cases"`
}

func loadCases(t testing.TB) schemaCases {
	t.Helper()
	data, err := os.ReadFile(schemaDir + "schema-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c schemaCases
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Cases) == 0 {
		t.Fatal("no schema cases")
	}
	return c
}

func TestSchemaCasesAgree(t *testing.T) {
	for _, c := range loadCases(t).Cases {
		t.Run(c.ID, func(t *testing.T) {
			_, err := config.Load(writeFile(t, toYAML(t, c.Instance)), noEnv)
			if (err == nil) != c.Valid {
				t.Fatalf("valid=%v, Load error %v", c.Valid, err)
			}
		})
	}
}

func TestExampleDocumentedValues(t *testing.T) {
	data, err := os.ReadFile(schemaDir + "example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(writeFile(t, toYAML(t, data)), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := config.Config{
		Schema: "ricevanta-server-config-v1",
		Roles:  []string{"api"},
		Listen: config.Listen{API: &config.Listener{Address: ":8443", TLS: config.TLS{
			Mode: "file", CertificateFile: "/etc/ricevanta/tls/api.crt", KeyFile: "/etc/ricevanta/tls/api.key"}}},
		Console:  config.Console{Enabled: true},
		Log:      config.Log{Level: "info"},
		HTTP:     config.HTTP{ReadHeaderTimeoutMS: 10000, IdleTimeoutMS: 60000, MaxHeaderBytes: 65536},
		Shutdown: config.Shutdown{TimeoutMS: 20000},
	}
	if !equal(c, want) {
		t.Fatalf("got %+v\nwant %+v", c, want)
	}
}

func equal(a, b config.Config) bool {
	return string(a.JSON()) == string(b.JSON())
}

func TestDefaults(t *testing.T) {
	c, err := config.Load(writeFile(t, []byte(minimalYAML)), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Console.Enabled || c.Log.Level != "info" || c.HTTP.ReadHeaderTimeoutMS != 10000 ||
		c.HTTP.IdleTimeoutMS != 60000 || c.HTTP.MaxHeaderBytes != 65536 || c.Shutdown.TimeoutMS != 20000 {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestListenerWithoutTLSDefaultsToFileMode(t *testing.T) {
	doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:8443\"\n"
	_, err := config.Load(writeFile(t, []byte(doc)), noEnv)
	if err == nil || !strings.Contains(err.Error(), "certificate_file") {
		t.Fatalf("want missing certificate_file under default mode file, got %v", err)
	}
}

const minimalYAML = `schema: ricevanta-server-config-v1
roles: [api]
listen:
  api:
    address: "127.0.0.1:8080"
    tls:
      mode: none
`

func TestYAMLNegatives(t *testing.T) {
	big := []byte(minimalYAML + "#")
	big = append(big, bytes.Repeat([]byte("x"), 65537-len(big))...)
	exact := []byte(minimalYAML + "#")
	exact = append(exact, bytes.Repeat([]byte("x"), 65536-len(exact))...)
	if _, err := config.Load(writeFile(t, exact), noEnv); err != nil {
		t.Fatalf("65,536-byte document rejected: %v", err)
	}
	cases := map[string]string{
		"duplicate key":          minimalYAML + "schema: ricevanta-server-config-v1\n",
		"duplicate nested key":   strings.Replace(minimalYAML, "      mode: none\n", "      mode: none\n      mode: none\n", 1),
		"anchor":                 strings.Replace(minimalYAML, "roles: [api]", "roles: &r [api]", 1),
		"alias":                  minimalYAML + "log: &l {level: info}\nconsole: *l\n",
		"alias only":             strings.Replace(minimalYAML, "roles: [api]", "roles: *r", 1),
		"explicit str tag":       strings.Replace(minimalYAML, "mode: none", "mode: !!str none", 1),
		"explicit local tag":     strings.Replace(minimalYAML, "mode: none", "mode: !none none", 1),
		"tagged int":             minimalYAML + "shutdown: {timeout_ms: !!int 5000}\n",
		"two documents":          minimalYAML + "---\n" + minimalYAML,
		"empty second document":  minimalYAML + "---\n",
		"scalar document":        "ricevanta\n",
		"sequence document":      "- api\n",
		"empty document":         "",
		"comment only":           "# nothing\n",
		"too large":              string(big),
		"unknown key":            minimalYAML + "database: {url: x}\n",
		"unknown nested key":     strings.Replace(minimalYAML, "      mode: none\n", "      mode: none\n      ciphers: x\n", 1),
		"null value":             minimalYAML + "log: {level: null}\n",
		"empty section":          minimalYAML + "log:\n",
		"yes as bool":            minimalYAML + "console: {enabled: yes}\n",
		"quoted bool":            minimalYAML + "console: {enabled: \"true\"}\n",
		"quoted int":             minimalYAML + "shutdown: {timeout_ms: \"5000\"}\n",
		"float int":              minimalYAML + "shutdown: {timeout_ms: 5000.5}\n",
		"int schema":             strings.Replace(minimalYAML, "schema: ricevanta-server-config-v1", "schema: 1", 1),
		"int role":               strings.Replace(minimalYAML, "roles: [api]", "roles: [1]", 1),
		"mapping as roles":       strings.Replace(minimalYAML, "roles: [api]", "roles: {api: 1}", 1),
		"invalid utf8":           minimalYAML + "# \xff\n",
		"byte order mark":        "\xef\xbb\xbf" + minimalYAML,
		"read timeout low":       minimalYAML + "http: {read_header_timeout_ms: 999}\n",
		"idle timeout high":      minimalYAML + "http: {idle_timeout_ms: 600001}\n",
		"header bytes low":       minimalYAML + "http: {max_header_bytes: 4095}\n",
		"header bytes high":      minimalYAML + "http: {max_header_bytes: 1048577}\n",
		"shutdown low":           minimalYAML + "shutdown: {timeout_ms: 999}\n",
		"bad level":              minimalYAML + "log: {level: trace}\n",
		"wrong schema":           strings.Replace(minimalYAML, "ricevanta-server-config-v1", "ricevanta-server-config-v2", 1),
		"missing schema":         strings.Replace(minimalYAML, "schema: ricevanta-server-config-v1\n", "", 1),
		"missing roles":          strings.Replace(minimalYAML, "roles: [api]\n", "", 1),
		"tls without mode":       strings.Replace(minimalYAML, "      mode: none\n", "      key_file: /k\n", 1),
		"relative key path":      strings.Replace(minimalYAML, "mode: none", "mode: file\n      certificate_file: /c\n      key_file: k", 1),
		"bracketed ipv4":         strings.Replace(minimalYAML, "127.0.0.1:8080", "[127.0.0.1]:8080", 1),
		"zoned ipv6":             strings.Replace(minimalYAML, "127.0.0.1:8080", "[fe80::1%eth0]:8080", 1),
		"bad ipv6":               strings.Replace(minimalYAML, "127.0.0.1:8080", "[:::1]:8080", 1),
		"leading zero port":      strings.Replace(minimalYAML, "127.0.0.1:8080", "127.0.0.1:08080", 1),
		"leading zero octet":     strings.Replace(minimalYAML, "127.0.0.1:8080", "127.0.0.01:8080", 1),
		"no port":                strings.Replace(minimalYAML, "127.0.0.1:8080", "127.0.0.1", 1),
		"merge key":              minimalYAML + "log:\n  <<: {level: info}\n",
		"plaintext all":          strings.Replace(minimalYAML, "127.0.0.1:8080", ":8080", 1),
		"plaintext unspecified4": strings.Replace(minimalYAML, "127.0.0.1:8080", "0.0.0.0:8080", 1),
		"plaintext public":       strings.Replace(minimalYAML, "127.0.0.1:8080", "192.0.2.1:8080", 1),
		"plaintext ipv6 any":     strings.Replace(minimalYAML, "127.0.0.1:8080", "[::]:8080", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(writeFile(t, []byte(doc)), noEnv); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestDuplicateKeyRejectedByDecoder(t *testing.T) {
	_, err := config.Load(writeFile(t, []byte(minimalYAML+"schema: ricevanta-server-config-v1\n")), noEnv)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want yaml.v3 duplicate key rejection, got %v", err)
	}
}

func TestPlaintextRequiresLoopback(t *testing.T) {
	doc := strings.Replace(minimalYAML, "127.0.0.1:8080", "0.0.0.0:8080", 1)
	_, err := config.Load(writeFile(t, []byte(doc)), noEnv)
	var ce *config.Error
	if !errors.As(err, &ce) || ce.Code != config.CodePlaintextRequiresLoopback {
		t.Fatalf("want %s, got %v", config.CodePlaintextRequiresLoopback, err)
	}
	for _, addr := range []string{"127.0.0.1:8080", "127.1.2.3:8080", "[::1]:8080", "[::ffff:127.0.0.1]:8080"} {
		doc := strings.Replace(minimalYAML, "127.0.0.1:8080", addr, 1)
		if _, err := config.Load(writeFile(t, []byte(doc)), noEnv); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestErrorsDoNotEchoValues(t *testing.T) {
	secretish := "s3cr3t-value-should-not-appear"
	docs := []string{
		strings.Replace(minimalYAML, "127.0.0.1:8080", secretish, 1),
		strings.Replace(minimalYAML, "mode: none", "mode: "+secretish, 1),
		minimalYAML + "shutdown: {timeout_ms: " + secretish + "}\n",
		minimalYAML + secretish + ": 1\n",
		minimalYAML + "log: {level: \"" + secretish + "\", level: x}\n",
		"[" + secretish,
	}
	for _, doc := range docs {
		_, err := config.Load(writeFile(t, []byte(doc)), noEnv)
		if err == nil {
			t.Fatalf("accepted %q", doc)
		}
		if strings.Contains(err.Error(), secretish) {
			t.Errorf("error echoes value: %v", err)
		}
	}
	_, err := config.Load(writeFile(t, []byte(minimalYAML)), envMap(map[string]string{"RICEVANTA_SERVER_LOG_LEVEL": secretish}))
	if err == nil || strings.Contains(err.Error(), secretish) {
		t.Errorf("environment error: %v", err)
	}
}

func TestEnvironmentOverrides(t *testing.T) {
	env := map[string]string{
		"RICEVANTA_SERVER_ROLES":                           "api,agent",
		"RICEVANTA_SERVER_LISTEN_API_ADDRESS":              "[::1]:9443",
		"RICEVANTA_SERVER_LISTEN_API_TLS_MODE":             "file",
		"RICEVANTA_SERVER_LISTEN_API_TLS_CERTIFICATE_FILE": "/run/tls/crt",
		"RICEVANTA_SERVER_LISTEN_API_TLS_KEY_FILE":         "/run/tls/key",
		"RICEVANTA_SERVER_CONSOLE_ENABLED":                 "false",
		"RICEVANTA_SERVER_LOG_LEVEL":                       "debug",
	}
	c, err := config.Load(writeFile(t, []byte("schema: ricevanta-server-config-v1\nroles: [api]\n")), envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Roles, ",") != "api,agent" {
		t.Errorf("roles %v", c.Roles)
	}
	if c.Listen.API == nil || c.Listen.API.Address != "[::1]:9443" || c.Listen.API.TLS.Mode != "file" ||
		c.Listen.API.TLS.CertificateFile != "/run/tls/crt" || c.Listen.API.TLS.KeyFile != "/run/tls/key" {
		t.Errorf("listener %+v", c.Listen.API)
	}
	if c.Console.Enabled || c.Log.Level != "debug" {
		t.Errorf("console %v level %s", c.Console.Enabled, c.Log.Level)
	}
}

func TestEnvironmentValuesValidated(t *testing.T) {
	for k, v := range map[string]string{
		"RICEVANTA_SERVER_ROLES":               "api, agent",
		"RICEVANTA_SERVER_CONSOLE_ENABLED":     "yes",
		"RICEVANTA_SERVER_LISTEN_API_ADDRESS":  "0.0.0.0:8080",
		"RICEVANTA_SERVER_LISTEN_API_TLS_MODE": "plain",
		"RICEVANTA_SERVER_LOG_LEVEL":           "",
	} {
		if _, err := config.Load(writeFile(t, []byte(minimalYAML)), envMap(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	roles := []string{"", ",", "api,", "api,api", "console"}
	for _, v := range roles {
		if _, err := config.Load(writeFile(t, []byte(minimalYAML)), envMap(map[string]string{"RICEVANTA_SERVER_ROLES": v})); err == nil {
			t.Errorf("roles %q accepted", v)
		}
	}
}

func TestEnvironmentWinsOverFile(t *testing.T) {
	c, err := config.Load(writeFile(t, []byte(minimalYAML+"log: {level: error}\n")), envMap(map[string]string{"RICEVANTA_SERVER_LOG_LEVEL": "warn"}))
	if err != nil || c.Log.Level != "warn" {
		t.Fatalf("level %q err %v", c.Log.Level, err)
	}
}

func TestUnknownPrefixedVariableRejected(t *testing.T) {
	err := config.CheckEnviron([]string{"PATH=/bin", "RICEVANTA_SERVER_LISTEN_API_ADRESS=127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "RICEVANTA_SERVER_LISTEN_API_ADRESS") || strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("got %v", err)
	}
	var ce *config.Error
	if !errors.As(err, &ce) || ce.Code != config.CodeUnknownEnvironment {
		t.Fatalf("code: %v", err)
	}
	if err := config.CheckEnviron([]string{"RICEVANTA_SERVER_LOG_LEVEL=info", "RICEVANTA_SERVER_CONFIG=/x", "RICEVANTA_AGENT_X=1", "NOEQUALS"}); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckEnviron([]string{"RICEVANTA_SERVER_=1"}); err == nil {
		t.Fatal("bare prefix accepted")
	}
}

func TestConfigPathPrecedence(t *testing.T) {
	env := envMap(map[string]string{"RICEVANTA_SERVER_CONFIG": "/from/env.yaml"})
	if p, err := config.ResolvePath("/from/flag.yaml", true, env); err != nil || p != "/from/flag.yaml" {
		t.Errorf("flag: %q %v", p, err)
	}
	if p, err := config.ResolvePath("", false, env); err != nil || p != "/from/env.yaml" {
		t.Errorf("env: %q %v", p, err)
	}
	if p, err := config.ResolvePath("", false, noEnv); err != nil || p != config.DefaultPath {
		t.Errorf("default: %q %v", p, err)
	}
	if config.DefaultPath != "/etc/ricevanta/server.yaml" {
		t.Errorf("default path %q", config.DefaultPath)
	}
	if _, err := config.ResolvePath("", true, env); err == nil {
		t.Error("empty flag accepted")
	}
	if _, err := config.ResolvePath("", false, envMap(map[string]string{"RICEVANTA_SERVER_CONFIG": ""})); err == nil {
		t.Error("empty variable accepted")
	}
}

func TestEffectiveJSONSortedWithoutFileContents(t *testing.T) {
	c, err := config.Load(writeFile(t, []byte(minimalYAML)), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"console":{"enabled":true},"http":{"idle_timeout_ms":60000,"max_header_bytes":65536,"read_header_timeout_ms":10000},"listen":{"api":{"address":"127.0.0.1:8080","tls":{"mode":"none"}}},"log":{"level":"info"},"roles":["api"],"schema":"ricevanta-server-config-v1","shutdown":{"timeout_ms":20000}}`
	if got := string(c.JSON()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestConfigFileMustBeRegular(t *testing.T) {
	if _, err := config.Load(t.TempDir(), noEnv); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := config.Load(filepath.Join(t.TempDir(), "missing.yaml"), noEnv); err == nil {
		t.Fatal("missing file accepted")
	}
}
